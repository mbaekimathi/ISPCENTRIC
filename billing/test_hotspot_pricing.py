"""Tests for Hotspot pay-for-other-devices pricing and voucher flow."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core import signing
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from accounts.models import Organization
from billing.hotspot_pricing import (
    PAY_MODE_OTHER_DEVICES,
    PAY_MODE_THIS_DEVICE,
    quote_other_devices_purchase,
    stk_other_devices_meta,
    stk_pay_mode,
)
from billing.models import AccessVoucher, BillingPlan, Customer, StkPushRequest
from billing.vouchers import activate_paid_subscription_stk, voucher_count_for_stk


class HotspotOtherDevicesPricingTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-other-dev", password="x")
        self.org = Organization.objects.create(
            name="Other Dev ISP",
            owner=self.owner,
            join_code="818181",
            hotspot_enabled=True,
            daraja_enabled=True,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Hotspot Flex",
            price=Decimal("50.00"),
            download_speed_mbps=10,
            upload_speed_mbps=5,
            duration=BillingPlan.Duration.DAILY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            max_devices=1,
            hotspot_other_devices_enabled=True,
            hotspot_other_base_price=Decimal("30.00"),
            hotspot_hourly_rate_per_device=Decimal("10.00"),
        )
        self.mac = "AA:BB:CC:DD:EE:81"

    def test_quote_other_devices_total(self):
        quote = quote_other_devices_purchase(self.plan, device_count=3, hours=2)
        self.assertTrue(quote["ok"])
        # base 30 + (10 × 3 × 2) = 90
        self.assertEqual(quote["total"], "90")
        self.assertEqual(quote["voucher_count"], 3)
        self.assertEqual(quote["package_hours"], 2)

    def test_quote_rounds_to_integer_kes(self):
        plan = BillingPlan.objects.create(
            organization=self.org,
            name="Odd Rate",
            price=Decimal("10.00"),
            download_speed_mbps=5,
            upload_speed_mbps=2,
            duration=BillingPlan.Duration.HOURLY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            hotspot_other_devices_enabled=True,
            hotspot_other_base_price=Decimal("10.50"),
            hotspot_hourly_rate_per_device=Decimal("3.33"),
        )
        quote = quote_other_devices_purchase(plan, device_count=2, hours=1)
        self.assertTrue(quote["ok"])
        # 10.50 + 6.66 = 17.16 → rounds to 17
        self.assertEqual(quote["total"], "17")

    def test_quote_rejects_disabled_plan(self):
        self.plan.hotspot_hourly_rate_per_device = Decimal("0")
        self.plan.save(update_fields=["hotspot_hourly_rate_per_device"])
        quote = quote_other_devices_purchase(self.plan, device_count=2, hours=1)
        self.assertFalse(quote["ok"])

    def test_voucher_count_for_other_devices_stk(self):
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=Customer.objects.create(
                organization=self.org,
                full_name="Buyer",
                phone="254712345678",
                service_type=Customer.ServiceType.HOTSPOT,
                plan=self.plan,
            ),
            plan=self.plan,
            amount=Decimal("90"),
            phone="254712345678",
            account_reference="HS8181",
            status=StkPushRequest.Status.SUCCESS,
            raw_callback={
                "pay_mode": PAY_MODE_OTHER_DEVICES,
                "device_count": 4,
                "hours": 2,
                "package_hours": 2,
                "voucher_count": 4,
            },
        )
        self.assertEqual(voucher_count_for_stk(stk), 4)
        self.assertEqual(stk_pay_mode(stk), PAY_MODE_OTHER_DEVICES)
        meta = stk_other_devices_meta(stk)
        self.assertEqual(meta["device_count"], 4)
        self.assertEqual(meta["package_hours"], 2)

    def test_pay_start_other_devices_passes_quote_to_stk(self):
        url = reverse(
            "core:hotspot_payment_start", kwargs={"join_code": self.org.join_code}
        )
        from core.models import MikroTikRouter

        router = MikroTikRouter.objects.create(
            organization=self.org,
            name="NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.81.81.1",
            username="admin",
            password="secret",
        )
        with (
            patch(
                "core.mikrotik_connect.find_hotspot_router_for_mac",
                return_value=router,
            ),
            patch("core.views._resolve_request_hotspot_mac", return_value=self.mac),
            patch(
                "billing.stk.start_subscription_stk_payment",
                return_value={"ok": True, "stk_id": 901, "amount": "90"},
            ) as stk,
        ):
            response = self.client.post(
                url,
                {
                    "plan_id": str(self.plan.pk),
                    "phone": "0712345678",
                    "mac": self.mac,
                    "pay_mode": "other_devices",
                    "device_count": "3",
                    "hours": "2",
                },
            )
        self.assertEqual(response.status_code, 200)
        kwargs = stk.call_args.kwargs
        self.assertEqual(kwargs["amount"], Decimal("90"))
        self.assertEqual(kwargs["pay_metadata"]["pay_mode"], PAY_MODE_OTHER_DEVICES)
        self.assertEqual(kwargs["pay_metadata"]["device_count"], 3)
        self.assertEqual(kwargs["pay_metadata"]["voucher_count"], 3)

    def test_activate_other_devices_creates_vouchers_without_mac_claim(self):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Payer",
            phone="254712345678",
            service_type=Customer.ServiceType.HOTSPOT,
            plan=self.plan,
            hotspot_mac=self.mac,
        )
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=customer,
            plan=self.plan,
            amount=Decimal("90"),
            phone="254712345678",
            account_reference="HS8181",
            status=StkPushRequest.Status.SUCCESS,
            raw_callback={
                "pay_mode": PAY_MODE_OTHER_DEVICES,
                "device_count": 2,
                "hours": 3,
                "package_hours": 3,
                "voucher_count": 2,
                "hotspot_mac": self.mac,
            },
        )
        with patch(
            "core.subscription_sync.enqueue_customer_subscription_sync",
            return_value={"ok": False, "allowed": False, "message": "test offline"},
        ):
            result = activate_paid_subscription_stk(stk, mac=self.mac)
        self.assertTrue(result.get("ok"))
        self.assertFalse(result.get("authorized"))
        vouchers = list(
            AccessVoucher.objects.filter(stk_request=stk).order_by("id")
        )
        self.assertEqual(len(vouchers), 2)
        for row in vouchers:
            self.assertEqual(row.status, AccessVoucher.Status.VALID)
            self.assertFalse((row.redeemed_mac or "").strip())
        customer.refresh_from_db()
        self.assertIsNotNone(customer.package_end)
        self.assertGreater(
            customer.package_end,
            timezone.now() + timedelta(hours=2),
        )

    def test_welcome_shows_purchase_voucher_codes(self):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Payer",
            phone="254712345678",
            service_type=Customer.ServiceType.HOTSPOT,
            plan=self.plan,
        )
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=customer,
            plan=self.plan,
            amount=Decimal("90"),
            phone="254712345678",
            account_reference="HS8181",
            status=StkPushRequest.Status.SUCCESS,
            subscription_applied=True,
            raw_callback={
                "pay_mode": PAY_MODE_OTHER_DEVICES,
                "device_count": 2,
                "hours": 2,
                "package_hours": 2,
                "voucher_count": 2,
            },
        )
        AccessVoucher.objects.create(
            organization=self.org,
            customer=customer,
            plan=self.plan,
            stk_request=stk,
            code="4827K",
            status=AccessVoucher.Status.VALID,
        )
        AccessVoucher.objects.create(
            organization=self.org,
            customer=customer,
            plan=self.plan,
            stk_request=stk,
            code="5938M",
            status=AccessVoucher.Status.VALID,
        )
        token = signing.dumps(
            {"stk": stk.pk, "org": self.org.pk, "mac": self.mac},
            salt="hotspot-payment-status",
        )
        url = (
            reverse("core:hotspot_welcome", kwargs={"join_code": self.org.join_code})
            + f"?stk={stk.pk}&token={token}"
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn("Your voucher codes", content)
        self.assertIn("otherDevicesPurchase=true", content.replace(" ", ""))
        self.assertIn("4827-K", content)
        self.assertIn("5938-M", content)

    def test_this_device_stk_pay_mode_default(self):
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=Customer.objects.create(
                organization=self.org,
                full_name="Self",
                phone="254712345678",
                service_type=Customer.ServiceType.HOTSPOT,
                plan=self.plan,
            ),
            plan=self.plan,
            amount=Decimal("50"),
            phone="254712345678",
            account_reference="HS8181",
            status=StkPushRequest.Status.SUCCESS,
            raw_callback={"hotspot_mac": self.mac},
        )
        self.assertEqual(stk_pay_mode(stk), PAY_MODE_THIS_DEVICE)
