"""HTTP end-to-end tests for Hotspot pay → status → activate → voucher."""

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
from billing.models import AccessVoucher, BillingPlan, Customer, StkPushRequest
from core.models import MikroTikRouter


class HotspotPaymentConnectionFlowTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-hs-flow", password="x")
        self.org = Organization.objects.create(
            name="Flow ISP",
            owner=self.owner,
            join_code="717171",
            hotspot_enabled=True,
            daraja_enabled=True,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Hotspot Daily",
            price=Decimal("50.00"),
            download_speed_mbps=10,
            upload_speed_mbps=5,
            duration=BillingPlan.Duration.DAILY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            max_devices=2,
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Flow NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.71.71.1",
            username="admin",
            password="secret",
        )
        self.mac = "AA:BB:CC:DD:EE:71"

    def _start_url(self):
        return reverse(
            "core:hotspot_payment_start", kwargs={"join_code": self.org.join_code}
        )

    def _status_url(self, stk_id: int):
        return reverse(
            "core:hotspot_payment_status",
            kwargs={"join_code": self.org.join_code, "stk_id": stk_id},
        )

    def _activate_url(self, stk_id: int):
        return reverse(
            "core:hotspot_payment_activate",
            kwargs={"join_code": self.org.join_code, "stk_id": stk_id},
        )

    def _voucher_url(self):
        return reverse(
            "core:hotspot_voucher_redeem", kwargs={"join_code": self.org.join_code}
        )

    def test_pay_start_without_mac_returns_json_400(self):
        with patch("core.views._resolve_request_hotspot_mac", return_value=""):
            response = self.client.post(
                self._start_url(),
                {"plan_id": str(self.plan.pk), "phone": "0712345678"},
            )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data["ok"])
        self.assertIn("device", data["error"].lower())

    def test_pay_start_creates_stk_session_token(self):
        with (
            patch(
                "core.mikrotik_connect.find_hotspot_router_for_mac",
                return_value=self.router,
            ),
            patch("core.views._resolve_request_hotspot_mac", return_value=self.mac),
            patch(
                "billing.stk.start_subscription_stk_payment",
                return_value={
                    "ok": True,
                    "stk_id": 501,
                    "amount": "50.00",
                    "message": "STK sent",
                },
            ) as stk,
        ):
            response = self.client.post(
                self._start_url(),
                {
                    "plan_id": str(self.plan.pk),
                    "phone": "0712345678",
                    "mac": self.mac,
                },
            )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["stk_id"], 501)
        self.assertTrue(data["status_url"])
        self.assertTrue(data["status_token"])
        payload = signing.loads(data["status_token"], salt="hotspot-payment-status")
        self.assertEqual(payload["stk"], 501)
        self.assertEqual(payload["org"], self.org.pk)
        self.assertEqual(payload["mac"].upper(), self.mac)
        stk.assert_called_once()

    def test_status_bad_token_returns_json_403(self):
        response = self.client.get(self._status_url(1) + "?token=bad")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(response.json()["ok"])

    def test_status_success_authorizes_when_nas_ready(self):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Flow Client",
            phone="254712345678",
            account_number="HOT-FLOW-1",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac=self.mac,
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            router=self.router,
        )
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=customer,
            plan=self.plan,
            amount=Decimal("50.00"),
            phone="254712345678",
            account_reference=customer.account_number,
            status=StkPushRequest.Status.SUCCESS,
            mpesa_receipt="RCPFLOW1",
            subscription_applied=False,
            raw_callback={"hotspot_mac": self.mac},
        )
        token = signing.dumps(
            {"stk": stk.pk, "org": self.org.pk, "mac": self.mac},
            salt="hotspot-payment-status",
            compress=True,
        )
        with patch(
            "core.subscription_sync.enqueue_customer_subscription_sync",
            return_value={"ok": True, "allowed": True},
        ):
            response = self.client.get(
                self._status_url(stk.pk) + f"?token={token}&nas=1"
            )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["success"])
        self.assertTrue(data["subscription_applied"])
        self.assertTrue(data["authorized"])
        self.assertTrue(data.get("surfing"))
        stk.refresh_from_db()
        self.assertTrue(stk.subscription_applied)
        vouchers = list(AccessVoucher.objects.filter(stk_request=stk))
        self.assertGreaterEqual(len(vouchers), 1)
        self.assertTrue(
            any(v.status == AccessVoucher.Status.INVALID for v in vouchers)
        )

    def test_activate_applies_when_subscription_not_yet_applied(self):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Activate Client",
            phone="254712345679",
            account_number="HOT-FLOW-2",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac=self.mac,
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            router=self.router,
        )
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=customer,
            plan=self.plan,
            amount=Decimal("50.00"),
            phone="254712345679",
            account_reference=customer.account_number,
            status=StkPushRequest.Status.SUCCESS,
            mpesa_receipt="RCPFLOW2",
            subscription_applied=False,
            raw_callback={"hotspot_mac": self.mac},
        )
        token = signing.dumps(
            {"stk": stk.pk, "org": self.org.pk, "mac": self.mac},
            salt="hotspot-payment-status",
            compress=True,
        )
        with patch(
            "core.subscription_sync.enqueue_customer_subscription_sync",
            return_value={"ok": True, "allowed": True},
        ):
            response = self.client.post(
                self._activate_url(stk.pk) + f"?token={token}"
            )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["authorized"])
        stk.refresh_from_db()
        self.assertTrue(stk.subscription_applied)

    def test_activate_idempotent_does_not_double_extend(self):
        from billing.vouchers import activate_paid_subscription_stk

        customer = Customer.objects.create(
            organization=self.org,
            full_name="Idem Client",
            phone="254712345680",
            account_number="HOT-FLOW-3",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac=self.mac,
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            router=self.router,
            package_start=timezone.now() - timedelta(hours=1),
            package_end=timezone.now() + timedelta(hours=20),
        )
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=customer,
            plan=self.plan,
            amount=Decimal("50.00"),
            phone="254712345680",
            account_reference=customer.account_number,
            status=StkPushRequest.Status.SUCCESS,
            mpesa_receipt="RCPFLOW3",
            subscription_applied=False,
            raw_callback={"hotspot_mac": self.mac},
        )
        with patch(
            "core.subscription_sync.enqueue_customer_subscription_sync",
            return_value={"ok": True, "allowed": True},
        ):
            first = activate_paid_subscription_stk(
                stk, mac=self.mac, wait_first=True, quick=True
            )
            customer.refresh_from_db()
            end_after_first = customer.package_end
            second = activate_paid_subscription_stk(
                stk, mac=self.mac, wait_first=True, quick=True
            )
            customer.refresh_from_db()
        self.assertTrue(first["ok"])
        self.assertTrue(second["ok"])
        self.assertTrue(second.get("already_applied"))
        self.assertEqual(customer.package_end, end_after_first)

    def test_voucher_redeem_authorizes_device(self):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Voucher Client",
            phone="254712345681",
            account_number="HOT-FLOW-4",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac=self.mac,
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            router=self.router,
            package_start=timezone.now() - timedelta(hours=1),
            package_end=timezone.now() + timedelta(hours=20),
        )
        voucher = AccessVoucher.objects.create(
            organization=self.org,
            customer=customer,
            plan=self.plan,
            code="FLOWCODE1",
            status=AccessVoucher.Status.VALID,
            subscription_applied=True,
        )
        with (
            patch("core.views._resolve_request_hotspot_mac", return_value=self.mac),
            patch(
                "core.subscription_sync.enqueue_customer_subscription_sync",
                return_value={"ok": True, "allowed": True},
            ),
        ):
            response = self.client.post(
                self._voucher_url(),
                {"voucher_code": voucher.code, "mac": self.mac},
            )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["authorized"])
        voucher.refresh_from_db()
        self.assertEqual(voucher.status, AccessVoucher.Status.INVALID)
