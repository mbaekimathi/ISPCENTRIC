from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from accounts.models import Organization
from billing.devices import (
    attach_hotspot_device,
    customer_devices_unlimited,
    customer_max_devices,
    find_hotspot_customer_for_mac,
    hotspot_macs_for_customer,
    resolve_or_create_hotspot_customer,
)
from billing.models import BillingPlan, Customer, CustomerDevice
from billing.services import apply_subscription_renewal
from core.models import MikroTikRouter


class HotspotDeviceLimitTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-devices", password="x")
        self.org = Organization.objects.create(
            name="Device ISP",
            owner=self.owner,
            join_code="909090",
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Family 10",
            price=Decimal("200.00"),
            download_speed_mbps=10,
            upload_speed_mbps=5,
            duration=BillingPlan.Duration.DAILY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            max_devices=2,
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Family Account",
            phone="254700000100",
            account_number="HOT-FAM-1",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:01",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
        )

    def test_creating_customer_seeds_primary_device(self):
        self.assertEqual(
            list(self.customer.devices.values_list("mac", flat=True)),
            ["AA:BB:CC:DD:EE:01"],
        )
        self.assertEqual(customer_max_devices(self.customer), 2)

    def test_attach_second_mac_under_cap(self):
        result = attach_hotspot_device(self.customer, "AA:BB:CC:DD:EE:02")
        self.assertTrue(result["ok"])
        self.assertTrue(result["created"])
        self.assertEqual(
            hotspot_macs_for_customer(self.customer),
            ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"],
        )
        found = find_hotspot_customer_for_mac(self.org, "AA:BB:CC:DD:EE:02")
        self.assertEqual(found.pk, self.customer.pk)

    def test_hotspot_macs_include_redeemed_voucher_mac(self):
        from billing.models import AccessVoucher

        AccessVoucher.objects.create(
            organization=self.org,
            customer=self.customer,
            plan=self.plan,
            code="4827K",
            status=AccessVoucher.Status.INVALID,
            redeemed_mac="AA:BB:CC:DD:EE:77",
        )
        self.assertIn(
            "AA:BB:CC:DD:EE:77",
            hotspot_macs_for_customer(self.customer),
        )

    def test_unlimited_plan_accepts_extra_macs(self):
        self.plan.max_devices = 0
        self.plan.save(update_fields=["max_devices"])
        self.assertTrue(customer_devices_unlimited(self.customer))
        self.assertEqual(customer_max_devices(self.customer), 0)
        first = attach_hotspot_device(self.customer, "AA:BB:CC:DD:EE:02")
        second = attach_hotspot_device(self.customer, "AA:BB:CC:DD:EE:03")
        self.assertTrue(first["ok"])
        self.assertTrue(second["ok"])
        self.assertEqual(CustomerDevice.objects.filter(customer=self.customer).count(), 3)

    def test_attach_third_mac_is_rejected(self):
        attach_hotspot_device(self.customer, "AA:BB:CC:DD:EE:02")
        result = attach_hotspot_device(self.customer, "AA:BB:CC:DD:EE:03")
        self.assertFalse(result["ok"])
        self.assertTrue(result.get("at_cap"))
        self.assertEqual(CustomerDevice.objects.filter(customer=self.customer).count(), 2)

    def test_same_mac_on_another_account_is_rejected(self):
        other = Customer.objects.create(
            organization=self.org,
            full_name="Other",
            phone="254700000101",
            account_number="HOT-FAM-2",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:99",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
        )
        result = attach_hotspot_device(other, "AA:BB:CC:DD:EE:01")
        self.assertFalse(result["ok"])
        self.assertIn("another account", result["error"])

    def test_phone_lookup_attaches_new_mac_without_new_customer(self):
        apply_subscription_renewal(self.customer, plan=self.plan)
        resolved = resolve_or_create_hotspot_customer(
            self.org,
            mac="AA:BB:CC:DD:EE:02",
            phone="0700000100",
            plan=self.plan,
        )
        self.assertTrue(resolved["ok"])
        self.assertFalse(resolved["created"])
        self.assertTrue(resolved["attached"])
        self.assertTrue(resolved["already_paid"])
        self.assertEqual(resolved["customer"].pk, self.customer.pk)
        self.assertEqual(Customer.objects.filter(organization=self.org).count(), 1)

    def test_phone_lookup_requires_voucher_when_unused_codes_remain(self):
        from billing.models import AccessVoucher

        apply_subscription_renewal(self.customer, plan=self.plan)
        AccessVoucher.objects.create(
            organization=self.org,
            customer=self.customer,
            plan=self.plan,
            code="FAMCODE2",
            status=AccessVoucher.Status.VALID,
        )
        resolved = resolve_or_create_hotspot_customer(
            self.org,
            mac="AA:BB:CC:DD:EE:02",
            phone="0700000100",
            plan=self.plan,
        )
        self.assertTrue(resolved["ok"])
        self.assertFalse(resolved["attached"])
        self.assertTrue(resolved["already_paid"])
        self.assertTrue(resolved["needs_voucher"])
        self.assertFalse(
            CustomerDevice.objects.filter(
                customer=self.customer, mac="AA:BB:CC:DD:EE:02"
            ).exists()
        )

    def test_phone_lookup_rejects_when_cap_reached(self):
        attach_hotspot_device(self.customer, "AA:BB:CC:DD:EE:02")
        resolved = resolve_or_create_hotspot_customer(
            self.org,
            mac="AA:BB:CC:DD:EE:03",
            phone="254700000100",
            plan=self.plan,
        )
        self.assertFalse(resolved["ok"])
        self.assertTrue(resolved.get("at_cap"))


class HotspotPaymentStartDeviceTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-hs-pay", password="x")
        self.org = Organization.objects.create(
            name="Pay Device ISP",
            owner=self.owner,
            join_code="919191",
            hotspot_enabled=True,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Hotspot 5",
            price=Decimal("50.00"),
            download_speed_mbps=5,
            upload_speed_mbps=2,
            duration=BillingPlan.Duration.DAILY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            max_devices=2,
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="HS NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.50.50.1",
            username="admin",
            password="secret",
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Paid Phone",
            phone="254700000200",
            account_number="HOT-PAY-1",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="11:22:33:44:55:01",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            router=self.router,
            package_start=timezone.now() - timedelta(hours=1),
            package_end=timezone.now() + timedelta(hours=20),
        )

    def test_second_device_with_unused_voucher_must_redeem(self):
        from billing.models import AccessVoucher

        AccessVoucher.objects.create(
            organization=self.org,
            customer=self.customer,
            plan=self.plan,
            code="PAYCODE2",
            status=AccessVoucher.Status.VALID,
        )
        url = reverse("core:hotspot_payment_start", kwargs={"join_code": self.org.join_code})
        with (
            patch(
                "core.mikrotik_connect.find_hotspot_router_for_mac",
                return_value=self.router,
            ),
            patch(
                "core.views._resolve_request_hotspot_mac",
                return_value="11:22:33:44:55:02",
            ),
            patch("billing.stk.start_subscription_stk_payment") as stk,
        ):
            response = self.client.post(
                url,
                {"plan_id": str(self.plan.pk), "phone": "0700000200", "mac": "11:22:33:44:55:02"},
            )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["already_paid"])
        self.assertTrue(data["needs_voucher"])
        self.assertFalse(data.get("attached"))
        self.assertFalse(data.get("authorized"))
        stk.assert_not_called()
        self.assertFalse(
            CustomerDevice.objects.filter(
                customer=self.customer, mac="11:22:33:44:55:02"
            ).exists()
        )

    def test_second_device_same_phone_attaches_without_stk(self):
        url = reverse("core:hotspot_payment_start", kwargs={"join_code": self.org.join_code})
        with (
            patch(
                "core.mikrotik_connect.find_hotspot_router_for_mac",
                return_value=self.router,
            ),
            patch(
                "core.views._resolve_request_hotspot_mac",
                return_value="11:22:33:44:55:02",
            ),
            patch(
                "core.subscription_sync.enqueue_customer_subscription_sync",
                return_value={"ok": True, "allowed": True},
            ) as sync,
            patch("billing.stk.start_subscription_stk_payment") as stk,
        ):
            response = self.client.post(
                url,
                {"plan_id": str(self.plan.pk), "phone": "0700000200", "mac": "11:22:33:44:55:02"},
            )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["already_paid"])
        self.assertTrue(data["attached"])
        stk.assert_not_called()
        sync.assert_called_once()
        self.assertEqual(Customer.objects.filter(organization=self.org).count(), 1)
        self.assertTrue(
            CustomerDevice.objects.filter(
                customer=self.customer, mac="11:22:33:44:55:02"
            ).exists()
        )

    def test_second_device_is_rejected_at_cap(self):
        attach_hotspot_device(self.customer, "11:22:33:44:55:02")
        url = reverse("core:hotspot_payment_start", kwargs={"join_code": self.org.join_code})
        with (
            patch(
                "core.mikrotik_connect.find_hotspot_router_for_mac",
                return_value=self.router,
            ),
            patch(
                "core.views._resolve_request_hotspot_mac",
                return_value="11:22:33:44:55:03",
            ),
            patch("billing.stk.start_subscription_stk_payment") as stk,
        ):
            response = self.client.post(
                url,
                {"plan_id": str(self.plan.pk), "phone": "0700000200", "mac": "11:22:33:44:55:03"},
            )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data["ok"])
        self.assertIn("allows 2 devices", data["error"])
        stk.assert_not_called()


class HotspotNasMultiMacTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-hs-nas", password="x")
        self.org = Organization.objects.create(
            name="NAS Device ISP",
            owner=self.owner,
            join_code="929292",
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="HS Multi",
            price=Decimal("80.00"),
            download_speed_mbps=8,
            upload_speed_mbps=4,
            duration=BillingPlan.Duration.DAILY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            max_devices=2,
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Multi MAC",
            phone="254700000300",
            account_number="HOT-NAS-1",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:AA:AA:AA:AA:01",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=timezone.now() - timedelta(minutes=10),
            package_end=timezone.now() + timedelta(hours=5),
        )
        attach_hotspot_device(self.customer, "AA:AA:AA:AA:AA:02")

    def test_apply_writes_both_mac_users(self):
        from core.mikrotik_connect import _apply_hotspot_customer_on_socket

        users = []

        def fake_ensure(sock, **kwargs):
            users.append(kwargs)
            return "created"

        with (
            patch("core.mikrotik_connect._remove_lan_wide_hotspot_bypasses"),
            patch("core.mikrotik_connect._ensure_hotspot_rate_profile", return_value="hs-profile"),
            patch("core.mikrotik_connect._ensure_hotspot_user", side_effect=fake_ensure),
            patch("core.mikrotik_connect._expire_hotspot_mac_sessions"),
            patch("core.mikrotik_connect._purge_hotspot_ok_list_for_mac", return_value=0),
        ):
            applied = _apply_hotspot_customer_on_socket(object(), self.customer)

        self.assertTrue(applied.get("ok"))
        names = [row["username"] for row in users]
        self.assertEqual(names, ["AA:AA:AA:AA:AA:01", "AA:AA:AA:AA:AA:02"])
        self.assertTrue(all(not row["disabled"] for row in users))

    def test_apply_disables_all_macs_when_package_expired(self):
        from core.mikrotik_connect import _apply_hotspot_customer_on_socket

        self.customer.package_end = timezone.now() - timedelta(days=1)
        self.customer.save(update_fields=["package_end"])

        users = []
        expired = []

        def fake_ensure(sock, **kwargs):
            users.append(kwargs)
            return "updated"

        def fake_expire(sock, mac, **kwargs):
            expired.append((mac, kwargs.get("disabled"), kwargs.get("reauthenticate")))

        with (
            patch("core.mikrotik_connect._remove_lan_wide_hotspot_bypasses"),
            patch("core.mikrotik_connect._ensure_hotspot_rate_profile", return_value="hs-profile"),
            patch("core.mikrotik_connect._ensure_hotspot_user", side_effect=fake_ensure),
            patch("core.mikrotik_connect._expire_hotspot_mac_sessions", side_effect=fake_expire),
            patch("core.mikrotik_connect._purge_hotspot_ok_list_for_mac", return_value=1),
        ):
            applied = _apply_hotspot_customer_on_socket(object(), self.customer)

        self.assertTrue(applied.get("ok"))
        self.assertEqual(
            [row["username"] for row in users],
            ["AA:AA:AA:AA:AA:01", "AA:AA:AA:AA:AA:02"],
        )
        self.assertTrue(all(row["disabled"] for row in users))
        self.assertEqual(all(row["limit_uptime"] == "0s" for row in users), True)
        self.assertEqual(
            [mac for mac, disabled, _kick in expired],
            ["AA:AA:AA:AA:AA:01", "AA:AA:AA:AA:AA:02"],
        )
        self.assertTrue(all(disabled for _mac, disabled, _kick in expired))
        self.assertTrue(all(kick for _mac, _disabled, kick in expired))

    def test_apply_disables_over_cap_macs(self):
        from core.mikrotik_connect import _apply_hotspot_customer_on_socket

        # Bypass attach cap to simulate a lowered package limit with leftover rows.
        from billing.devices import ensure_customer_device

        ensure_customer_device(self.customer, "AA:AA:AA:AA:AA:03")
        users = []

        def fake_ensure(sock, **kwargs):
            users.append(kwargs)
            return "updated"

        with (
            patch("core.mikrotik_connect._remove_lan_wide_hotspot_bypasses"),
            patch("core.mikrotik_connect._ensure_hotspot_rate_profile", return_value="hs-profile"),
            patch("core.mikrotik_connect._ensure_hotspot_user", side_effect=fake_ensure),
            patch("core.mikrotik_connect._expire_hotspot_mac_sessions"),
            patch("core.mikrotik_connect._purge_hotspot_ok_list_for_mac", return_value=1),
        ):
            applied = _apply_hotspot_customer_on_socket(object(), self.customer)

        self.assertTrue(applied.get("ok"))
        self.assertEqual(applied.get("max_devices"), 2)
        self.assertEqual(applied.get("allowed_count"), 2)
        # Prune removes the third CustomerDevice before NAS write.
        self.assertEqual(applied.get("over_cap_count"), 0)
        self.assertIn("AA:AA:AA:AA:AA:03", applied.get("pruned_macs") or [])
        enabled = [row for row in users if not row["disabled"]]
        disabled = [row for row in users if row["disabled"]]
        self.assertEqual(len(enabled), 2)
        self.assertEqual(len(disabled), 0)

    def test_prune_over_cap_keeps_primary(self):
        from billing.devices import ensure_customer_device, prune_over_cap_hotspot_devices

        ensure_customer_device(self.customer, "AA:AA:AA:AA:AA:03")
        ensure_customer_device(self.customer, "AA:AA:AA:AA:AA:04")
        removed = prune_over_cap_hotspot_devices(self.customer)
        self.assertEqual(sorted(removed), ["AA:AA:AA:AA:AA:03", "AA:AA:AA:AA:AA:04"])
        self.assertEqual(
            hotspot_macs_for_customer(self.customer),
            ["AA:AA:AA:AA:AA:01", "AA:AA:AA:AA:AA:02"],
        )
