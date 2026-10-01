from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from accounts.models import Organization
from billing.fup import (
    apply_fup_byte_delta,
    customer_fup_blocks_internet,
    customer_fup_throttle_speeds,
    evaluate_customer_fup,
    plan_fup_limit_bytes,
    reset_customer_fup_window,
)
from billing.models import BillingPlan, Customer
from billing.services import customer_receives_internet


class PackageFupTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-pkg-fup", password="x")
        self.org = Organization.objects.create(
            name="FUP ISP",
            owner=self.owner,
            join_code="909090",
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Home FUP",
            price=Decimal("2000.00"),
            download_speed_mbps=20,
            upload_speed_mbps=10,
            duration=BillingPlan.Duration.MONTHLY,
            is_active=True,
        )
        self.client.force_login(self.owner)

    def test_packages_page_exposes_fup_controls(self):
        res = self.client.get(reverse("billing:packages"))
        self.assertEqual(res.status_code, 200)
        html = res.content.decode()
        self.assertIn("Fair usage policy", html)
        self.assertIn('name="fup_enabled"', html)
        self.assertIn('name="fup_period_value"', html)
        self.assertIn('name="fup_data_limit_gb"', html)
        self.assertIn('name="fup_action"', html)

    def test_register_package_with_fup_throttle(self):
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "register_package",
                "name": "FUP Throttle",
                "description": "",
                "price": "1800.00",
                "download_speed_mbps": "15",
                "upload_speed_mbps": "5",
                "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.MONTHS,
                "service_type": BillingPlan.ServiceType.PPPOE,
                "is_active": "on",
                "fup_enabled": "on",
                "fup_period_value": "1",
                "fup_period_unit": BillingPlan.DurationUnit.MONTHS,
                "fup_data_limit_gb": "40",
                "fup_action": BillingPlan.FupAction.THROTTLE,
                "fup_throttle_download_mbps": "2",
                "fup_throttle_upload_mbps": "1",
            },
        )
        self.assertEqual(res.status_code, 302)
        plan = BillingPlan.objects.get(organization=self.org, name="FUP THROTTLE")
        self.assertTrue(plan.fup_enabled)
        self.assertEqual(plan.fup_data_limit_gb, Decimal("40.00"))
        self.assertEqual(plan.fup_action, BillingPlan.FupAction.THROTTLE)
        self.assertEqual(plan.fup_throttle_download_mbps, 2)
        self.assertIn("40 GB", plan.fup_display_label)

    def test_register_fup_requires_data_limit(self):
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "register_package",
                "name": "FUP Incomplete",
                "description": "",
                "price": "1000.00",
                "download_speed_mbps": "10",
                "upload_speed_mbps": "5",
                "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.MONTHS,
                "service_type": BillingPlan.ServiceType.PPPOE,
                "is_active": "on",
                "fup_enabled": "on",
                "fup_period_value": "7",
                "fup_period_unit": BillingPlan.DurationUnit.DAYS,
                "fup_action": BillingPlan.FupAction.DISCONNECT,
            },
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(
            BillingPlan.objects.filter(organization=self.org, name="FUP INCOMPLETE").exists()
        )

    def test_edit_package_enables_fup_disconnect(self):
        with patch(
            "billing.views._schedule_reprovision_customers_for_plan_speeds",
        ) as schedule:
            res = self.client.post(
                reverse("billing:packages"),
                {
                    "action": "edit_package",
                    "package_id": str(self.plan.id),
                    "name": "Home FUP",
                    "description": "",
                    "price": "2000.00",
                    "download_speed_mbps": "20",
                    "upload_speed_mbps": "10",
                    "duration_value": "1",
                    "duration_unit": BillingPlan.DurationUnit.MONTHS,
                    "service_type": BillingPlan.ServiceType.PPPOE,
                    "is_active": "on",
                    "fup_enabled": "on",
                    "fup_period_value": "30",
                    "fup_period_unit": BillingPlan.DurationUnit.DAYS,
                    "fup_data_limit_gb": "100",
                    "fup_action": BillingPlan.FupAction.DISCONNECT,
                    "fup_throttle_download_mbps": "1",
                    "fup_throttle_upload_mbps": "1",
                },
            )
        self.assertEqual(res.status_code, 302)
        self.plan.refresh_from_db()
        self.assertTrue(self.plan.fup_enabled)
        self.assertEqual(self.plan.fup_action, BillingPlan.FupAction.DISCONNECT)
        self.assertEqual(self.plan.fup_period_value, 30)
        schedule.assert_called_once_with(self.plan.id)


class CustomerFupEnforcementTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-fup-enf", password="x")
        self.org = Organization.objects.create(
            name="FUP Enforce ISP",
            owner=self.owner,
            join_code="919191",
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Capped",
            price=Decimal("1500.00"),
            download_speed_mbps=10,
            upload_speed_mbps=5,
            duration=BillingPlan.Duration.MONTHLY,
            fup_enabled=True,
            fup_period_value=1,
            fup_period_unit=BillingPlan.DurationUnit.DAYS,
            fup_data_limit_gb=Decimal("1.00"),
            fup_action=BillingPlan.FupAction.THROTTLE,
            fup_throttle_download_mbps=1,
            fup_throttle_upload_mbps=1,
        )
        now = timezone.localtime()
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="FUP Client",
            phone="0712345678",
            account_number="FUP-001",
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now,
            package_end=now + timezone.timedelta(days=30),
            pppoe_username="fupuser",
        )

    def test_throttle_applies_after_limit(self):
        reset_customer_fup_window(self.customer, at=timezone.localtime())
        limit = plan_fup_limit_bytes(self.plan)
        with patch("billing.fup._schedule_fup_access_sync"):
            result = apply_fup_byte_delta(self.customer, limit)
        self.customer.refresh_from_db()
        self.assertTrue(result["restricted"])
        self.assertTrue(self.customer.fup_restricted)
        speeds = customer_fup_throttle_speeds(self.customer)
        self.assertEqual(speeds, (1, 1))
        self.assertFalse(customer_fup_blocks_internet(self.customer))

    def test_disconnect_blocks_internet(self):
        self.plan.fup_action = BillingPlan.FupAction.DISCONNECT
        self.plan.save(update_fields=["fup_action"])
        reset_customer_fup_window(self.customer, at=timezone.localtime())
        limit = plan_fup_limit_bytes(self.plan)
        with patch("billing.fup._schedule_fup_access_sync"):
            apply_fup_byte_delta(self.customer, limit)
        self.customer.refresh_from_db()
        self.assertTrue(customer_fup_blocks_internet(self.customer))
        self.assertFalse(customer_receives_internet(self.customer))

    def test_window_reset_clears_restriction(self):
        reset_customer_fup_window(
            self.customer,
            at=timezone.localtime() - timezone.timedelta(days=2),
        )
        self.customer.fup_bytes_used = plan_fup_limit_bytes(self.plan)
        self.customer.fup_restricted = True
        self.customer.save(
            update_fields=["fup_bytes_used", "fup_restricted", "fup_window_start"]
        )
        with patch("billing.fup._schedule_fup_access_sync"):
            result = evaluate_customer_fup(self.customer, sync_access=False)
        self.customer.refresh_from_db()
        self.assertFalse(result["restricted"])
        self.assertFalse(self.customer.fup_restricted)
        self.assertEqual(self.customer.fup_bytes_used, 0)

    def test_hitting_limit_notifies_client_and_isp(self):
        reset_customer_fup_window(self.customer, at=timezone.localtime())
        limit = plan_fup_limit_bytes(self.plan)
        with (
            patch("billing.fup._schedule_fup_access_sync"),
            patch("accounts.communications.maybe_notify_fup_limit_reached") as notify,
        ):
            notify.return_value = {"ok": True, "skipped": False, "sent": 2}
            result = apply_fup_byte_delta(self.customer, limit)
        self.assertTrue(result["restricted"])
        self.assertTrue(result["changed"])
        notify.assert_called_once()
        kwargs = notify.call_args.kwargs
        self.assertEqual(kwargs.get("action"), "throttle")
        self.assertEqual(kwargs.get("bytes_limit"), limit)

    def test_already_restricted_does_not_renotify(self):
        reset_customer_fup_window(self.customer, at=timezone.localtime())
        limit = plan_fup_limit_bytes(self.plan)
        self.customer.fup_bytes_used = limit
        self.customer.fup_restricted = True
        self.customer.fup_restricted_at = timezone.localtime()
        self.customer.save(
            update_fields=["fup_bytes_used", "fup_restricted", "fup_restricted_at"]
        )
        with (
            patch("billing.fup._schedule_fup_access_sync"),
            patch("accounts.communications.maybe_notify_fup_limit_reached") as notify,
        ):
            result = apply_fup_byte_delta(self.customer, 1024)
        self.assertTrue(result["restricted"])
        self.assertFalse(result["changed"])
        notify.assert_not_called()
