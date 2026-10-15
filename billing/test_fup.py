from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from accounts.models import Organization
from datetime import datetime, timedelta

from billing.fup import (
    apply_fup_byte_delta,
    customer_fup_blocks_internet,
    customer_fup_is_active,
    customer_fup_throttle_speeds,
    customer_fup_usage_snapshot,
    evaluate_customer_fup,
    fup_next_reset_at,
    plan_fup_limit_bytes,
    reset_customer_fup_window,
    roll_elapsed_fup_windows,
    set_customer_fup_enabled,
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

    def test_client_fup_disable_exempts_from_throttle_and_disconnect(self):
        reset_customer_fup_window(self.customer, at=timezone.localtime())
        limit = plan_fup_limit_bytes(self.plan)
        with patch("billing.fup._schedule_fup_access_sync") as sync:
            apply_fup_byte_delta(self.customer, limit)
            self.customer.refresh_from_db()
            self.assertTrue(self.customer.fup_restricted)
            self.assertEqual(customer_fup_throttle_speeds(self.customer), (1, 1))

            result = set_customer_fup_enabled(self.customer, False, sync_access=True)
            self.customer.refresh_from_db()
            self.assertTrue(result["changed"])
            self.assertFalse(self.customer.fup_enabled)
            self.assertFalse(self.customer.fup_restricted)
            self.assertFalse(customer_fup_is_active(self.customer))
            self.assertIsNone(customer_fup_throttle_speeds(self.customer))
            self.assertFalse(customer_fup_blocks_internet(self.customer))
            self.assertTrue(customer_receives_internet(self.customer))
            # Bytes stay so re-enable can re-apply the package action.
            self.assertGreaterEqual(self.customer.fup_bytes_used, limit)
            sync.assert_called()

            # Further deltas are ignored while disabled.
            skipped = apply_fup_byte_delta(self.customer, limit)
            self.assertTrue(skipped.get("skipped"))
            self.customer.refresh_from_db()
            self.assertFalse(self.customer.fup_restricted)

    def test_client_fup_reenable_applies_package_action(self):
        reset_customer_fup_window(self.customer, at=timezone.localtime())
        limit = plan_fup_limit_bytes(self.plan)
        self.customer.fup_bytes_used = limit
        self.customer.fup_enabled = False
        self.customer.fup_restricted = False
        self.customer.save(
            update_fields=["fup_bytes_used", "fup_enabled", "fup_restricted"]
        )
        with patch("billing.fup._schedule_fup_access_sync"):
            result = set_customer_fup_enabled(self.customer, True, sync_access=True)
        self.customer.refresh_from_db()
        self.assertTrue(result["fup_enabled"])
        self.assertTrue(result["restricted"])
        self.assertTrue(self.customer.fup_restricted)
        self.assertEqual(customer_fup_throttle_speeds(self.customer), (1, 1))

        self.plan.fup_action = BillingPlan.FupAction.DISCONNECT
        self.plan.save(update_fields=["fup_action"])
        self.customer.plan.refresh_from_db()
        self.assertTrue(customer_fup_blocks_internet(self.customer, plan=self.plan))
        self.assertFalse(customer_receives_internet(self.customer))

    def test_client_detail_set_client_fup_endpoint(self):
        self.client.force_login(self.owner)
        url = reverse("core:client_detail", kwargs={"customer_id": self.customer.pk})
        with patch("billing.fup._schedule_fup_access_sync"):
            res = self.client.post(
                url,
                {"action": "set_client_fup", "fup_enabled": "0"},
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )
        self.assertEqual(res.status_code, 200)
        payload = res.json()
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["fup_enabled"])
        self.customer.refresh_from_db()
        self.assertFalse(self.customer.fup_enabled)

        page = self.client.get(url)
        self.assertEqual(page.status_code, 200)
        html = page.content.decode()
        self.assertIn("Fair usage policy", html)
        self.assertIn("data-client-fup", html)
        self.assertIn("Disabled", html)


def _local_at(year, month, day, hour=0, minute=0):
    return timezone.make_aware(
        datetime(year, month, day, hour, minute),
        timezone.get_current_timezone(),
    )


class FupMidnightResetTests(TestCase):
    """Daily FUP windows end at local 00:00, not 24 hours after they started."""

    def setUp(self):
        self.owner = User.objects.create_user("owner-fup-midnight", password="x")
        self.org = Organization.objects.create(
            name="FUP Midnight ISP",
            owner=self.owner,
            join_code="929292",
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Daily Cap",
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
        started = _local_at(2026, 10, 14, 15, 30)
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Midnight Client",
            phone="0712000001",
            account_number="FUP-MID-1",
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=started,
            package_end=started + timedelta(days=30),
            pppoe_username="fupmid",
        )

    def _restrict_from(self, started):
        limit = plan_fup_limit_bytes(self.plan)
        reset_customer_fup_window(self.customer, at=started)
        self.customer.fup_bytes_used = limit
        self.customer.fup_restricted = True
        self.customer.fup_restricted_at = started
        self.customer.save(
            update_fields=["fup_bytes_used", "fup_restricted", "fup_restricted_at"]
        )

    def test_one_day_window_resets_at_local_midnight(self):
        started = _local_at(2026, 10, 14, 15, 30)
        self._restrict_from(started)
        self.assertEqual(fup_next_reset_at(self.plan, started), _local_at(2026, 10, 15, 0, 0))

        before = _local_at(2026, 10, 14, 23, 59)
        with (
            patch("billing.fup._now", return_value=before),
            patch("billing.fup._schedule_fup_access_sync"),
        ):
            still = evaluate_customer_fup(
                self.customer, recompute_usage=False, sync_access=False
            )
            self.assertTrue(still["restricted"])
            self.assertEqual(customer_fup_throttle_speeds(self.customer), (1, 1))
        self.customer.refresh_from_db()
        self.assertTrue(self.customer.fup_restricted)
        self.assertEqual(self.customer.fup_bytes_used, plan_fup_limit_bytes(self.plan))

        at_midnight = _local_at(2026, 10, 15, 0, 0)
        with (
            patch("billing.fup._now", return_value=at_midnight),
            patch("billing.fup._schedule_fup_access_sync") as sync,
        ):
            result = evaluate_customer_fup(
                self.customer, recompute_usage=False, sync_access=True
            )
            self.assertIsNone(customer_fup_throttle_speeds(self.customer))
            self.assertFalse(customer_fup_blocks_internet(self.customer))
        self.customer.refresh_from_db()
        self.assertFalse(result["restricted"])
        self.assertTrue(result["changed"])
        self.assertFalse(self.customer.fup_restricted)
        self.assertEqual(self.customer.fup_bytes_used, 0)
        self.assertEqual(self.customer.fup_window_start, at_midnight)
        sync.assert_called()

    def test_afternoon_start_does_not_wait_until_next_afternoon(self):
        started = _local_at(2026, 10, 14, 15, 30)
        self._restrict_from(started)
        morning = _local_at(2026, 10, 15, 9, 0)
        with (
            patch("billing.fup._now", return_value=morning),
            patch("billing.fup._schedule_fup_access_sync"),
        ):
            result = evaluate_customer_fup(
                self.customer, recompute_usage=False, sync_access=False
            )
            snap = customer_fup_usage_snapshot(self.customer, self.plan)
        self.customer.refresh_from_db()
        self.assertFalse(result["restricted"])
        self.assertEqual(self.customer.fup_window_start, _local_at(2026, 10, 15, 0, 0))
        self.assertEqual(snap["bytes_used"], 0)
        self.assertFalse(snap["restricted"])

    def test_disconnect_lifts_at_midnight_via_roll(self):
        self.plan.fup_action = BillingPlan.FupAction.DISCONNECT
        self.plan.save(update_fields=["fup_action"])
        started = _local_at(2026, 10, 14, 18, 0)
        self._restrict_from(started)
        with patch("billing.fup._now", return_value=started):
            self.assertTrue(customer_fup_blocks_internet(self.customer))
            self.assertFalse(customer_receives_internet(self.customer))

        with patch("billing.fup._now", return_value=_local_at(2026, 10, 15, 0, 5)):
            with patch("billing.fup._schedule_fup_access_sync") as sync:
                cleared = roll_elapsed_fup_windows(now=_local_at(2026, 10, 15, 0, 5))
        self.customer.refresh_from_db()
        self.assertEqual(cleared, 1)
        self.assertFalse(self.customer.fup_restricted)
        self.assertEqual(self.customer.fup_bytes_used, 0)
        self.assertFalse(customer_fup_blocks_internet(self.customer))
        self.assertTrue(customer_receives_internet(self.customer))
        sync.assert_called()

    def test_hourly_window_does_not_snap_to_midnight(self):
        self.plan.fup_period_unit = BillingPlan.DurationUnit.HOURS
        self.plan.fup_period_value = 6
        self.plan.save(update_fields=["fup_period_unit", "fup_period_value"])
        started = _local_at(2026, 10, 14, 20, 0)
        self._restrict_from(started)
        self.assertEqual(fup_next_reset_at(self.plan, started), _local_at(2026, 10, 15, 2, 0))
        from billing.fup import ensure_fup_window

        self.assertFalse(
            ensure_fup_window(self.customer, self.plan, now=_local_at(2026, 10, 15, 0, 0))
        )
        self.customer.refresh_from_db()
        self.assertTrue(self.customer.fup_restricted)
        self.assertTrue(
            ensure_fup_window(self.customer, self.plan, now=_local_at(2026, 10, 15, 2, 0))
        )

    def test_seven_day_window_resets_on_midnight_of_day_seven(self):
        self.plan.fup_period_value = 7
        self.plan.save(update_fields=["fup_period_value"])
        started = _local_at(2026, 10, 1, 11, 0)
        self.assertEqual(fup_next_reset_at(self.plan, started), _local_at(2026, 10, 8, 0, 0))
        self._restrict_from(started)
        from billing.fup import ensure_fup_window

        self.assertFalse(
            ensure_fup_window(self.customer, self.plan, now=_local_at(2026, 10, 7, 23, 0))
        )
        self.assertTrue(
            ensure_fup_window(self.customer, self.plan, now=_local_at(2026, 10, 8, 0, 0))
        )
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.fup_window_start, _local_at(2026, 10, 8, 0, 0))
        self.assertEqual(self.customer.fup_bytes_used, 0)
