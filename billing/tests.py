from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from accounts.models import Organization
from billing.models import BillingPlan, Customer
from billing.services import (
    apply_subscription_renewal,
    customer_can_surf_via_hotspot,
    customer_can_surf_via_pppoe,
    customer_package_is_paused,
    customer_pppoe_secret_disabled,
    customer_receives_internet,
    customer_subscription_expired,
    generate_account_number_from_phone,
    organization_uses_dynamic_access,
    package_remaining_seconds,
    pause_customer_package,
    recharge_customer_cash,
    resume_customer_package,
    subscription_period_allows,
)


class SubscriptionRenewalTests(SimpleTestCase):
    def test_active_renewal_extends_end_without_postponing_access(self):
        now = timezone.localtime()

        class FakeCustomer:
            plan = None
            package_start = now - timedelta(minutes=10)
            package_end = now + timedelta(minutes=50)

            def save(self, **kwargs):
                self.saved_fields = kwargs["update_fields"]

        customer = FakeCustomer()
        plan = BillingPlan(duration=BillingPlan.Duration.HOURLY)
        original_start = customer.package_start
        original_end = customer.package_end

        apply_subscription_renewal(customer, plan=plan)

        self.assertEqual(customer.package_start, original_start)
        self.assertEqual(customer.package_end, original_end + timedelta(hours=1))
        self.assertEqual(customer.saved_fields, ["package_start", "package_end"])


class PrepaidAccessPolicyTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-access", password="x")
        self.org = Organization.objects.create(
            name="Access ISP",
            owner=self.owner,
            join_code="654321",
            pppoe_compulsory=True,
            hotspot_enabled=True,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Daily",
            price="100.00",
            duration=BillingPlan.Duration.DAILY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )

    def _pppoe(self, **kwargs):
        defaults = {
            "organization": self.org,
            "full_name": "PPPoE Client",
            "phone": "254700000001",
            "account_number": "PPP-1",
            "service_type": Customer.ServiceType.PPPOE,
            "pppoe_username": "client1",
            "pppoe_password": "secret",
            "status": Customer.Status.ACTIVE,
            "plan": self.plan,
        }
        defaults.update(kwargs)
        return Customer.objects.create(**defaults)

    def _hotspot(self, **kwargs):
        defaults = {
            "organization": self.org,
            "full_name": "Hotspot Device",
            "phone": "254700000002",
            "account_number": "HOT-1",
            "service_type": Customer.ServiceType.HOTSPOT,
            "hotspot_mac": "AA:BB:CC:DD:EE:FF",
            "status": Customer.Status.ACTIVE,
            "plan": self.plan,
        }
        defaults.update(kwargs)
        return Customer.objects.create(**defaults)

    def test_pppoe_without_package_period_is_denied(self):
        customer = self._pppoe()
        self.assertTrue(subscription_period_allows(customer))
        self.assertFalse(customer_receives_internet(customer))

    def test_pppoe_with_active_package_is_allowed(self):
        now = timezone.localtime()
        customer = self._pppoe(
            package_start=now - timedelta(hours=1),
            package_end=now + timedelta(days=1),
        )
        self.assertTrue(customer_receives_internet(customer))

    def test_pppoe_with_expired_package_is_denied_but_secret_stays_enabled(self):
        now = timezone.localtime()
        customer = self._pppoe(
            package_start=now - timedelta(days=3),
            package_end=now - timedelta(days=1),
        )
        self.assertFalse(customer_receives_internet(customer))
        self.assertFalse(customer_pppoe_secret_disabled(customer))

    def test_suspended_pppoe_secret_is_disabled(self):
        now = timezone.localtime()
        customer = self._pppoe(
            status=Customer.Status.SUSPENDED,
            package_start=now - timedelta(hours=1),
            package_end=now + timedelta(days=1),
        )
        self.assertFalse(customer_receives_internet(customer))
        self.assertTrue(customer_pppoe_secret_disabled(customer))

    def test_hotspot_without_package_period_is_denied(self):
        customer = self._hotspot()
        self.assertFalse(customer_receives_internet(customer))

    def test_hotspot_with_active_package_is_allowed(self):
        now = timezone.localtime()
        customer = self._hotspot(
            package_start=now - timedelta(minutes=5),
            package_end=now + timedelta(hours=1),
        )
        self.assertTrue(customer_receives_internet(customer))

    def test_daily_package_stays_up_past_package_end_clock_until_midnight(self):
        """Daily PPPoE must not cut mid-afternoon — only at local 00:00 after end day."""
        from datetime import datetime, time
        from unittest.mock import patch

        from billing.services import subscription_access_deadline

        end_day = timezone.localdate()
        package_end = timezone.make_aware(
            datetime.combine(end_day, time(15, 0)),
            timezone.get_current_timezone(),
        )
        customer = self._pppoe(
            package_start=package_end - timedelta(days=1),
            package_end=package_end,
        )
        deadline = subscription_access_deadline(customer)
        self.assertEqual(deadline.date(), end_day + timedelta(days=1))
        self.assertEqual(deadline.time(), time(0, 0))

        real_localtime = timezone.localtime
        afternoon = timezone.make_aware(
            datetime.combine(end_day, time(18, 30)),
            timezone.get_current_timezone(),
        )

        def localtime_at(fixed):
            def _localtime(value=None):
                if value is None:
                    return fixed
                return real_localtime(value)

            return _localtime

        with (
            patch("billing.services.timezone.localtime", side_effect=localtime_at(afternoon)),
            patch("billing.services.timezone.localdate", return_value=end_day),
        ):
            self.assertTrue(subscription_period_allows(customer))
            self.assertTrue(customer_receives_internet(customer))
            self.assertFalse(customer_subscription_expired(customer))

        after_midnight = timezone.make_aware(
            datetime.combine(end_day + timedelta(days=1), time(0, 0)),
            timezone.get_current_timezone(),
        )
        with (
            patch(
                "billing.services.timezone.localtime",
                side_effect=localtime_at(after_midnight),
            ),
            patch(
                "billing.services.timezone.localdate",
                return_value=end_day + timedelta(days=1),
            ),
        ):
            self.assertFalse(subscription_period_allows(customer))
            self.assertFalse(customer_receives_internet(customer))
            self.assertTrue(customer_subscription_expired(customer))

    def test_hourly_package_still_ends_at_exact_clock_time(self):
        from datetime import datetime, time
        from unittest.mock import patch

        from billing.models import BillingPlan

        hourly = BillingPlan.objects.create(
            organization=self.org,
            name="Hourly",
            price="50.00",
            duration=BillingPlan.Duration.HOURLY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )
        end = timezone.make_aware(
            datetime.combine(timezone.localdate(), time(15, 0)),
            timezone.get_current_timezone(),
        )
        customer = self._pppoe(
            plan=hourly,
            package_start=end - timedelta(hours=1),
            package_end=end,
        )
        real_localtime = timezone.localtime

        def localtime_at(fixed):
            def _localtime(value=None):
                if value is None:
                    return fixed
                return real_localtime(value)

            return _localtime

        before = end - timedelta(minutes=1)
        with patch(
            "billing.services.timezone.localtime",
            side_effect=localtime_at(before),
        ):
            self.assertTrue(subscription_period_allows(customer))
        with patch(
            "billing.services.timezone.localtime",
            side_effect=localtime_at(end),
        ):
            self.assertFalse(subscription_period_allows(customer))


class DynamicAccessPolicyTests(TestCase):
    """
    Dynamic mode (PPPoE compulsory + Hotspot fallback):
    - Hotspot surfing only after payment applied (active package window)
    - PPPoE surfing only inside the subscription period
    """

    def setUp(self):
        self.owner = User.objects.create_user("dynamic-owner", password="x")
        self.org = Organization.objects.create(
            name="Dynamic ISP",
            owner=self.owner,
            join_code="112233",
            pppoe_compulsory=True,
            hotspot_enabled=True,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Daily",
            price="100.00",
            duration=BillingPlan.Duration.DAILY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )

    def test_organization_uses_dynamic_access_when_both_flags_on(self):
        self.assertTrue(organization_uses_dynamic_access(self.org))
        self.org.hotspot_enabled = False
        self.assertFalse(organization_uses_dynamic_access(self.org))

    def test_hotspot_denied_without_paid_package_even_after_stk_success(self):
        from billing.models import StkPushRequest
        from billing.stk import fulfill_successful_stk

        now = timezone.localtime()
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Phone",
            phone="254700000050",
            account_number="DYN-HS-1",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:01",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
        )
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=customer,
            plan=self.plan,
            phone="254700000050",
            amount=self.plan.price,
            purpose=StkPushRequest.Purpose.SUBSCRIPTION,
        )
        fulfill_successful_stk(stk, mpesa_receipt="PAID123")
        customer.refresh_from_db()
        stk.refresh_from_db()

        self.assertEqual(stk.status, StkPushRequest.Status.SUCCESS)
        self.assertFalse(stk.subscription_applied)
        self.assertIsNone(customer.package_end)
        self.assertFalse(customer_can_surf_via_hotspot(customer))
        self.assertFalse(customer_receives_internet(customer))

    def test_hotspot_allowed_only_after_voucher_redeem(self):
        from billing.models import StkPushRequest
        from billing.stk import fulfill_successful_stk
        from billing.vouchers import redeem_access_voucher

        customer = Customer.objects.create(
            organization=self.org,
            full_name="Phone Paid",
            phone="254700000051",
            account_number="DYN-HS-2",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:02",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
        )
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=customer,
            plan=self.plan,
            phone="254700000051",
            amount=self.plan.price,
            purpose=StkPushRequest.Purpose.SUBSCRIPTION,
        )
        fulfill = fulfill_successful_stk(stk, mpesa_receipt="PAID456")
        redeem = redeem_access_voucher(
            organization=self.org,
            code=fulfill["voucher_code"],
            customer=customer,
        )
        customer.refresh_from_db()

        self.assertTrue(redeem["ok"])
        self.assertTrue(customer_can_surf_via_hotspot(customer))
        self.assertIsNotNone(customer.package_end)

    def test_pppoe_allowed_only_inside_subscription_period(self):
        now = timezone.localtime()
        active = Customer.objects.create(
            organization=self.org,
            full_name="Home Active",
            phone="254700000052",
            account_number="DYN-PPP-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="home1",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now - timedelta(hours=1),
            package_end=now + timedelta(days=1),
        )
        expired = Customer.objects.create(
            organization=self.org,
            full_name="Home Expired",
            phone="254700000053",
            account_number="DYN-PPP-2",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="home2",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now - timedelta(days=3),
            package_end=now - timedelta(days=1),
        )

        self.assertTrue(customer_can_surf_via_pppoe(active))
        self.assertFalse(customer_can_surf_via_pppoe(expired))

    def test_pppoe_customer_cannot_surf_via_hotspot_path(self):
        now = timezone.localtime()
        customer = Customer.objects.create(
            organization=self.org,
            full_name="PPPoE Only",
            phone="254700000054",
            account_number="DYN-PPP-3",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="home3",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now - timedelta(hours=1),
            package_end=now + timedelta(days=1),
        )
        self.assertTrue(customer_can_surf_via_pppoe(customer))
        self.assertFalse(customer_can_surf_via_hotspot(customer))

    def test_hotspot_customer_cannot_surf_via_pppoe_path(self):
        now = timezone.localtime()
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Hotspot Only",
            phone="254700000055",
            account_number="DYN-HS-3",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:03",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now - timedelta(minutes=5),
            package_end=now + timedelta(hours=1),
        )
        self.assertTrue(customer_can_surf_via_hotspot(customer))
        self.assertFalse(customer_can_surf_via_pppoe(customer))


class AccessAccountLoopTests(TestCase):
    """Unit tests for shared PPPoE/Hotspot correction-loop helpers."""

    def setUp(self):
        self.owner = User.objects.create_user("loop-unit-owner", password="x")
        self.org = Organization.objects.create(
            name="Loop Unit ISP",
            owner=self.owner,
            join_code="909090",
            pppoe_compulsory=True,
            hotspot_enabled=True,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Daily Loop",
            price="100.00",
            duration=BillingPlan.Duration.DAILY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )
        now = timezone.localtime()
        self.pppoe_active = Customer.objects.create(
            organization=self.org,
            full_name="PPPoE Active",
            phone="254700000060",
            account_number="LOOP-PPP-ACT",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="active1",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now - timedelta(hours=1),
            package_end=now + timedelta(days=1),
        )
        self.pppoe_expired = Customer.objects.create(
            organization=self.org,
            full_name="PPPoE Expired",
            phone="254700000061",
            account_number="LOOP-PPP-EXP",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="expired1",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now - timedelta(days=3),
            package_end=now - timedelta(days=1),
        )
        self.pppoe_inactive = Customer.objects.create(
            organization=self.org,
            full_name="PPPoE Inactive",
            phone="254700000064",
            account_number="LOOP-PPP-INA",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="inactive1",
            pppoe_password="secret",
            status=Customer.Status.ALLOCATED_OPEN,
            plan=self.plan,
        )
        self.hotspot_unpaid = Customer.objects.create(
            organization=self.org,
            full_name="Hotspot Unpaid",
            phone="254700000062",
            account_number="LOOP-HS-UNP",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:AA",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
        )
        self.hotspot_paid = Customer.objects.create(
            organization=self.org,
            full_name="Hotspot Paid",
            phone="254700000063",
            account_number="LOOP-HS-PAD",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:BB",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now - timedelta(minutes=10),
            package_end=now + timedelta(hours=2),
        )

    def test_billing_allows_surf_per_account_type(self):
        from billing.access_verification import billing_allows_surf

        self.assertTrue(billing_allows_surf(self.pppoe_active))
        self.assertFalse(billing_allows_surf(self.pppoe_expired))
        self.assertFalse(billing_allows_surf(self.hotspot_unpaid))
        self.assertTrue(billing_allows_surf(self.hotspot_paid))

    def test_evaluate_pppoe_active_sync(self):
        from billing.access_verification import evaluate_nas_policy

        sync = {
            "ok": True,
            "allowed": True,
            "provision": {"ok": True, "profile": "ispcentric-5u-10d", "disabled": False},
            "portal": {"ok": True},
        }
        result = evaluate_nas_policy(self.pppoe_active, sync)
        self.assertTrue(result["policy_match"])

    def test_evaluate_pppoe_active_cpe_offline_nas_ready(self):
        from billing.access_verification import evaluate_nas_policy

        sync = {
            "ok": False,
            "allowed": True,
            "cpe_renew_clear_pending": True,
            "provision": {"ok": True, "profile": "ispcentric-5u-10d", "disabled": False},
            "portal": {"ok": False, "skipped": True, "error": "CPE offline"},
        }
        result = evaluate_nas_policy(self.pppoe_active, sync)
        self.assertTrue(result["policy_match"])
        self.assertTrue(result["details"].get("cpe_clear_pending"))

    def test_evaluate_pppoe_expired_sync(self):
        from billing.access_verification import evaluate_nas_policy

        sync = {
            "ok": True,
            "allowed": False,
            "provision": {"ok": True, "profile": "ispcentric-blocked", "disabled": False},
            "portal": {"ok": True, "skipped": False},
        }
        result = evaluate_nas_policy(self.pppoe_expired, sync)
        self.assertTrue(result["policy_match"])

    def test_evaluate_pppoe_inactive_sync(self):
        from billing.access_verification import evaluate_nas_policy

        sync = {
            "ok": True,
            "allowed": False,
            "provision": {"ok": True, "profile": "ispcentric-pppoe", "disabled": True},
            "portal": {"ok": True, "skipped": True},
        }
        result = evaluate_nas_policy(self.pppoe_inactive, sync)
        self.assertTrue(result["policy_match"])

    def test_evaluate_hotspot_unpaid_sync(self):
        from billing.access_verification import evaluate_nas_policy

        sync = {
            "ok": True,
            "allowed": False,
            "provision": {"ok": True},
        }
        result = evaluate_nas_policy(self.hotspot_unpaid, sync)
        self.assertTrue(result["policy_match"])
        self.assertTrue(result["details"]["hotspot_disabled"])

    def test_evaluate_hotspot_paid_sync(self):
        from billing.access_verification import evaluate_nas_policy

        sync = {
            "ok": True,
            "allowed": True,
            "provision": {"ok": True},
        }
        result = evaluate_nas_policy(self.hotspot_paid, sync)
        self.assertTrue(result["policy_match"])
        self.assertFalse(result["details"]["hotspot_disabled"])
        self.assertTrue(result["details"]["hotspot_limit_uptime"].endswith("s"))

    def test_run_correction_loop_retries_until_match(self):
        from billing.access_verification import run_access_correction_loop

        calls = {"n": 0}

        def fake_sync(customer, **kwargs):
            calls["n"] += 1
            if calls["n"] < 2:
                return {
                    "ok": False,
                    "allowed": True,
                    "provision": {"ok": False},
                }
            return {
                "ok": True,
                "allowed": True,
                "provision": {"ok": True, "profile": "ispcentric", "disabled": False},
                "portal": {"ok": True},
            }

        with patch(
            "core.mikrotik_connect.sync_customer_subscription_access",
            side_effect=fake_sync,
        ):
            outcome = run_access_correction_loop(
                self.pppoe_active,
                loops=3,
                settle=0,
            )
        self.assertTrue(outcome.passed)
        self.assertEqual(len(outcome.attempts), 2)

    def test_run_correction_loop_blocks_unpaid_hotspot_on_retry(self):
        from billing.access_verification import run_access_correction_loop

        sync_calls = {"n": 0}

        def fake_sync(customer, **kwargs):
            sync_calls["n"] += 1
            if sync_calls["n"] == 1:
                return {
                    "ok": False,
                    "allowed": False,
                    "provision": {"ok": False},
                }
            return {
                "ok": True,
                "allowed": False,
                "provision": {"ok": True},
            }

        with (
            patch(
                "core.mikrotik_connect.sync_customer_subscription_access",
                side_effect=fake_sync,
            ),
            patch(
                "core.mikrotik_connect.block_hotspot_mac_until_paid",
                return_value={"ok": True},
            ) as block_mock,
        ):
            outcome = run_access_correction_loop(
                self.hotspot_unpaid,
                loops=2,
                settle=0,
            )
        block_mock.assert_called_once()
        self.assertTrue(outcome.passed)

    def test_verify_access_accounts_command_dry_run(self):
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command(
            "verify_access_accounts",
            organization=self.org.pk,
            dry_run=True,
            stdout=out,
        )
        text = out.getvalue()
        self.assertIn("PASS", text)
        self.assertIn("LOOP-PPP-ACT", text)
        self.assertIn("LOOP-HS-UNP", text)

    def test_customers_for_access_verification_filters_service(self):
        from billing.access_verification import customers_for_access_verification

        pppoe_only = customers_for_access_verification(
            organization_id=self.org.pk,
            service="pppoe",
        )
        self.assertTrue(all(c.service_type == Customer.ServiceType.PPPOE for c in pppoe_only))
        self.assertEqual(len(pppoe_only), 2)

        hotspot_only = customers_for_access_verification(
            organization_id=self.org.pk,
            service="hotspot",
        )
        self.assertTrue(all(c.service_type == Customer.ServiceType.HOTSPOT for c in hotspot_only))
        self.assertEqual(len(hotspot_only), 2)


class PackagePauseResumeTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-pause", password="x")
        self.org = Organization.objects.create(
            name="Pause ISP",
            owner=self.owner,
            join_code="998877",
            pppoe_compulsory=True,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Hourly Pause",
            price="50.00",
            duration=BillingPlan.Duration.HOURLY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )

    def test_pause_blocks_internet_and_freezes_remaining(self):
        now = timezone.localtime()
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Pause Client",
            phone="254700000030",
            account_number="PPP-PAUSE",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="pause1",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now - timedelta(minutes=10),
            package_end=now + timedelta(minutes=50),
        )
        remaining_before = package_remaining_seconds(customer, now=now)
        pause_customer_package(customer, now=now)
        customer.refresh_from_db()

        self.assertTrue(customer_package_is_paused(customer))
        self.assertFalse(customer_receives_internet(customer))
        self.assertFalse(customer_pppoe_secret_disabled(customer))
        later = now + timedelta(minutes=20)
        remaining_while_paused = package_remaining_seconds(customer, now=later)
        self.assertEqual(remaining_while_paused, remaining_before)

    def test_resume_extends_end_by_pause_duration(self):
        now = timezone.localtime()
        original_end = now + timedelta(minutes=40)
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Resume Client",
            phone="254700000031",
            account_number="PPP-RESUME",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="resume1",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now - timedelta(minutes=20),
            package_end=original_end,
        )
        pause_at = now
        pause_customer_package(customer, now=pause_at)
        resume_at = pause_at + timedelta(minutes=15)
        resume_customer_package(customer, now=resume_at)
        customer.refresh_from_db()

        self.assertFalse(customer_package_is_paused(customer))
        self.assertEqual(customer.package_end, original_end + timedelta(minutes=15))
        self.assertTrue(customer_receives_internet(customer))

    def test_cannot_pause_expired_package(self):
        now = timezone.localtime()
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Expired Pause",
            phone="254700000032",
            account_number="PPP-EXPIRED-PAUSE",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="expired1",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now - timedelta(hours=2),
            package_end=now - timedelta(minutes=5),
        )
        with self.assertRaises(ValueError):
            pause_customer_package(customer, now=now)


class HotspotMacUniquenessTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-mac", password="x")
        self.org = Organization.objects.create(
            name="MAC ISP",
            owner=self.owner,
            join_code="111222",
        )

    def test_duplicate_hotspot_mac_in_same_org_is_rejected(self):
        from django.db import IntegrityError

        Customer.objects.create(
            organization=self.org,
            full_name="Device A",
            phone="254700000010",
            account_number="HOT-A",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="11:22:33:44:55:66",
        )
        with self.assertRaises(IntegrityError):
            Customer.objects.create(
                organization=self.org,
                full_name="Device B",
                phone="254700000011",
                account_number="HOT-B",
                service_type=Customer.ServiceType.HOTSPOT,
                hotspot_mac="11:22:33:44:55:66",
            )


class CustomerPhoneUniquenessTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-phone", password="x")
        self.org = Organization.objects.create(
            name="Phone ISP",
            owner=self.owner,
            join_code="555666",
        )

    def test_duplicate_phone_in_same_org_is_rejected(self):
        from django.db import IntegrityError

        Customer.objects.create(
            organization=self.org,
            full_name="Client A",
            phone="254700000010",
            account_number="CLT-A",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:01",
        )
        with self.assertRaises(IntegrityError):
            Customer.objects.create(
                organization=self.org,
                full_name="Client B",
                phone="0710000010",
                account_number="CLT-B",
                service_type=Customer.ServiceType.HOTSPOT,
                hotspot_mac="AA:BB:CC:DD:EE:02",
            )

    def test_pppoe_register_form_rejects_duplicate_phone(self):
        from billing.forms import PppoeClientRegisterForm

        Customer.objects.create(
            organization=self.org,
            full_name="Existing",
            phone="254700000011",
            account_number="CLT-EXIST",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="EXIST",
            pppoe_password="secret",
        )
        form = PppoeClientRegisterForm(
            {
                "full_name": "New Client",
                "phone": "0710000011",
                "pppoe_username": "NEWUSER",
                "pppoe_password": "secret",
                "router": "",
            },
            organization=self.org,
        )
        self.assertFalse(form.is_valid())
        self.assertIn("phone", form.errors)

    def test_normalized_phone_key_matches_equivalent_formats(self):
        from billing.services import normalize_customer_phone_key

        self.assertEqual(
            normalize_customer_phone_key("254700000012"),
            normalize_customer_phone_key("0710000012"),
        )
        self.assertEqual(
            normalize_customer_phone_key("+254700000012"),
            normalize_customer_phone_key("254700000012"),
        )


class FulfillIdempotencyTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-stk", password="x")
        self.org = Organization.objects.create(
            name="STK ISP",
            owner=self.owner,
            join_code="333444",
            pppoe_compulsory=True,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Hourly",
            price="50.00",
            duration=BillingPlan.Duration.HOURLY,
            download_speed_mbps=8,
            upload_speed_mbps=4,
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Pay Client",
            phone="254700000020",
            account_number="PPP-PAY",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="payuser",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
        )

    @patch("core.mikrotik_connect.sync_customer_subscription_access")
    def test_successful_fulfill_is_idempotent(self, sync_mock):
        from billing.models import AccessVoucher, StkPushRequest
        from billing.stk import fulfill_successful_stk

        sync_mock.return_value = {"ok": True, "allowed": True}
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=self.customer,
            amount=self.plan.price,
            phone=self.customer.phone,
            account_reference=self.customer.account_number,
            checkout_request_id="ws_CO_1",
            status=StkPushRequest.Status.PENDING,
        )

        first = fulfill_successful_stk(stk, mpesa_receipt="ABC123")
        self.customer.refresh_from_db()
        self.assertTrue(first["ok"])
        self.assertFalse(first["already_applied"])
        self.assertTrue(first["needs_voucher"])
        self.assertIsNone(self.customer.package_end)
        voucher = AccessVoucher.objects.get(stk_request=stk)
        self.assertEqual(voucher.status, AccessVoucher.Status.VALID)

        stk.refresh_from_db()
        self.assertEqual(stk.mpesa_receipt, "ABC123")
        self.assertEqual(stk.payment.reference, "ABC123")

        second = fulfill_successful_stk(stk, mpesa_receipt="ABC123")
        self.customer.refresh_from_db()
        self.assertTrue(second["ok"])
        self.assertFalse(second["already_applied"])
        self.assertEqual(second["voucher_code"], first["voucher_code"])
        self.assertIsNone(self.customer.package_end)
        self.assertEqual(AccessVoucher.objects.filter(stk_request=stk).count(), 1)
        sync_mock.assert_not_called()

    @patch("core.mikrotik_connect.sync_customer_subscription_access")
    def test_callback_backfills_mpesa_receipt_after_query(self, sync_mock):
        """STK Query may confirm first without a receipt; callback fills it in."""
        from billing.models import Payment, StkPushRequest
        from billing.stk import fulfill_successful_stk

        sync_mock.return_value = {"ok": True, "allowed": True}
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=self.customer,
            amount=self.plan.price,
            phone=self.customer.phone,
            account_reference=self.customer.account_number,
            checkout_request_id="ws_CO_RECEIPT",
            status=StkPushRequest.Status.PENDING,
        )

        first = fulfill_successful_stk(stk, mpesa_receipt="")
        self.assertTrue(first["ok"])
        stk.refresh_from_db()
        self.assertEqual(stk.payment.reference, "ws_CO_RECEIPT")
        self.assertEqual(stk.mpesa_receipt, "")

        second = fulfill_successful_stk(stk, mpesa_receipt="QWERTY99")
        self.assertTrue(second["ok"])
        stk.refresh_from_db()
        self.assertEqual(stk.mpesa_receipt, "QWERTY99")
        payment = Payment.objects.get(pk=stk.payment_id)
        self.assertEqual(payment.reference, "QWERTY99")

    @patch("core.mikrotik_connect.sync_customer_subscription_access")
    def test_fulfill_applies_the_package_that_was_charged(self, sync_mock):
        from billing.models import StkPushRequest
        from billing.stk import fulfill_successful_stk
        from billing.vouchers import redeem_access_voucher

        sync_mock.return_value = {"ok": True, "allowed": True}
        daily = BillingPlan.objects.create(
            organization=self.org,
            name="Daily",
            price="120.00",
            duration=BillingPlan.Duration.DAILY,
            download_speed_mbps=12,
            upload_speed_mbps=6,
        )
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=self.customer,
            plan=daily,
            amount=daily.price,
            phone=self.customer.phone,
            account_reference=self.customer.account_number,
            checkout_request_id="ws_CO_PLAN",
        )

        before = timezone.localtime()
        result = fulfill_successful_stk(stk, mpesa_receipt="PLAN123")
        self.customer.refresh_from_db()

        self.assertTrue(result["ok"])
        self.assertEqual(self.customer.plan_id, daily.pk)
        self.assertTrue(result["needs_voucher"])
        self.assertIsNone(self.customer.package_end)

        redeem = redeem_access_voucher(
            organization=self.org,
            code=result["voucher_code"],
            customer=self.customer,
        )
        self.customer.refresh_from_db()
        self.assertTrue(redeem["ok"])
        self.assertGreater(
            self.customer.package_end - before,
            timedelta(hours=23),
        )
        stk.refresh_from_db()
        self.assertEqual(stk.payment.reference, "PLAN123")
        sync_mock.assert_called()


class AccountNumberFromPhoneTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-acct", password="x")
        self.org = Organization.objects.create(
            name="Acct ISP",
            owner=self.owner,
            join_code="112233",
        )

    def test_local_phone_becomes_msisdn_account(self):
        self.assertEqual(
            generate_account_number_from_phone("0712345678", organization=self.org),
            "254712345678",
        )

    def test_collision_appends_suffix(self):
        Customer.objects.create(
            organization=self.org,
            full_name="Existing",
            phone="0712345678",
            account_number="254712345678",
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.ACTIVE,
        )
        self.assertEqual(
            generate_account_number_from_phone("0712345678", organization=self.org),
            "254712345678-2",
        )


class AccessVoucherLifecycleTests(TestCase):
    """Payment → valid voucher → redeem/expired → surfing/invalid."""

    def setUp(self):
        self.owner = User.objects.create_user("owner-voucher", password="x")
        self.org = Organization.objects.create(
            name="Voucher ISP",
            owner=self.owner,
            join_code="778899",
            hotspot_enabled=True,
            pppoe_compulsory=True,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Daily Hotspot",
            price="50.00",
            duration=BillingPlan.Duration.DAILY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
            service_type=BillingPlan.ServiceType.HOTSPOT,
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Voucher Client",
            phone="254700000777",
            account_number="HOT-VOUCHER-1",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:77",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
        )

    def _stk(self, **kwargs):
        from decimal import Decimal

        from billing.models import StkPushRequest

        defaults = {
            "organization": self.org,
            "customer": self.customer,
            "plan": self.plan,
            "amount": Decimal("50.00"),
            "phone": "254700000777",
            "account_reference": self.customer.account_number,
            "checkout_request_id": "ws_CO_TEST_VOUCHER",
            "status": StkPushRequest.Status.PENDING,
            "purpose": StkPushRequest.Purpose.SUBSCRIPTION,
        }
        defaults.update(kwargs)
        return StkPushRequest.objects.create(**defaults)

    def test_payment_success_creates_valid_voucher_without_activating(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk

        stk = self._stk()
        with patch(
            "core.mikrotik_connect.sync_customer_subscription_access"
        ) as sync_mock:
            result = fulfill_successful_stk(
                stk,
                result_code=0,
                result_desc="The service request is processed successfully.",
                mpesa_receipt="RCVVOUCHER1",
            )

        stk.refresh_from_db()
        self.customer.refresh_from_db()
        voucher = AccessVoucher.objects.get(stk_request=stk)

        self.assertTrue(result["ok"])
        self.assertTrue(result["needs_voucher"])
        self.assertEqual(result["voucher_status"], AccessVoucher.Status.VALID)
        self.assertFalse(stk.subscription_applied)
        self.assertIsNone(self.customer.package_end)
        self.assertEqual(voucher.status, AccessVoucher.Status.VALID)
        sync_mock.assert_not_called()

    def test_redeem_activates_once_and_marks_expired(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk
        from billing.vouchers import redeem_access_voucher

        stk = self._stk()
        fulfill_successful_stk(
            stk,
            result_code=0,
            result_desc="ok",
            mpesa_receipt="RCVVOUCHER2",
        )
        voucher = AccessVoucher.objects.get(stk_request=stk)
        code = voucher.code

        with patch(
            "core.mikrotik_connect.sync_customer_subscription_access",
            return_value={"ok": True, "allowed": True},
        ):
            first = redeem_access_voucher(
                organization=self.org,
                code=code,
                customer=self.customer,
                mac=self.customer.hotspot_mac,
            )
            second = redeem_access_voucher(
                organization=self.org,
                code=code,
                customer=self.customer,
            )

        voucher.refresh_from_db()
        stk.refresh_from_db()
        self.customer.refresh_from_db()

        self.assertTrue(first["ok"])
        self.assertTrue(first["activated"])
        self.assertEqual(first["voucher_status"], AccessVoucher.Status.EXPIRED)
        self.assertTrue(first["authorized"])
        self.assertIsNotNone(self.customer.package_end)
        self.assertTrue(stk.subscription_applied)
        self.assertEqual(voucher.status, AccessVoucher.Status.EXPIRED)
        self.assertFalse(second["ok"])
        self.assertEqual(second.get("voucher_status"), "expired")

    def test_surfing_marks_expired_voucher_invalid(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk
        from billing.vouchers import (
            invalidate_vouchers_for_surfing_customers,
            redeem_access_voucher,
        )

        stk = self._stk()
        fulfill_successful_stk(stk, result_code=0, result_desc="ok", mpesa_receipt="R3")
        voucher = AccessVoucher.objects.get(stk_request=stk)
        with patch(
            "core.mikrotik_connect.sync_customer_subscription_access",
            return_value={"ok": True, "allowed": True},
        ):
            redeem_access_voucher(
                organization=self.org, code=voucher.code, customer=self.customer
            )
        voucher.refresh_from_db()
        self.assertEqual(voucher.status, AccessVoucher.Status.EXPIRED)

        changed = invalidate_vouchers_for_surfing_customers([self.customer])
        voucher.refresh_from_db()
        self.assertEqual(changed, 1)
        self.assertEqual(voucher.status, AccessVoucher.Status.INVALID)
        self.assertIsNotNone(voucher.invalidated_at)

    def test_surfing_while_valid_burns_voucher_and_applies_package(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk
        from billing.vouchers import invalidate_vouchers_for_surfing_customers

        stk = self._stk()
        fulfill_successful_stk(stk, result_code=0, result_desc="ok", mpesa_receipt="R4")
        voucher = AccessVoucher.objects.get(stk_request=stk)
        self.assertEqual(voucher.status, AccessVoucher.Status.VALID)
        self.assertIsNone(self.customer.package_end)

        changed = invalidate_vouchers_for_surfing_customers([self.customer])
        voucher.refresh_from_db()
        stk.refresh_from_db()
        self.customer.refresh_from_db()

        self.assertEqual(changed, 1)
        self.assertEqual(voucher.status, AccessVoucher.Status.INVALID)
        self.assertIsNotNone(self.customer.package_end)
        self.assertTrue(stk.subscription_applied)

        from billing.vouchers import redeem_access_voucher

        blocked = redeem_access_voucher(
            organization=self.org, code=voucher.code, customer=self.customer
        )
        self.assertFalse(blocked["ok"])
        self.assertEqual(blocked.get("voucher_status"), "invalid")

    def test_fulfill_is_idempotent_for_same_stk(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk

        stk = self._stk()
        first = fulfill_successful_stk(
            stk, result_code=0, result_desc="ok", mpesa_receipt="R5"
        )
        second = fulfill_successful_stk(
            stk, result_code=0, result_desc="ok", mpesa_receipt="R5"
        )
        self.assertEqual(
            AccessVoucher.objects.filter(stk_request=stk).count(),
            1,
        )
        self.assertEqual(first["voucher_code"], second["voucher_code"])

    def test_pay_page_shows_voucher_input(self):
        self.org.daraja_enabled = True
        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.mpesa_payment_type = Organization.MpesaPaymentType.PAYBILL
        self.org.mpesa_number = "123456"
        self.org.daraja_consumer_key = "key"
        self.org.daraja_consumer_secret = "secret"
        self.org.daraja_passkey = "pass"
        self.org.daraja_callback_url = "https://example.com/callback"
        self.org.save()

        response = self.client.get(f"/hotspot/{self.org.join_code}/pay/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Have a voucher?")
        self.assertContains(response, 'name="voucher_code"')
        self.assertContains(response, "Activate voucher")

    def test_client_billing_lists_and_shares_voucher(self):
        from billing.models import AccessVoucher, StkPushRequest
        from billing.stk import fulfill_successful_stk

        self.client.force_login(self.owner)
        stk = self._stk()
        result = fulfill_successful_stk(
            stk, result_code=0, result_desc="ok", mpesa_receipt="SHARE1"
        )
        voucher = AccessVoucher.objects.get(stk_request=stk)

        response = self.client.get(f"/app/clients/{self.customer.pk}/billing/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Access vouchers")
        self.assertContains(response, result["voucher_code"])
        self.assertContains(response, "WhatsApp")
        self.assertContains(response, "Copy")
        self.assertContains(response, "Pay page")
        self.assertEqual(response.context["valid_voucher_count"], 1)
        self.assertEqual(voucher.status, AccessVoucher.Status.VALID)
        # Share payload targets the client's phone.
        row = response.context["vouchers"][0]
        self.assertTrue(row["share"]["can_share"])
        self.assertIn(voucher.code[:4], row["share"]["share_text"])
        self.assertIn("wa.me/254700000777", row["share"]["whatsapp_client_url"])


class CashRechargeTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-cash", password="x")
        self.org = Organization.objects.create(
            name="Cash ISP",
            owner=self.owner,
            join_code="111222",
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Hourly",
            price="50.00",
            duration=BillingPlan.Duration.HOURLY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )
        now = timezone.localtime()
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Cash Client",
            phone="254700000050",
            account_number="CASH-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="cash1",
            pppoe_password="secret",
            status=Customer.Status.SUSPENDED,
            plan=self.plan,
            package_start=now - timedelta(minutes=30),
            package_end=now + timedelta(minutes=30),
        )

    def test_cash_recharge_records_payment_and_extends_package(self):
        from billing.models import Invoice, Payment

        original_end = self.customer.package_end
        result = recharge_customer_cash(
            customer=self.customer,
            organization=self.org,
            plan=self.plan,
            amount="50.00",
            reference="RCP-1",
            recorded_by=self.owner,
        )
        self.customer.refresh_from_db()
        payment = result["payment"]
        invoice = result["invoice"]

        self.assertEqual(self.customer.status, Customer.Status.ACTIVE)
        self.assertEqual(self.customer.package_end, original_end + timedelta(hours=1))
        self.assertEqual(payment.method, Payment.Method.CASH)
        self.assertEqual(payment.reference, "RCP-1")
        self.assertEqual(invoice.status, Invoice.Status.PAID)
        self.assertTrue(invoice.invoice_number.startswith("CASH-"))
        self.assertTrue(customer_receives_internet(self.customer))
