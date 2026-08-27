from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from accounts.models import Organization
from billing.models import BillingPlan, Customer
from billing.services import (
    apply_subscription_renewal,
    compute_partial_recharge_amount,
    customer_can_surf_via_hotspot,
    customer_can_surf_via_pppoe,
    customer_needs_nas_provision,
    customer_package_is_paused,
    customer_pppoe_secret_disabled,
    customer_receives_internet,
    customer_subscription_expired,
    generate_account_number_from_phone,
    organization_uses_dynamic_access,
    package_remaining_seconds,
    partial_recharge_window,
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

    def test_customers_near_access_deadline_includes_just_expired_hourly(self):
        from billing.services import customers_near_access_deadline

        now = timezone.localtime()
        hourly = BillingPlan.objects.create(
            organization=self.org,
            name="Hourly Near",
            price="50.00",
            duration=BillingPlan.Duration.HOURLY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )
        due = self._pppoe(
            account_number="PPP-NEAR",
            pppoe_username="near1",
            phone="254700000088",
            plan=hourly,
            package_start=now - timedelta(hours=1, minutes=1),
            package_end=now - timedelta(seconds=20),
        )
        far = self._pppoe(
            account_number="PPP-FAR",
            pppoe_username="far1",
            phone="254700000099",
            plan=hourly,
            package_start=now - timedelta(minutes=5),
            package_end=now + timedelta(hours=2),
        )
        near_ids = {
            c.pk
            for c in customers_near_access_deadline(
                past_seconds=90, future_seconds=45, now=now
            )
        }
        self.assertIn(due.pk, near_ids)
        self.assertNotIn(far.pk, near_ids)

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
            "provision": {
                "ok": True,
                "profile": "ispcentric-pppoe-5u-10d",
                "rate_limit": "5M/10M",
                "disabled": False,
            },
            "portal": {"ok": True},
        }
        result = evaluate_nas_policy(self.pppoe_active, sync)
        self.assertTrue(result["policy_match"])
        self.assertEqual(
            result["details"]["expected_profile"], "ispcentric-pppoe-5u-10d"
        )

    def test_evaluate_pppoe_active_wrong_speed_fails(self):
        from billing.access_verification import evaluate_nas_policy

        sync = {
            "ok": True,
            "allowed": True,
            "provision": {
                "ok": True,
                "profile": "ispcentric-pppoe",
                "disabled": False,
            },
            "portal": {"ok": True},
        }
        result = evaluate_nas_policy(self.pppoe_active, sync)
        self.assertFalse(result["policy_match"])
        self.assertEqual(result["details"].get("surf_gap"), "wrong_speed_profile")

    def test_evaluate_pppoe_active_cpe_offline_nas_ready(self):
        from billing.access_verification import evaluate_nas_policy

        sync = {
            "ok": False,
            "allowed": True,
            "cpe_renew_clear_pending": True,
            "provision": {
                "ok": True,
                "profile": "ispcentric-pppoe-5u-10d",
                "rate_limit": "5M/10M",
                "disabled": False,
            },
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
            "provision": {
                "ok": True,
                "profile": "ispcentric-hs-5u-10d",
                "rate_limit": "5M/10M",
                "max_devices": 2,
                "allowed_count": 1,
                "over_cap_count": 0,
            },
        }
        result = evaluate_nas_policy(self.hotspot_paid, sync)
        self.assertTrue(result["policy_match"])
        self.assertFalse(result["details"]["hotspot_disabled"])
        self.assertTrue(result["details"]["hotspot_limit_uptime"].endswith("s"))

    def test_evaluate_hotspot_device_cap_exceeded_fails(self):
        from billing.access_verification import evaluate_nas_policy

        self.plan.max_devices = 2
        self.plan.save(update_fields=["max_devices"])
        self.hotspot_paid.plan = self.plan
        self.hotspot_paid.save(update_fields=["plan"])

        sync = {
            "ok": True,
            "allowed": True,
            "provision": {
                "ok": True,
                "profile": "ispcentric-hs-5u-10d",
                "rate_limit": "5M/10M",
                "max_devices": 2,
                "allowed_count": 5,
                "over_cap_count": 0,
            },
        }
        result = evaluate_nas_policy(self.hotspot_paid, sync)
        self.assertFalse(result["policy_match"])
        self.assertEqual(result["details"].get("surf_gap"), "device_cap_exceeded")

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
                "provision": {
                    "ok": True,
                    "profile": "ispcentric-pppoe-5u-10d",
                    "rate_limit": "5M/10M",
                    "disabled": False,
                },
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
        self.assertEqual(len(pppoe_only), 3)

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

    def test_pause_sync_moves_secret_to_blocked_profile(self):
        from core.mikrotik_connect import (
            PPPOE_BLOCKED_PROFILE_NAME,
            sync_customer_subscription_access,
        )

        now = timezone.localtime()
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Pause Sync",
            phone="254700000033",
            account_number="PPP-PAUSE-SYNC",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="pausesync",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            plan=self.plan,
            package_start=now - timedelta(minutes=5),
            package_end=now + timedelta(hours=1),
        )
        pause_customer_package(customer, now=now)
        customer.refresh_from_db()

        order = []

        def portal_side_effect(customer, *, enabled, portal_url="", timeout=8.0):
            order.append(("portal", enabled))
            return {"ok": True, "enabled": enabled, "notes": ["paused portal"]}

        def provision_side_effect(customer, **kwargs):
            order.append(("provision", kwargs.get("force_disabled")))
            return {"ok": True, "profile": PPPOE_BLOCKED_PROFILE_NAME}

        with (
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
                side_effect=portal_side_effect,
            ),
            patch(
                "core.mikrotik_connect.provision_customer_pppoe",
                side_effect=provision_side_effect,
            ),
            patch(
                "core.mikrotik_connect._pppoe_pay_portal_url",
                return_value="http://billing.example/pppoe/998877/pay/?t=x",
            ),
        ):
            result = sync_customer_subscription_access(customer, provision=True)

        self.assertFalse(result["allowed"])
        self.assertTrue(result["ok"])
        self.assertEqual(order[0], ("portal", True))
        self.assertEqual(order[1], ("provision", False))
        self.assertEqual(result["provision"]["profile"], PPPOE_BLOCKED_PROFILE_NAME)

        from billing.services import customer_portal_access_context

        portal = customer_portal_access_context(customer)
        self.assertTrue(portal["subscription_paused"])
        self.assertFalse(portal["show_renew_payment"])
        self.assertEqual(portal["access_banner_title"], "Internet paused")

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

    def test_multiple_hotspot_devices_without_stored_phone_do_not_collide(self):
        Customer.objects.create(
            organization=self.org,
            full_name="Device A",
            phone="",
            account_number="HOT-A",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:01",
        )
        second = Customer.objects.create(
            organization=self.org,
            full_name="Device B",
            phone="",
            account_number="HOT-B",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:02",
        )
        self.assertEqual(second.phone_normalized, "")


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


class VoucherCodeFormatTests(SimpleTestCase):
    def test_new_codes_are_four_digits_and_a_letter(self):
        from billing.vouchers import (
            _generate_code,
            format_voucher_code,
            normalize_voucher_code,
        )

        code = _generate_code()
        self.assertRegex(code, r"^[0-9]{4}[A-HJ-NP-Z]$")
        self.assertEqual(format_voucher_code(code), f"{code[:4]}-{code[4]}")
        self.assertEqual(normalize_voucher_code("4827-k"), "4827K")
        self.assertEqual(format_voucher_code("4827K"), "4827-K")
        self.assertEqual(format_voucher_code("AB12CD34"), "AB12-CD34")


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
    """Payment → valid voucher → redeem/invalid (used) → cannot reuse."""

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
        from billing.vouchers import format_voucher_code

        self.assertRegex(voucher.code, r"^[0-9]{4}[A-HJ-NP-Z]$")
        self.assertEqual(result["voucher_code"], format_voucher_code(voucher.code))

    def test_redeem_accepts_short_dashed_code(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk
        from billing.vouchers import format_voucher_code, redeem_access_voucher

        stk = self._stk()
        fulfill_successful_stk(
            stk, result_code=0, result_desc="ok", mpesa_receipt="RCVSHORT1"
        )
        voucher = AccessVoucher.objects.get(stk_request=stk)
        dashed = format_voucher_code(voucher.code)
        self.assertRegex(dashed, r"^[0-9]{4}-[A-HJ-NP-Z]$")

        with patch(
            "core.mikrotik_connect.sync_customer_subscription_access",
            return_value={"ok": True, "allowed": True},
        ):
            result = redeem_access_voucher(
                organization=self.org,
                code=dashed,
                customer=self.customer,
                mac=self.customer.hotspot_mac,
            )

        voucher.refresh_from_db()
        self.assertTrue(result["ok"])
        self.assertEqual(voucher.status, AccessVoucher.Status.INVALID)

    def test_redeem_activates_once_and_marks_invalid(self):
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
        self.assertEqual(first["voucher_status"], AccessVoucher.Status.INVALID)
        self.assertTrue(first["authorized"])
        self.assertIsNotNone(self.customer.package_end)
        self.assertTrue(stk.subscription_applied)
        self.assertEqual(voucher.status, AccessVoucher.Status.INVALID)
        self.assertIsNotNone(voucher.invalidated_at)
        self.assertFalse(second["ok"])
        self.assertEqual(second.get("voucher_status"), AccessVoucher.Status.INVALID)

    def test_surfing_after_redeem_keeps_voucher_invalid(self):
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
        self.assertEqual(voucher.status, AccessVoucher.Status.INVALID)

        changed = invalidate_vouchers_for_surfing_customers([self.customer])
        voucher.refresh_from_db()
        self.assertEqual(changed, 0)
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
        self.assertContains(response, self.org.name)
        self.assertContains(response, 'name="phone"')
        self.assertContains(response, 'name="plan_id"')
        self.assertContains(response, "Have a voucher?")
        self.assertContains(response, 'name="voucher_code"')
        self.assertContains(response, "Activate voucher")
        self.assertContains(response, 'data-voucher-box')
        self.assertNotContains(response, 'data-voucher-box hidden')

    def test_pay_page_shows_package_image(self):
        from django.core.files.uploadedfile import SimpleUploadedFile

        png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
            b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
            b"\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x00\x03\x00\x01"
            b"\x00\x05\xfe\xd4\xef\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        self.plan.image.save(
            "daily.png",
            SimpleUploadedFile("daily.png", png, content_type="image/png"),
            save=True,
        )
        self.plan.refresh_from_db()

        response = self.client.get(f"/hotspot/{self.org.join_code}/pay/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.plan.image.url)
        self.assertContains(response, 'class="plan-image"')

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

    def test_client_detail_shows_available_voucher(self):
        from billing.stk import fulfill_successful_stk
        from billing.vouchers import format_voucher_code

        self.client.force_login(self.owner)
        stk = self._stk()
        fulfill_successful_stk(
            stk, result_code=0, result_desc="ok", mpesa_receipt="DETAIL1"
        )
        from billing.models import AccessVoucher

        voucher = AccessVoucher.objects.get(stk_request=stk)
        display = format_voucher_code(voucher.code)

        response = self.client.get(f"/app/clients/{self.customer.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Available vouchers")
        self.assertContains(response, display)
        self.assertContains(response, "1 unused voucher")
        self.assertEqual(response.context["valid_voucher_count"], 1)
        self.assertEqual(len(response.context["available_vouchers"]), 1)

    def test_refresh_stk_status_auto_applies_package(self):
        from billing.stk import fulfill_successful_stk, refresh_stk_status

        stk = self._stk()
        fulfill_successful_stk(
            stk, result_code=0, result_desc="ok", mpesa_receipt="AUTO1"
        )
        with patch(
            "core.subscription_sync.enqueue_customer_subscription_sync",
            return_value={"ok": True, "allowed": True},
        ) as enqueue:
            result = refresh_stk_status(stk, wait_for_nas=True)

        stk.refresh_from_db()
        self.customer.refresh_from_db()
        self.assertTrue(result["success"])
        self.assertTrue(result["subscription_applied"])
        self.assertTrue(result["authorized"])
        self.assertFalse(result.get("needs_voucher"))
        self.assertIsNotNone(self.customer.package_end)
        enqueue.assert_called()
        self.assertTrue(enqueue.call_args.kwargs.get("wait_first"))
        self.assertTrue(enqueue.call_args.kwargs.get("quick"))
        from billing.models import AccessVoucher

        voucher = AccessVoucher.objects.get(stk_request=stk)
        self.assertEqual(voucher.status, AccessVoucher.Status.INVALID)
        self.assertTrue(result.get("surfing"))

    def test_auto_connect_keeps_voucher_when_nas_fails(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk, refresh_stk_status

        stk = self._stk()
        fulfill_successful_stk(
            stk, result_code=0, result_desc="ok", mpesa_receipt="AUTO2"
        )
        with patch(
            "core.subscription_sync.enqueue_customer_subscription_sync",
            return_value={"ok": False, "allowed": False, "offline": True},
        ):
            result = refresh_stk_status(stk, wait_for_nas=True)

        stk.refresh_from_db()
        voucher = AccessVoucher.objects.get(stk_request=stk)
        self.assertTrue(result["success"])
        self.assertTrue(result["subscription_applied"])
        self.assertFalse(result.get("authorized"))
        self.assertFalse(result.get("surfing"))
        self.assertFalse(result.get("needs_voucher"))
        self.assertTrue(result.get("voucher_fallback"))
        self.assertTrue(result.get("voucher_redeemable"))
        self.assertEqual(voucher.status, AccessVoucher.Status.VALID)

    def test_auto_connect_treats_pending_cpe_as_authorized(self):
        from billing.stk import fulfill_successful_stk, refresh_stk_status

        stk = self._stk()
        fulfill_successful_stk(
            stk, result_code=0, result_desc="ok", mpesa_receipt="AUTO3"
        )
        with patch(
            "core.subscription_sync.enqueue_customer_subscription_sync",
            return_value={
                "ok": False,
                "allowed": True,
                "provision": {"ok": True},
                "cpe_renew_clear_pending": True,
            },
        ):
            result = refresh_stk_status(stk, wait_for_nas=True)

        self.assertTrue(result["authorized"])
        self.assertTrue(result["surfing"])
        self.assertFalse(result.get("needs_voucher"))

    def test_status_poll_loop_retries_until_nas_ready(self):
        from billing.stk import fulfill_successful_stk, refresh_stk_status

        stk = self._stk()
        fulfill_successful_stk(
            stk, result_code=0, result_desc="ok", mpesa_receipt="LOOP1"
        )
        calls = {"n": 0}

        def fake_enqueue(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] < 3:
                return {"ok": False, "allowed": False, "provision": {"ok": False}}
            return {"ok": True, "allowed": True, "provision": {"ok": True}}

        with patch(
            "core.subscription_sync.enqueue_customer_subscription_sync",
            side_effect=fake_enqueue,
        ):
            result = {"authorized": False}
            for _ in range(5):
                result = refresh_stk_status(stk, wait_for_nas=True)
                if result.get("authorized") or result.get("surfing"):
                    break

        self.assertTrue(result.get("authorized"))
        self.assertGreaterEqual(calls["n"], 3)
        self.assertLessEqual(calls["n"], 5)

    def test_callback_queues_background_activate(self):
        from billing.stk import process_stk_callback_payload

        stk = self._stk()
        stk.checkout_request_id = "ws_CO_TEST"
        stk.merchant_request_id = "ws_MR_TEST"
        stk.save(update_fields=["checkout_request_id", "merchant_request_id"])
        payload = {
            "Body": {
                "stkCallback": {
                    "MerchantRequestID": "ws_MR_TEST",
                    "CheckoutRequestID": "ws_CO_TEST",
                    "ResultCode": 0,
                    "ResultDesc": "The service request is processed successfully.",
                    "CallbackMetadata": {
                        "Item": [
                            {"Name": "Amount", "Value": 50},
                            {"Name": "MpesaReceiptNumber", "Value": "CBK1"},
                            {"Name": "PhoneNumber", "Value": 254700000777},
                        ]
                    },
                }
            }
        }
        with patch(
            "billing.stk._confirm_stk_success_with_daraja",
            return_value={
                "success": True,
                "pending": False,
                "error": "",
                "result_desc": "Confirmed",
                "data": {},
            },
        ), patch(
            "billing.vouchers.activate_paid_subscription_stk",
            return_value={"ok": True, "queued": True},
        ) as activate:
            result = process_stk_callback_payload(payload)

        self.assertTrue(result["ok"])
        activate.assert_called_once()
        self.assertTrue(activate.call_args.kwargs.get("background"))

    def test_callback_rejects_amount_mismatch(self):
        from billing.stk import process_stk_callback_payload

        stk = self._stk()
        stk.checkout_request_id = "ws_CO_AMT"
        stk.save(update_fields=["checkout_request_id"])
        payload = {
            "Body": {
                "stkCallback": {
                    "CheckoutRequestID": "ws_CO_AMT",
                    "ResultCode": 0,
                    "ResultDesc": "ok",
                    "CallbackMetadata": {
                        "Item": [
                            {"Name": "Amount", "Value": 999},
                            {"Name": "MpesaReceiptNumber", "Value": "FAKE1"},
                        ]
                    },
                }
            }
        }
        with patch(
            "billing.stk._confirm_stk_success_with_daraja",
            return_value={"success": True, "pending": False, "error": "", "data": {}},
        ) as confirm:
            result = process_stk_callback_payload(payload)

        self.assertFalse(result["ok"])
        self.assertIn("does not match", result.get("error") or "")
        confirm.assert_not_called()
        stk.refresh_from_db()
        self.assertEqual(stk.status, stk.Status.PENDING)

    def test_callback_defers_when_daraja_confirm_pending(self):
        from billing.stk import process_stk_callback_payload

        stk = self._stk()
        stk.checkout_request_id = "ws_CO_PEND"
        stk.save(update_fields=["checkout_request_id"])
        payload = {
            "Body": {
                "stkCallback": {
                    "CheckoutRequestID": "ws_CO_PEND",
                    "ResultCode": 0,
                    "ResultDesc": "ok",
                    "CallbackMetadata": {
                        "Item": [
                            {"Name": "Amount", "Value": 50},
                            {"Name": "MpesaReceiptNumber", "Value": "PEND1"},
                        ]
                    },
                }
            }
        }
        with patch(
            "billing.stk._confirm_stk_success_with_daraja",
            return_value={
                "success": False,
                "pending": True,
                "error": "waiting",
                "result_desc": "",
                "data": {},
            },
        ), patch(
            "billing.vouchers.activate_paid_subscription_stk",
        ) as activate:
            result = process_stk_callback_payload(payload)

        self.assertTrue(result.get("pending_verification"))
        activate.assert_not_called()
        stk.refresh_from_db()
        self.assertEqual(stk.status, stk.Status.PENDING)
        self.assertEqual(stk.mpesa_receipt, "PEND1")


class HotspotMultiDeviceVoucherTests(TestCase):
    """A 3-device Hotspot package issues 3 one-time vouchers."""

    def setUp(self):
        self.owner = User.objects.create_user("owner-hs-vouchers", password="x")
        self.org = Organization.objects.create(
            name="Family HS ISP",
            owner=self.owner,
            join_code="667788",
            hotspot_enabled=True,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Family 3",
            price="150.00",
            duration=BillingPlan.Duration.DAILY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            max_devices=3,
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Family Phone",
            phone="254700000888",
            account_number="HOT-FAM-V",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:88",
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
            "amount": Decimal("150.00"),
            "phone": "254700000888",
            "account_reference": self.customer.account_number,
            "checkout_request_id": "ws_CO_FAM_VOUCHER",
            "status": StkPushRequest.Status.PENDING,
            "purpose": StkPushRequest.Purpose.SUBSCRIPTION,
        }
        defaults.update(kwargs)
        return StkPushRequest.objects.create(**defaults)

    def test_plan_label_shows_device_vouchers(self):
        self.assertEqual(self.plan.max_devices_label, "3 devices · 3 vouchers")

    def test_payment_creates_one_voucher_per_device(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk

        stk = self._stk()
        result = fulfill_successful_stk(
            stk, result_code=0, result_desc="ok", mpesa_receipt="FAM1"
        )
        codes = result.get("voucher_codes") or []
        self.assertEqual(result["voucher_count"], 3)
        self.assertEqual(result["voucher_valid_count"], 3)
        self.assertEqual(len(codes), 3)
        self.assertEqual(
            AccessVoucher.objects.filter(stk_request=stk, status=AccessVoucher.Status.VALID).count(),
            3,
        )
        self.assertTrue(result["needs_voucher"])

    def test_client_detail_lists_unused_multi_device_vouchers(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk
        from billing.vouchers import format_voucher_code

        self.client.force_login(self.owner)
        stk = self._stk()
        result = fulfill_successful_stk(
            stk, result_code=0, result_desc="ok", mpesa_receipt="FAMDETAIL"
        )
        codes = [format_voucher_code(c) for c in (result.get("voucher_codes") or [])]
        used = AccessVoucher.objects.filter(stk_request=stk).first()
        used.status = AccessVoucher.Status.INVALID
        used.save(update_fields=["status"])

        response = self.client.get(f"/app/clients/{self.customer.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Available vouchers")
        self.assertContains(response, "3 devices")
        self.assertContains(response, "2 unused")
        self.assertContains(response, "1 used")
        self.assertEqual(response.context["valid_voucher_count"], 2)
        self.assertEqual(response.context["voucher_device_cap"], 3)
        for code in codes:
            if format_voucher_code(used.code) == code:
                self.assertNotContains(response, code)
            else:
                self.assertContains(response, code)

    def test_fulfill_is_idempotent_and_does_not_mint_extras(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk

        stk = self._stk()
        first = fulfill_successful_stk(stk, result_code=0, result_desc="ok", mpesa_receipt="FAM2")
        second = fulfill_successful_stk(stk, result_code=0, result_desc="ok", mpesa_receipt="FAM2")
        self.assertEqual(AccessVoucher.objects.filter(stk_request=stk).count(), 3)
        self.assertEqual(sorted(first["voucher_codes"]), sorted(second["voucher_codes"]))

    def test_redeem_one_device_leaves_sibling_vouchers_valid(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk
        from billing.vouchers import redeem_access_voucher

        stk = self._stk()
        fulfill_successful_stk(stk, result_code=0, result_desc="ok", mpesa_receipt="FAM3")
        vouchers = list(AccessVoucher.objects.filter(stk_request=stk).order_by("id"))
        first, second, third = vouchers

        with patch(
            "core.mikrotik_connect.sync_customer_subscription_access",
            return_value={"ok": True, "allowed": True},
        ):
            used = redeem_access_voucher(
                organization=self.org,
                code=first.code,
                customer=self.customer,
                mac="AA:BB:CC:DD:EE:88",
            )
            blocked = redeem_access_voucher(
                organization=self.org,
                code=first.code,
                customer=self.customer,
            )
            extra = redeem_access_voucher(
                organization=self.org,
                code=second.code,
                mac="AA:BB:CC:DD:EE:89",
            )

        first.refresh_from_db()
        second.refresh_from_db()
        third.refresh_from_db()
        self.assertTrue(used["ok"])
        self.assertEqual(first.status, AccessVoucher.Status.INVALID)
        self.assertFalse(blocked["ok"])
        self.assertTrue(extra["ok"])
        self.assertEqual(second.status, AccessVoucher.Status.INVALID)
        self.assertEqual(third.status, AccessVoucher.Status.VALID)
        self.assertEqual(second.redeemed_mac, "AA:BB:CC:DD:EE:89")
        from billing.vouchers import format_voucher_code

        remaining = extra.get("voucher_codes") or []
        self.assertEqual(extra["voucher_valid_count"], 1)
        self.assertEqual(remaining, [format_voucher_code(third.code)])
        self.assertNotIn(format_voucher_code(first.code), remaining)
        self.assertNotIn(format_voucher_code(second.code), remaining)

    def test_pay_payload_lists_only_valid_vouchers(self):
        from billing.models import AccessVoucher, StkPushRequest
        from billing.vouchers import (
            attach_voucher_to_stk_status,
            create_vouchers_for_stk,
            format_voucher_code,
        )

        stk = self._stk()
        stk.status = StkPushRequest.Status.SUCCESS
        stk.save(update_fields=["status"])
        vouchers = create_vouchers_for_stk(stk)
        used = vouchers[0]
        used.status = AccessVoucher.Status.INVALID
        used.save(update_fields=["status"])

        payload = attach_voucher_to_stk_status({"ok": True}, stk)
        used_code = format_voucher_code(used.code)
        valid_codes = [
            format_voucher_code(row.code)
            for row in vouchers[1:]
        ]
        self.assertEqual(payload["voucher_valid_count"], 2)
        self.assertEqual(sorted(payload["voucher_codes"]), sorted(valid_codes))
        self.assertNotIn(used_code, payload["voucher_codes"])
        self.assertIn(payload["voucher_code"], valid_codes)

    def test_surfing_does_not_burn_unused_device_vouchers(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk
        from billing.vouchers import invalidate_vouchers_for_surfing_customers

        stk = self._stk()
        fulfill_successful_stk(stk, result_code=0, result_desc="ok", mpesa_receipt="FAM4")
        changed = invalidate_vouchers_for_surfing_customers([self.customer])
        self.assertEqual(changed, 1)
        statuses = list(
            AccessVoucher.objects.filter(stk_request=stk)
            .order_by("id")
            .values_list("status", flat=True)
        )
        self.assertEqual(statuses.count(AccessVoucher.Status.INVALID), 1)
        self.assertEqual(statuses.count(AccessVoucher.Status.VALID), 2)

    def test_expired_package_burns_unused_device_vouchers(self):
        from billing.models import AccessVoucher
        from billing.stk import fulfill_successful_stk
        from billing.vouchers import invalidate_unused_vouchers_for_expired_customers

        stk = self._stk()
        fulfill_successful_stk(stk, result_code=0, result_desc="ok", mpesa_receipt="FAM5")
        self.customer.package_start = timezone.now() - timedelta(days=2)
        self.customer.package_end = timezone.now() - timedelta(days=1)
        self.customer.save(update_fields=["package_start", "package_end"])

        burned = invalidate_unused_vouchers_for_expired_customers([self.customer])
        self.assertEqual(burned, 3)
        self.assertEqual(
            AccessVoucher.objects.filter(
                stk_request=stk, status=AccessVoucher.Status.VALID
            ).count(),
            0,
        )
        self.assertEqual(
            AccessVoucher.objects.filter(
                stk_request=stk, status=AccessVoucher.Status.INVALID
            ).count(),
            3,
        )

    def test_pppoe_payment_still_issues_one_voucher(self):
        from billing.models import AccessVoucher, BillingPlan, Customer, StkPushRequest
        from billing.stk import fulfill_successful_stk

        plan = BillingPlan.objects.create(
            organization=self.org,
            name="Home PPP",
            price="1000.00",
            duration=BillingPlan.Duration.MONTHLY,
            download_speed_mbps=20,
            upload_speed_mbps=10,
            service_type=BillingPlan.ServiceType.PPPOE,
            max_devices=4,
        )
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Home PPP",
            phone="254700000889",
            account_number="PPP-FAM-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="homeppp",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            plan=plan,
        )
        stk = StkPushRequest.objects.create(
            organization=self.org,
            customer=customer,
            plan=plan,
            amount=plan.price,
            phone=customer.phone,
            account_reference=customer.account_number,
            checkout_request_id="ws_CO_PPP_VOUCHER",
            purpose=StkPushRequest.Purpose.SUBSCRIPTION,
        )
        result = fulfill_successful_stk(stk, result_code=0, result_desc="ok", mpesa_receipt="PPP1")
        self.assertEqual(result["voucher_count"], 1)
        self.assertEqual(AccessVoucher.objects.filter(stk_request=stk).count(), 1)


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


class PartialRechargeTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-partial", password="x")
        self.org = Organization.objects.create(
            name="Partial ISP",
            owner=self.owner,
            join_code="333444",
        )
        self.hourly_plan = BillingPlan.objects.create(
            organization=self.org,
            name="Per hour",
            price="1.00",
            duration=BillingPlan.Duration.HOURLY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )
        self.daily_plan = BillingPlan.objects.create(
            organization=self.org,
            name="Daily",
            price="100.00",
            duration=BillingPlan.Duration.DAILY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Partial Client",
            phone="254700000060",
            account_number="PART-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="partial1",
            pppoe_password="secret",
            status=Customer.Status.ALLOCATED_OPEN,
            plan=self.hourly_plan,
        )

    def test_partial_window_single_day_hourly(self):
        day = timezone.localdate()
        start, end = partial_recharge_window(day, day, self.hourly_plan)
        self.assertEqual(timezone.localtime(start).date(), day)
        self.assertEqual(timezone.localtime(end).date(), day + timedelta(days=1))

    def test_partial_amount_prorates_daily_plan(self):
        day = timezone.localdate()
        start, end = partial_recharge_window(day, day + timedelta(days=2), self.daily_plan)
        amount = compute_partial_recharge_amount(self.daily_plan, start, end)
        self.assertEqual(amount, Decimal("300.00"))

    def test_partial_cash_recharge_sets_window_and_activates(self):
        from billing.models import Payment

        day = timezone.localdate()
        start, end = partial_recharge_window(day, day, self.hourly_plan)
        amount = compute_partial_recharge_amount(self.hourly_plan, start, end)
        result = recharge_customer_cash(
            customer=self.customer,
            organization=self.org,
            plan=self.hourly_plan,
            amount=amount,
            reference="PART-1",
            recorded_by=self.owner,
            period_start=start,
            period_end=end,
        )
        self.customer.refresh_from_db()
        self.assertTrue(result["partial"])
        self.assertEqual(self.customer.status, Customer.Status.ACTIVE)
        self.assertEqual(self.customer.package_start, start)
        self.assertEqual(self.customer.package_end, end)
        self.assertEqual(result["payment"].method, Payment.Method.CASH)
        self.assertEqual(result["payment"].amount, amount)


class CustomerCashRechargeFormTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-form", password="x")
        self.org = Organization.objects.create(
            name="Form ISP",
            owner=self.owner,
            join_code="555666",
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Daily",
            price="100.00",
            duration=BillingPlan.Duration.DAILY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Form Client",
            phone="254700000070",
            account_number="FORM-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="form1",
            pppoe_password="secret",
            plan=self.plan,
        )

    def test_partial_form_calculates_amount(self):
        from billing.forms import CustomerCashRechargeForm

        day = timezone.localdate()
        form = CustomerCashRechargeForm(
            {
                "recharge_mode": CustomerCashRechargeForm.MODE_PARTIAL,
                "plan": str(self.plan.pk),
                "period_from": day.isoformat(),
                "period_to": (day + timedelta(days=1)).isoformat(),
                "amount": "999.00",
                "reference": "",
            },
            organization=self.org,
            customer=self.customer,
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["amount"], Decimal("200.00"))
        self.assertIsNotNone(form.cleaned_data["period_start"])
        self.assertIsNotNone(form.cleaned_data["period_end"])


class CustomerNeedsNasProvisionTests(SimpleTestCase):
    def test_hotspot_mac_is_enough_without_pppoe(self):
        class Fake:
            hotspot_mac = "AA:BB:CC:DD:EE:FF"
            pppoe_username = ""
            router_id = None

        self.assertTrue(customer_needs_nas_provision(Fake()))

    def test_pppoe_requires_username_and_router(self):
        class Fake:
            hotspot_mac = ""
            pppoe_username = "user1"
            router_id = 18

        self.assertTrue(customer_needs_nas_provision(Fake()))

        class NoRouter:
            hotspot_mac = ""
            pppoe_username = "user1"
            router_id = None

        self.assertFalse(customer_needs_nas_provision(NoRouter()))

    def test_empty_identity_does_not_provision(self):
        class Fake:
            hotspot_mac = ""
            pppoe_username = ""
            router_id = 18

        self.assertFalse(customer_needs_nas_provision(Fake()))


class SubscriptionRenewUrlTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            name="Renew Org",
            owner=User.objects.create_user("owner-renew-url", password="x"),
            join_code="616161",
            hotspot_enabled=True,
            pppoe_compulsory=True,
        )
        self.plan_hs = BillingPlan.objects.create(
            organization=self.org,
            name="HS Day",
            price=100,
            duration=BillingPlan.Duration.DAILY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            is_active=True,
        )
        self.plan_pp = BillingPlan.objects.create(
            organization=self.org,
            name="PP Month",
            price=2000,
            duration=BillingPlan.Duration.MONTHLY,
            service_type=BillingPlan.ServiceType.PPPOE,
            is_active=True,
        )

    def test_billing_renew_sends_hotspot_customer_to_hotspot_pay(self):
        from billing.services import make_renew_token

        customer = Customer.objects.create(
            organization=self.org,
            full_name="Hot Client",
            phone="254700061616",
            account_number="HS-6161",
            service_type=Customer.ServiceType.HOTSPOT,
            plan=self.plan_hs,
            status=Customer.Status.ACTIVE,
        )
        token = make_renew_token(customer)
        response = self.client.get(f"/billing/renew/{token}/")
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/hotspot/{self.org.join_code}/pay/", response.url)
        self.assertNotIn("/pppoe/", response.url)

    def test_billing_renew_sends_pppoe_customer_to_pppoe_pay(self):
        from billing.services import make_renew_token

        customer = Customer.objects.create(
            organization=self.org,
            full_name="PPP Client",
            phone="254700061617",
            account_number="PP-6161",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="pp6161",
            plan=self.plan_pp,
            status=Customer.Status.ACTIVE,
        )
        token = make_renew_token(customer)
        response = self.client.get(f"/billing/renew/{token}/")
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/pppoe/{self.org.join_code}/pay/", response.url)

    def test_billing_renew_hotspot_html_matches_service_type_branch(self):
        from billing.services import make_renew_token

        hotspot = Customer.objects.create(
            organization=self.org,
            full_name="Hot HTML",
            phone="254700061618",
            account_number="HS-6162",
            service_type=Customer.ServiceType.HOTSPOT,
            plan=self.plan_hs,
            status=Customer.Status.ACTIVE,
        )
        response = self.client.get(
            f"/billing/renew/{make_renew_token(hotspot)}/hotspot.html"
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/hotspot/{self.org.join_code}/pay/", response.url)