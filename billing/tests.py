from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from accounts.models import Organization
from billing.models import BillingPlan, Customer
from billing.services import (
    apply_subscription_renewal,
    customer_pppoe_secret_disabled,
    customer_receives_internet,
    customer_subscription_expired,
    generate_account_number_from_phone,
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
        from billing.models import StkPushRequest
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
        end_after_first = self.customer.package_end
        self.assertTrue(first["ok"])
        self.assertFalse(first["already_applied"])
        self.assertIsNotNone(end_after_first)

        stk.refresh_from_db()
        self.assertEqual(stk.mpesa_receipt, "ABC123")
        self.assertEqual(stk.payment.reference, "ABC123")

        second = fulfill_successful_stk(stk, mpesa_receipt="ABC123")
        self.customer.refresh_from_db()
        self.assertTrue(second["ok"])
        self.assertTrue(second["already_applied"])
        self.assertEqual(self.customer.package_end, end_after_first)

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
        self.assertTrue(second["already_applied"])
        stk.refresh_from_db()
        self.assertEqual(stk.mpesa_receipt, "QWERTY99")
        payment = Payment.objects.get(pk=stk.payment_id)
        self.assertEqual(payment.reference, "QWERTY99")

    @patch("core.mikrotik_connect.sync_customer_subscription_access")
    def test_fulfill_applies_the_package_that_was_charged(self, sync_mock):
        from billing.models import StkPushRequest
        from billing.stk import fulfill_successful_stk

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
        self.assertGreater(
            self.customer.package_end - before,
            timedelta(hours=23),
        )
        stk.refresh_from_db()
        self.assertEqual(stk.payment.reference, "PLAN123")


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
