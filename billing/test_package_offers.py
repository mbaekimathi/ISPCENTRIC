"""Tests for buy-X-get-1-free package offers."""

from decimal import Decimal

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from accounts.models import Organization
from billing.models import BillingPlan, Customer, PackageOfferProgress
from billing.package_offers import (
    apply_paid_subscription_with_offer,
    attach_offer_progress_to_plans,
    payments_until_free,
)
from billing.services import compute_package_end


class PackageOfferTests(TestCase):
    def setUp(self):
        owner = User.objects.create_user("offer-owner-x", password="x")
        self.org = Organization.objects.create(
            name="Offer ISP",
            owner=owner,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="DAILY",
            price=Decimal("100.00"),
            duration=BillingPlan.Duration.DAILY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            offer_enabled=True,
            offer_pay_count=5,
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="TEST USER",
            phone="254712345678",
            service_type=Customer.ServiceType.HOTSPOT,
            plan=self.plan,
            status=Customer.Status.ACTIVE,
        )

    def test_payments_until_free(self):
        self.assertEqual(payments_until_free(self.plan, 0), 5)
        self.assertEqual(payments_until_free(self.plan, 4), 1)
        self.assertEqual(payments_until_free(self.plan, 5), 0)

    def test_buy_five_get_one_grants_bonus_on_fifth_payment(self):
        now = timezone.localtime()
        self.customer.package_start = now
        self.customer.package_end = compute_package_end(now, self.plan)
        self.customer.save()

        for index in range(4):
            result = apply_paid_subscription_with_offer(self.customer, plan=self.plan)
            self.assertFalse(result["free_session_granted"])
            self.assertEqual(result["offer_paid_count"], index + 1)

        result = apply_paid_subscription_with_offer(self.customer, plan=self.plan)
        self.assertTrue(result["free_session_granted"])
        self.assertEqual(result["offer_paid_count"], 0)
        progress = PackageOfferProgress.objects.get(customer=self.customer, plan=self.plan)
        self.assertEqual(progress.paid_count, 0)

    def test_attach_offer_progress_to_plans(self):
        PackageOfferProgress.objects.create(
            customer=self.customer,
            plan=self.plan,
            paid_count=3,
        )
        plans = attach_offer_progress_to_plans([self.plan], self.customer)
        self.assertEqual(plans[0].offer_payments_remaining, 2)
        self.assertEqual(plans[0].offer_label, "Buy 5 get 1 free")
        self.assertEqual(plans[0].offer_paid_count, 3)
        self.assertEqual(plans[0].offer_threshold, 5)
        self.assertEqual(plans[0].offer_percent, 60)
        self.assertEqual(len(plans[0].offer_slots), 5)
        self.assertEqual(sum(1 for slot in plans[0].offer_slots if slot["filled"]), 3)

    def test_started_offer_progress_for_customer(self):
        from billing.package_offers import started_offer_progress_for_customer

        other = BillingPlan.objects.create(
            organization=self.org,
            name="WEEKLY",
            price=Decimal("300.00"),
            duration=BillingPlan.Duration.WEEKLY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            offer_enabled=True,
            offer_pay_count=2,
        )
        PackageOfferProgress.objects.create(
            customer=self.customer,
            plan=self.plan,
            paid_count=3,
        )
        PackageOfferProgress.objects.create(
            customer=self.customer,
            plan=other,
            paid_count=0,
        )
        rows = started_offer_progress_for_customer(self.customer)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["plan_name"], "DAILY")
        self.assertEqual(rows[0]["paid_count"], 3)
        self.assertEqual(rows[0]["threshold"], 5)
        self.assertEqual(rows[0]["remaining"], 2)
        self.assertEqual(len(rows[0]["slots"]), 5)
        self.assertEqual(sum(1 for slot in rows[0]["slots"] if slot["filled"]), 3)
        self.assertFalse(rows[0]["nearly_free"])
        self.assertIn("2 more payments", rows[0]["nudge"])

        PackageOfferProgress.objects.filter(customer=self.customer, plan=self.plan).update(
            paid_count=4
        )
        rows = started_offer_progress_for_customer(self.customer)
        self.assertTrue(rows[0]["nearly_free"])
        self.assertIn("1 more payment", rows[0]["nudge"])

    def test_welcome_page_shows_started_offer_progress(self):
        self.org.join_code = "884422"
        self.org.save(update_fields=["join_code"])
        self.customer.hotspot_mac = "AA:BB:CC:DD:EE:01"
        self.customer.save(update_fields=["hotspot_mac"])
        PackageOfferProgress.objects.create(
            customer=self.customer,
            plan=self.plan,
            paid_count=2,
        )
        response = self.client.get(
            f"/hotspot/{self.org.join_code}/welcome/",
            {"mac": "AA:BB:CC:DD:EE:01"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Your offer progress")
        self.assertContains(response, "DAILY")
        self.assertContains(response, "Buy 5 get 1 free")
        self.assertContains(response, "2/5 paid")
        self.assertContains(response, "offer-slot is-filled")
        self.assertNotContains(response, "Buy again")

    def test_welcome_page_shows_dummy_offer_progress_without_mac(self):
        from billing.package_offers import dummy_offer_progress_for_org

        self.org.join_code = "884433"
        self.org.save(update_fields=["join_code"])
        rows = dummy_offer_progress_for_org(self.org)
        self.assertTrue(rows)
        self.assertTrue(rows[0]["is_dummy"])
        self.assertGreaterEqual(rows[0]["paid_count"], 1)
        response = self.client.get(f"/hotspot/{self.org.join_code}/welcome/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Demo offer progress")
        self.assertContains(response, "Your progress:")
        self.assertContains(response, "offer-slot is-filled")
        self.assertNotContains(response, "Your offer progress")
