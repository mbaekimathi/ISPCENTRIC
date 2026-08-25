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
