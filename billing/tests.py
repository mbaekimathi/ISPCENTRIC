from datetime import timedelta

from django.test import SimpleTestCase
from django.utils import timezone

from billing.models import BillingPlan
from billing.services import apply_subscription_renewal


class SubscriptionRenewalTests(SimpleTestCase):
    def test_active_renewal_extends_end_without_postponing_access(self):
        now = timezone.localtime()

        class Customer:
            plan = None
            package_start = now - timedelta(minutes=10)
            package_end = now + timedelta(minutes=50)

            def save(self, **kwargs):
                self.saved_fields = kwargs["update_fields"]

        customer = Customer()
        plan = BillingPlan(duration=BillingPlan.Duration.HOURLY)
        original_start = customer.package_start
        original_end = customer.package_end

        apply_subscription_renewal(customer, plan=plan)

        self.assertEqual(customer.package_start, original_start)
        self.assertEqual(customer.package_end, original_end + timedelta(hours=1))
        self.assertEqual(customer.saved_fields, ["package_start", "package_end"])
