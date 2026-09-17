"""
Performance smoke tests for hot owner-workspace pages.

These assert that critical pages stay under a query budget and respond quickly
with a modest dataset, catching regressions that would break under load.
"""

from __future__ import annotations

import time
from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import Client, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from accounts.models import Organization
from billing.models import BillingPlan, Customer, Invoice, Payment
from billing.services import customers_needing_renewal_attention
from core.models import MikroTikRouter

User = get_user_model()

# Soft budgets: fail when a page clearly regresses into unbounded work.
_MAX_QUERIES = {
    "workspace": 90,
    "clients": 40,
    "billing": 55,
    "noc": 60,
}
_MAX_SECONDS = 3.0


@override_settings(
    DEBUG=False,
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "perf-smoke-default",
        },
        "jobs": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "perf-smoke-jobs",
        },
    },
)
class HotPathPerfSmokeTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="perf_owner",
            password="PerfSmokePass123!",
            email="perf@example.com",
        )
        cls.org = Organization.objects.create(
            name="Perf Smoke ISP",
            owner=cls.user,
            join_code="998877",
        )
        plan = BillingPlan.objects.create(
            organization=cls.org,
            name="Daily",
            price=Decimal("100.00"),
            duration=BillingPlan.Duration.DAILY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
            is_active=True,
        )
        router = MikroTikRouter.objects.create(
            organization=cls.org,
            name="Edge-1",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.9.9.1",
            username="admin",
            password="x",
            account_status=MikroTikRouter.AccountStatus.ACTIVE,
        )
        now = timezone.now()
        customers = []
        for i in range(120):
            customers.append(
                Customer(
                    organization=cls.org,
                    full_name=f"Client {i:03d}",
                    phone=f"0712{i:06d}",
                    account_number=f"PERF{i:04d}",
                    service_type=Customer.ServiceType.PPPOE,
                    status=Customer.Status.ACTIVE,
                    plan=plan,
                    router=router,
                    package_start=now - timedelta(hours=20),
                    package_end=now + timedelta(hours=4 if i % 5 else -2),
                    pppoe_username=f"u{i:04d}",
                )
            )
        Customer.objects.bulk_create(customers)
        created = list(Customer.objects.filter(organization=cls.org).order_by("id")[:40])
        today = timezone.localdate()
        for idx, customer in enumerate(created):
            invoice = Invoice.objects.create(
                organization=cls.org,
                customer=customer,
                invoice_number=f"INV-PERF-{idx:04d}",
                amount=Decimal("100.00"),
                status=Invoice.Status.PAID,
                due_date=today,
            )
            Payment.objects.create(
                organization=cls.org,
                invoice=invoice,
                amount=Decimal("100.00"),
                method=Payment.Method.CASH,
                received_at=now - timedelta(minutes=idx),
                reference=f"REF{idx:04d}",
            )

    def setUp(self):
        self.client = Client()
        self.client.force_login(self.user)

    def _get(self, path: str):
        started = time.perf_counter()
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(path)
        elapsed = time.perf_counter() - started
        return response, len(ctx), elapsed

    def test_workspace_stays_within_budget(self):
        response, queries, elapsed = self._get("/app/")
        self.assertIn(response.status_code, {200, 302})
        if response.status_code == 200:
            self.assertLessEqual(queries, _MAX_QUERIES["workspace"])
            self.assertLess(elapsed, _MAX_SECONDS)

    def test_clients_list_paginates_without_full_scan_budget_blowout(self):
        response, queries, elapsed = self._get("/app/clients/?tab=pppoe&sort=used")
        self.assertEqual(response.status_code, 200)
        page = response.context["clients_page"]
        self.assertLessEqual(len(page.object_list), 100)
        self.assertGreaterEqual(page.paginator.count, 100)
        self.assertLessEqual(queries, _MAX_QUERIES["clients"])
        self.assertLess(elapsed, _MAX_SECONDS)

    def test_billing_dashboard_caps_payment_rows(self):
        response, queries, elapsed = self._get("/billing/dashboard/")
        self.assertEqual(response.status_code, 200)
        payments = response.context["payments"]
        self.assertLessEqual(len(payments), 100)
        self.assertLessEqual(queries, _MAX_QUERIES["billing"])
        self.assertLess(elapsed, _MAX_SECONDS)

    def test_noc_page_responds(self):
        response, queries, elapsed = self._get("/app/noc/")
        self.assertIn(response.status_code, {200, 302})
        if response.status_code == 200:
            self.assertLessEqual(queries, _MAX_QUERIES["noc"])
            self.assertLess(elapsed, _MAX_SECONDS)

    def test_attention_helper_respects_limit(self):
        rows = customers_needing_renewal_attention(self.org, limit=25)
        self.assertLessEqual(len(rows), 25)
