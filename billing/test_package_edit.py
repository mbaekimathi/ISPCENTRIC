from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from accounts.models import Organization
from billing.models import BillingPlan, Customer, StkPushRequest


class PackageEditTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-pkg-edit", password="x")
        self.org = Organization.objects.create(
            name="Pkg Edit ISP",
            owner=self.owner,
            join_code="808080",
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Home 10",
            price=Decimal("1500.00"),
            download_speed_mbps=10,
            upload_speed_mbps=5,
            duration=BillingPlan.Duration.MONTHLY,
            is_active=True,
        )
        self.client.force_login(self.owner)

    def test_packages_page_shows_edit_controls(self):
        res = self.client.get(reverse("billing:packages"))
        self.assertEqual(res.status_code, 200)
        html = res.content.decode()
        self.assertIn("data-edit-package", html)
        self.assertIn("data-suspend-package", html)
        self.assertIn("data-delete-package", html)
        self.assertIn("billing-package-edit-modal", html)
        self.assertIn("billing-package-suspend-modal", html)
        self.assertIn("billing-package-delete-modal", html)
        self.assertIn(f'data-package-id="{self.plan.id}"', html)

    def test_edit_package_can_change_service_type(self):
        self.assertEqual(self.plan.service_type, BillingPlan.ServiceType.PPPOE)
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "edit_package",
                "package_id": str(self.plan.id),
                "name": "Home 10",
                "description": "",
                "price": "1500.00",
                "download_speed_mbps": "10",
                "upload_speed_mbps": "5",
                "duration": BillingPlan.Duration.MONTHLY,
                "service_type": BillingPlan.ServiceType.HOTSPOT,
                "is_active": "on",
            },
        )
        self.assertEqual(res.status_code, 302)
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.service_type, BillingPlan.ServiceType.HOTSPOT)

    def test_packages_edit_modal_exposes_service_type_choices(self):
        res = self.client.get(reverse("billing:packages"))
        self.assertEqual(res.status_code, 200)
        html = res.content.decode()
        self.assertIn('name="service_type"', html)
        self.assertIn('value="pppoe"', html)
        self.assertIn('value="hotspot"', html)
        self.assertIn("package-service-type-toggle", html)
        self.assertIn('data-package-service-type="pppoe"', html)

    def test_edit_package_updates_fields(self):
        with patch(
            "billing.views._schedule_reprovision_customers_for_plan_speeds",
        ) as schedule:
            res = self.client.post(
                reverse("billing:packages"),
                {
                    "action": "edit_package",
                    "package_id": str(self.plan.id),
                    "name": "Home 20",
                    "description": "Faster home plan",
                    "price": "2500.00",
                    "download_speed_mbps": "20",
                    "upload_speed_mbps": "10",
                    "duration": BillingPlan.Duration.MONTHLY,
                    "service_type": BillingPlan.ServiceType.PPPOE,
                    "is_active": "on",
                },
            )
        self.assertEqual(res.status_code, 302)
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.name, "HOME 20")
        self.assertEqual(self.plan.price, Decimal("2500.00"))
        self.assertEqual(self.plan.download_speed_mbps, 20)
        self.assertEqual(self.plan.upload_speed_mbps, 10)
        self.assertEqual(self.plan.speed_mbps, 20)
        self.assertTrue(self.plan.is_active)
        schedule.assert_called_once_with(self.plan.id)

    def test_edit_package_skips_reprovision_when_speeds_unchanged(self):
        with patch(
            "billing.views._schedule_reprovision_customers_for_plan_speeds",
        ) as schedule:
            res = self.client.post(
                reverse("billing:packages"),
                {
                    "action": "edit_package",
                    "package_id": str(self.plan.id),
                    "name": "Home Renamed",
                    "description": "",
                    "price": "1500.00",
                    "download_speed_mbps": "10",
                    "upload_speed_mbps": "5",
                    "duration": BillingPlan.Duration.MONTHLY,
                    "service_type": BillingPlan.ServiceType.PPPOE,
                    "is_active": "on",
                },
            )
        self.assertEqual(res.status_code, 302)
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.name, "HOME RENAMED")
        schedule.assert_not_called()

    def test_edit_package_can_deactivate(self):
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "edit_package",
                "package_id": str(self.plan.id),
                "name": self.plan.name,
                "description": "",
                "price": "1500.00",
                "download_speed_mbps": "10",
                "upload_speed_mbps": "5",
                "duration": BillingPlan.Duration.MONTHLY,
                "service_type": BillingPlan.ServiceType.PPPOE,
            },
        )
        self.assertEqual(res.status_code, 302)
        self.plan.refresh_from_db()
        self.assertFalse(self.plan.is_active)

    def test_edit_rejects_duplicate_name(self):
        BillingPlan.objects.create(
            organization=self.org,
            name="Business 50",
            price=Decimal("5000.00"),
            download_speed_mbps=50,
            upload_speed_mbps=20,
            duration=BillingPlan.Duration.MONTHLY,
        )
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "edit_package",
                "package_id": str(self.plan.id),
                "name": "Business 50",
                "description": "",
                "price": "1500.00",
                "download_speed_mbps": "10",
                "upload_speed_mbps": "5",
                "duration": BillingPlan.Duration.MONTHLY,
                "service_type": BillingPlan.ServiceType.PPPOE,
                "is_active": "on",
            },
        )
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "already exists for this service type")
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.name, "Home 10")

    def test_suspend_and_unsuspend_package(self):
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "suspend_package",
                "package_id": str(self.plan.id),
                "confirm": "on",
            },
        )
        self.assertEqual(res.status_code, 302)
        self.plan.refresh_from_db()
        self.assertFalse(self.plan.is_active)

        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "unsuspend_package",
                "package_id": str(self.plan.id),
                "confirm": "on",
            },
        )
        self.assertEqual(res.status_code, 302)
        self.plan.refresh_from_db()
        self.assertTrue(self.plan.is_active)

    def test_delete_package_unassigns_customers(self):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Ada Client",
            phone="0700000001",
            account_number="PKG-DEL-1",
            plan=self.plan,
        )
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "delete_package",
                "package_id": str(self.plan.id),
                "confirm": "on",
            },
        )
        self.assertEqual(res.status_code, 302)
        self.assertFalse(BillingPlan.objects.filter(pk=self.plan.id).exists())
        customer.refresh_from_db()
        self.assertIsNone(customer.plan_id)

    def test_delete_blocked_when_payment_history_exists(self):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Pay Client",
            phone="0700000002",
            account_number="PKG-STK-1",
            plan=self.plan,
        )
        StkPushRequest.objects.create(
            organization=self.org,
            customer=customer,
            plan=self.plan,
            amount=Decimal("1500.00"),
            phone="254700000002",
            account_reference=customer.account_number,
        )
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "delete_package",
                "package_id": str(self.plan.id),
                "confirm": "on",
            },
            follow=True,
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(BillingPlan.objects.filter(pk=self.plan.id).exists())
        self.assertContains(res, "payment history")
