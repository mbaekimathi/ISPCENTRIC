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
        self.assertIn("Max devices", html)
        self.assertIn("1 CPE", html)
        self.assertIn("unlimited LAN", html)
        self.assertIn('data-package-max-devices="0"', html)

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
                "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.MONTHS,
                "service_type": BillingPlan.ServiceType.HOTSPOT,
                "max_devices": "1",
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
        self.assertIn("package-type-wizard", html)
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
                    "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.MONTHS,
                    "service_type": BillingPlan.ServiceType.PPPOE,
                    "max_devices": "1",
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
                    "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.MONTHS,
                    "service_type": BillingPlan.ServiceType.PPPOE,
                    "is_active": "on",
                },
            )
        self.assertEqual(res.status_code, 302)
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.name, "HOME RENAMED")
        self.assertEqual(self.plan.max_devices, 0)
        schedule.assert_not_called()

    def test_register_package_blank_max_devices_is_unlimited(self):
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "register_package",
                "name": "Open WiFi",
                "description": "",
                "price": "200.00",
                "download_speed_mbps": "8",
                "upload_speed_mbps": "4",
                "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.DAYS,
                "service_type": BillingPlan.ServiceType.HOTSPOT,
                "is_active": "on",
            },
        )
        self.assertEqual(res.status_code, 302)
        plan = BillingPlan.objects.get(organization=self.org, name="OPEN WIFI")
        self.assertEqual(plan.max_devices, 0)
        self.assertEqual(plan.max_devices_label, "Unlimited devices")

    def test_edit_package_blank_max_devices_is_unlimited(self):
        self.plan.max_devices = 2
        self.plan.save(update_fields=["max_devices"])
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
                "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.MONTHS,
                "service_type": BillingPlan.ServiceType.PPPOE,
                "is_active": "on",
            },
        )
        self.assertEqual(res.status_code, 302)
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.max_devices, 0)
        self.assertEqual(self.plan.max_devices_label, "1 CPE · unlimited LAN")

    def test_edit_package_reprovisions_when_max_devices_changes(self):
        with patch(
            "billing.views._schedule_reprovision_customers_for_plan_speeds",
        ) as schedule:
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
                    "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.MONTHS,
                    "service_type": BillingPlan.ServiceType.PPPOE,
                    "max_devices": "3",
                    "is_active": "on",
                },
            )
        self.assertEqual(res.status_code, 302)
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.max_devices, 3)
        schedule.assert_called_once_with(self.plan.id)

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
                "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.MONTHS,
                "service_type": BillingPlan.ServiceType.PPPOE,
                "max_devices": "1",
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
                "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.MONTHS,
                "service_type": BillingPlan.ServiceType.PPPOE,
                "max_devices": "1",
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

    def test_register_package_accepts_custom_billing_period(self):
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "register_package",
                "name": "Three Day Pass",
                "description": "",
                "price": "250.00",
                "download_speed_mbps": "10",
                "upload_speed_mbps": "5",
                "duration_value": "3",
                "duration_unit": BillingPlan.DurationUnit.DAYS,
                "service_type": BillingPlan.ServiceType.HOTSPOT,
                "is_active": "on",
            },
        )
        self.assertEqual(res.status_code, 302)
        plan = BillingPlan.objects.get(organization=self.org, name="THREE DAY PASS")
        self.assertEqual(plan.duration_value, 3)
        self.assertEqual(plan.duration_unit, BillingPlan.DurationUnit.DAYS)
        self.assertEqual(plan.duration, BillingPlan.Duration.CUSTOM)
        self.assertEqual(plan.get_duration_display(), "3 days")

    def test_edit_package_can_set_custom_hours(self):
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
                "duration_value": "12",
                "duration_unit": BillingPlan.DurationUnit.HOURS,
                "service_type": BillingPlan.ServiceType.PPPOE,
                "is_active": "on",
            },
        )
        self.assertEqual(res.status_code, 302)
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.duration_value, 12)
        self.assertEqual(self.plan.duration_unit, BillingPlan.DurationUnit.HOURS)
        self.assertEqual(self.plan.duration, BillingPlan.Duration.CUSTOM)
        self.assertTrue(self.plan.uses_clock_time)
        self.assertEqual(self.plan.get_duration_display(), "12 hours")

    def test_packages_page_exposes_custom_duration_controls(self):
        res = self.client.get(reverse("billing:packages"))
        self.assertEqual(res.status_code, 200)
        html = res.content.decode()
        self.assertIn("package-duration-custom", html)
        self.assertIn('name="duration_value"', html)
        self.assertIn('name="duration_unit"', html)
        self.assertIn('data-package-duration-value=', html)
        self.assertIn('data-package-duration-unit=', html)

    def test_edit_hotspot_fixed_package_updates_devices_and_details(self):
        hotspot = BillingPlan.objects.create(
            organization=self.org,
            name="Hot Daily",
            price=Decimal("50.00"),
            download_speed_mbps=5,
            upload_speed_mbps=2,
            duration=BillingPlan.Duration.DAILY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            max_devices=1,
            is_active=True,
        )
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "edit_package",
                "package_id": str(hotspot.id),
                "name": "Hot Family",
                "description": "Three phones",
                "price": "120.00",
                "download_speed_mbps": "8",
                "upload_speed_mbps": "4",
                "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.DAYS,
                "service_type": BillingPlan.ServiceType.HOTSPOT,
                "max_devices": "3",
                "hotspot_other_devices_enabled": "",
                "hotspot_hourly_rate_per_device": "0",
                "is_active": "on",
            },
        )
        self.assertEqual(res.status_code, 302)
        hotspot.refresh_from_db()
        self.assertEqual(hotspot.name, "HOT FAMILY")
        self.assertEqual(hotspot.price, Decimal("120.00"))
        self.assertEqual(hotspot.download_speed_mbps, 8)
        self.assertEqual(hotspot.max_devices, 3)
        self.assertFalse(hotspot.hotspot_other_devices_enabled)
        self.assertEqual(hotspot.max_devices_label, "3 devices · 3 vouchers")

    def test_edit_hotspot_other_devices_pricing(self):
        hotspot = BillingPlan.objects.create(
            organization=self.org,
            name="Hot Hourly",
            price=Decimal("30.00"),
            download_speed_mbps=5,
            upload_speed_mbps=2,
            duration=BillingPlan.Duration.HOURLY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            max_devices=0,
            hotspot_other_devices_enabled=True,
            hotspot_other_base_price=Decimal("30.00"),
            hotspot_hourly_rate_per_device=Decimal("10.00"),
            is_active=True,
        )
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "edit_package",
                "package_id": str(hotspot.id),
                "name": "Hot Hourly",
                "description": "",
                "price": "40.00",
                "download_speed_mbps": "6",
                "upload_speed_mbps": "3",
                "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.HOURS,
                "service_type": BillingPlan.ServiceType.HOTSPOT,
                "hotspot_other_devices_enabled": "on",
                "hotspot_other_base_price": "40.00",
                "hotspot_hourly_rate_per_device": "15.00",
                "is_active": "on",
            },
        )
        self.assertEqual(res.status_code, 302)
        hotspot.refresh_from_db()
        self.assertEqual(hotspot.price, Decimal("40.00"))
        self.assertEqual(hotspot.download_speed_mbps, 6)
        self.assertTrue(hotspot.hotspot_other_devices_enabled)
        self.assertEqual(hotspot.hotspot_other_base_price, Decimal("40.00"))
        self.assertEqual(hotspot.hotspot_hourly_rate_per_device, Decimal("15.00"))

    def test_edit_hotspot_other_devices_requires_hourly_rate(self):
        hotspot = BillingPlan.objects.create(
            organization=self.org,
            name="Hot Needs Rate",
            price=Decimal("30.00"),
            download_speed_mbps=5,
            upload_speed_mbps=2,
            duration=BillingPlan.Duration.HOURLY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            hotspot_other_devices_enabled=True,
            hotspot_hourly_rate_per_device=Decimal("10.00"),
            is_active=True,
        )
        res = self.client.post(
            reverse("billing:packages"),
            {
                "action": "edit_package",
                "package_id": str(hotspot.id),
                "name": "Hot Needs Rate",
                "description": "",
                "price": "30.00",
                "download_speed_mbps": "5",
                "upload_speed_mbps": "2",
                "duration_value": "1",
                "duration_unit": BillingPlan.DurationUnit.HOURS,
                "service_type": BillingPlan.ServiceType.HOTSPOT,
                "hotspot_other_devices_enabled": "on",
                "hotspot_other_base_price": "30.00",
                "hotspot_hourly_rate_per_device": "0",
                "is_active": "on",
            },
        )
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "hourly rate per device")
        hotspot.refresh_from_db()
        self.assertEqual(hotspot.hotspot_hourly_rate_per_device, Decimal("10.00"))

    def test_packages_page_exposes_hotspot_edit_fields(self):
        BillingPlan.objects.create(
            organization=self.org,
            name="Portal Hot",
            price=Decimal("50.00"),
            download_speed_mbps=5,
            upload_speed_mbps=2,
            duration=BillingPlan.Duration.DAILY,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            max_devices=2,
            is_active=True,
        )
        res = self.client.get(reverse("billing:packages"))
        self.assertEqual(res.status_code, 200)
        html = res.content.decode()
        self.assertIn('data-package-service-type="hotspot"', html)
        self.assertIn("data-package-hotspot-other-enabled=", html)
        self.assertIn("data-package-hotspot-hourly-rate=", html)
        self.assertIn("hotspot_hourly_rate_per_device", html)
        self.assertIn("data-package-hotspot-fixed-hint", html)
        self.assertIn("Fixed package", html)
        self.assertIn("Other devices", html)
