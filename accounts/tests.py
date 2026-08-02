from django import forms
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from accounts.forms import OrganizationEditForm, OwnerProfileForm, RegisterForm, validate_flexible_password
from accounts.models import Employee, Organization
from billing.models import Customer


class FlexiblePasswordTests(TestCase):
    def test_accepts_six_digit_code(self):
        self.assertEqual(validate_flexible_password("123456", "123456", required=True), "123456")

    def test_accepts_longer_password(self):
        self.assertEqual(
            validate_flexible_password("secret1", "secret1", required=True),
            "secret1",
        )

    def test_rejects_short_non_code(self):
        with self.assertRaises(forms.ValidationError):
            validate_flexible_password("12345", "12345", required=True)


class OwnerProfileFormTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="OWNER1",
            email="owner@example.com",
            password="oldpass1",
        )
        Organization.objects.create(name="Test ISP", owner=self.user, join_code="998877")

    def test_can_set_six_digit_username_and_password(self):
        form = OwnerProfileForm(
            {
                "username": "654321",
                "first_name": "Ann",
                "last_name": "Owner",
                "email": "owner@example.com",
                "password1": "112233",
                "password2": "112233",
            },
            user=self.user,
        )
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, "654321")
        self.assertTrue(self.user.check_password("112233"))

    def test_leave_password_blank_keeps_current(self):
        form = OwnerProfileForm(
            {
                "username": "OWNER1",
                "first_name": "",
                "last_name": "",
                "email": "owner@example.com",
                "password1": "",
                "password2": "",
            },
            user=self.user,
        )
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("oldpass1"))


class RegisterFormSixDigitTests(TestCase):
    def test_register_with_six_digit_username_and_password(self):
        form = RegisterForm(
            {
                "username": "777888",
                "email": "new@isp.com",
                "company_name": "NEW ISP",
                "country_code": "254|Kenya",
                "phone": "712345678",
                "password1": "445566",
                "password2": "445566",
            }
        )
        self.assertTrue(form.is_valid(), form.errors)


class OrganizationMpesaAccountModeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("acct-owner", password="x")
        self.org = Organization.objects.create(
            name="Paybill ISP",
            owner=self.user,
            join_code="334455",
            mpesa_payment_type=Organization.MpesaPaymentType.PAYBILL,
            mpesa_number="522522",
        )

    def _payload(self, **overrides):
        data = {
            "name": self.org.name,
            "phone": "",
            "status": self.org.status,
            "mpesa_payment_type": "paybill",
            "mpesa_number": "522522",
            "mpesa_account_mode": "client",
            "mpesa_account": "",
            "daraja_enabled": False,
            "daraja_environment": Organization.DarajaEnvironment.SANDBOX,
            "daraja_consumer_key": "",
            "daraja_consumer_secret": "",
            "daraja_passkey": "",
        }
        data.update(overrides)
        return data

    def test_client_mode_clears_custom_account(self):
        self.org.mpesa_account = "OLDNAME"
        self.org.save(update_fields=["mpesa_account"])
        form = OrganizationEditForm(self._payload(), instance=self.org)
        self.assertTrue(form.is_valid(), form.errors)
        org = form.save()
        self.assertEqual(org.mpesa_account, "")

    def test_custom_mode_requires_value(self):
        form = OrganizationEditForm(
            self._payload(mpesa_account_mode="custom", mpesa_account=""),
            instance=self.org,
        )
        self.assertFalse(form.is_valid())
        self.assertIn("mpesa_account", form.errors)

    def test_custom_mode_saves_name_or_any_input(self):
        form = OrganizationEditForm(
            self._payload(mpesa_account_mode="custom", mpesa_account="Jane ISP"),
            instance=self.org,
        )
        self.assertTrue(form.is_valid(), form.errors)
        org = form.save()
        self.assertEqual(org.mpesa_account, "Jane ISP")

    def test_initial_mode_follows_saved_account(self):
        self.org.mpesa_account = "BizName"
        form = OrganizationEditForm(instance=self.org)
        self.assertEqual(
            form.initial.get("mpesa_account_mode"),
            OrganizationEditForm.MpesaAccountMode.CUSTOM,
        )


class SalesCustomerRegistrationTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("sales-owner", password="pass123")
        self.org = Organization.objects.create(
            name="Sales Org ISP",
            owner=self.owner,
            join_code="112233",
        )
        self.sales_user = User.objects.create_user("salesperson", password="pass123")
        self.employee = Employee.objects.create(
            user=self.sales_user,
            organization=None,
            login_code="334455",
            status=Employee.Status.ACTIVE,
            role=Employee.Role.SALES,
        )
        self.client = Client()
        self.url = reverse("roles:sales_customer_registration")

    def test_page_loads_without_employee_organization(self):
        self.client.force_login(self.sales_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "What are you registering?")
        self.assertContains(response, "PPPoE client")
        self.assertContains(response, "Business (ISP)")
        self.assertContains(response, 'id="client-register-fields"')
        self.assertContains(response, 'id="isp-register-fields"')
        self.assertContains(response, 'id="customer-register-form"')
        self.assertContains(response, 'id="customer-register-modal"')
        self.assertContains(response, "Register customer")
        self.assertContains(response, "PPPoE client details")
        self.assertContains(response, "Business (ISP) details")
        self.assertNotContains(response, "Your account is not linked to an organization.")
        self.assertNotContains(response, "PPPoE username")
        self.assertNotContains(response, "Select MikroTik router")

    def test_register_personal_client(self):
        self.client.force_login(self.sales_user)
        response = self.client.post(
            self.url,
            {
                "registration_type": "client",
                "client-organization": str(self.org.pk),
                "client-full_name": "Jane Client",
                "client-country_code": "254|Kenya",
                "client-phone": "0712345678",
                "client-email": "jane@example.com",
                "client-address": "Westlands, Nairobi",
                "client-location_lat": "-1.267000",
                "client-location_lng": "36.811000",
                "client-building_name": "ABC Towers",
                "client-house_number": "12B",
            },
        )
        self.assertEqual(response.status_code, 302)
        customer = Customer.objects.get(full_name="JANE CLIENT")
        self.assertEqual(customer.organization_id, self.org.pk)
        self.assertEqual(customer.phone, "+254712345678")
        self.assertEqual(customer.email, "jane@example.com")
        self.assertEqual(customer.address, "WESTLANDS, NAIROBI")
        self.assertEqual(str(customer.location_lat), "-1.267000")
        self.assertEqual(str(customer.location_lng), "36.811000")
        self.assertEqual(customer.building_name, "ABC TOWERS")
        self.assertEqual(customer.house_number, "12B")
        self.assertEqual(customer.registered_by_id, self.sales_user.pk)
        self.assertEqual(customer.status, Customer.Status.ALLOCATED)
        self.assertTrue(customer.sales_ticket_number)
        self.assertTrue(customer.sales_ticket_number.startswith("PPP-"))
        self.assertFalse(customer.pppoe_username)
        self.assertIsNone(customer.router_id)

    def test_register_personal_client_without_isp(self):
        self.client.force_login(self.sales_user)
        response = self.client.post(
            self.url,
            {
                "registration_type": "client",
                "client-organization": "",
                "client-full_name": "Open Client",
                "client-country_code": "254|Kenya",
                "client-phone": "0798765432",
                "client-email": "",
                "client-address": "Kilimani, Nairobi",
                "client-location_lat": "-1.292100",
                "client-location_lng": "36.821900",
                "client-building_name": "Sunrise Court",
                "client-house_number": "",
            },
        )
        self.assertEqual(response.status_code, 302)
        customer = Customer.objects.get(full_name="OPEN CLIENT")
        self.assertIsNone(customer.organization_id)
        self.assertEqual(customer.registered_by_id, self.sales_user.pk)
        self.assertEqual(customer.status, Customer.Status.NEW)
        self.assertEqual(customer.phone, "+254798765432")
        self.assertEqual(customer.building_name, "SUNRISE COURT")
        self.assertEqual(customer.house_number, "")
        self.assertTrue(customer.sales_ticket_number)
        self.assertTrue(customer.sales_ticket_number.startswith("PPP-"))
        self.assertTrue(customer.account_number)

    def test_sales_lists_only_own_clients(self):
        other = User.objects.create_user("othersales", password="pass123")
        Employee.objects.create(
            user=other,
            organization=None,
            login_code="778899",
            status=Employee.Status.ACTIVE,
            role=Employee.Role.SALES,
        )
        Customer.objects.create(
            organization=self.org,
            full_name="Other Person Client",
            phone="0700000001",
            account_number="OTHER-1",
            registered_by=other,
        )
        mine = Customer.objects.create(
            organization=self.org,
            full_name="My Person Client",
            phone="0700000002",
            account_number="MINE-1",
            registered_by=self.sales_user,
        )
        self.client.force_login(self.sales_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, mine.full_name)
        self.assertNotContains(response, "Other Person Client")

    def test_register_isp_provider(self):
        self.client.force_login(self.sales_user)
        response = self.client.post(
            self.url,
            {
                "registration_type": "isp",
                "isp-username": "NEWISP1",
                "isp-email": "owner@newisp.com",
                "isp-company_name": "NEW FIBER",
                "isp-country_code": "254|Kenya",
                "isp-phone": "712345678",
                "isp-password1": "445566",
                "isp-password2": "445566",
            },
        )
        self.assertEqual(response.status_code, 302)
        org = Organization.objects.get(name="NEW FIBER")
        self.assertEqual(org.owner.username, "NEWISP1")
        self.assertEqual(org.status, Organization.Status.REGISTERED)
        self.assertEqual(org.registered_by_id, self.sales_user.pk)
        self.assertEqual(self.sales_user, User.objects.get(username="salesperson"))
        self.assertTrue(
            self.client.session.get("_auth_user_id") == str(self.sales_user.pk)
            or int(self.client.session.get("_auth_user_id")) == self.sales_user.pk
        )

    def test_lead_management_loads_without_employee_organization(self):
        self.client.force_login(self.sales_user)
        response = self.client.get(reverse("roles:sales_lead_management"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Your account is not linked to an organization.")
        self.assertContains(response, "ISP / organization")

    def test_technician_dashboard_loads_without_organization(self):
        tech_user = User.objects.create_user("techperson", password="pass123")
        Employee.objects.create(
            user=tech_user,
            organization=None,
            login_code="556677",
            status=Employee.Status.ACTIVE,
            role=Employee.Role.TECHNICIAN,
        )
        self.client.force_login(tech_user)
        response = self.client.get(reverse("roles:technician"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Your account is not linked to an organization.")


class EmployeeAdminOrgOptionalTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            "pending-staff",
            email="staff@example.com",
            password="pass123",
            first_name="Ann",
            last_name="Staff",
        )
        self.employee = Employee.objects.create(
            user=self.user,
            organization=None,
            login_code="778899",
            status=Employee.Status.PENDING_APPROVAL,
            role=Employee.Role.PENDING,
        )

    def test_sales_role_can_save_without_organization(self):
        from accounts.forms import EmployeeAdminEditForm

        form = EmployeeAdminEditForm(
            {
                "first_name": "Ann",
                "last_name": "Staff",
                "email": "staff@example.com",
                "phone": "",
                "organization": "",
                "role": Employee.Role.SALES,
                "status": Employee.Status.ACTIVE,
            },
            employee=self.employee,
        )
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        self.employee.refresh_from_db()
        self.assertEqual(self.employee.role, Employee.Role.SALES)
        self.assertIsNone(self.employee.organization_id)

    def test_technician_role_can_save_without_organization(self):
        from accounts.forms import EmployeeAdminEditForm

        form = EmployeeAdminEditForm(
            {
                "first_name": "Ann",
                "last_name": "Staff",
                "email": "staff@example.com",
                "phone": "",
                "organization": "",
                "role": Employee.Role.TECHNICIAN,
                "status": Employee.Status.ACTIVE,
            },
            employee=self.employee,
        )
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        self.employee.refresh_from_db()
        self.assertEqual(self.employee.role, Employee.Role.TECHNICIAN)
        self.assertIsNone(self.employee.organization_id)

    def test_administrator_role_requires_organization(self):
        from accounts.forms import EmployeeAdminEditForm

        form = EmployeeAdminEditForm(
            {
                "first_name": "Ann",
                "last_name": "Staff",
                "email": "staff@example.com",
                "phone": "",
                "organization": "",
                "role": Employee.Role.ADMINISTRATOR,
                "status": Employee.Status.ACTIVE,
            },
            employee=self.employee,
        )
        self.assertFalse(form.is_valid())
        self.assertIn("organization", form.errors)
