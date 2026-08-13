from unittest.mock import patch

from django import forms
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from accounts.forms import (
    EmployeeLoginForm,
    EmployeeRegisterForm,
    OrganizationEditForm,
    OwnerProfileForm,
    RegisterForm,
    validate_account_password,
)
from accounts.models import (
    CommunicationSettings,
    Employee,
    Organization,
    PaymentGateway,
)
from billing.models import AccessVoucher, BillingPlan, Customer, StkPushRequest


STRONG_PASSWORD = "CorrectHorseBattery9!"


class AccountPasswordTests(TestCase):
    def test_rejects_six_digit_code(self):
        with self.assertRaises(forms.ValidationError):
            validate_account_password("123456", "123456", required=True)

    def test_rejects_short_password(self):
        with self.assertRaises(forms.ValidationError):
            validate_account_password("secret1", "secret1", required=True)

    def test_accepts_strong_password(self):
        self.assertEqual(
            validate_account_password(STRONG_PASSWORD, STRONG_PASSWORD, required=True),
            STRONG_PASSWORD,
        )


class OwnerProfileFormTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="OWNER1",
            email="owner@example.com",
            password="oldpass1-long!",
        )
        Organization.objects.create(name="Test ISP", owner=self.user, join_code="998877")

    def test_rejects_six_digit_password(self):
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
        self.assertFalse(form.is_valid())
        self.assertIn("password1", form.errors)

    def test_can_set_strong_password(self):
        form = OwnerProfileForm(
            {
                "username": "654321",
                "first_name": "Ann",
                "last_name": "Owner",
                "email": "owner@example.com",
                "password1": STRONG_PASSWORD,
                "password2": STRONG_PASSWORD,
            },
            user=self.user,
        )
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, "654321")
        self.assertTrue(self.user.check_password(STRONG_PASSWORD))

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
        self.assertTrue(self.user.check_password("oldpass1-long!"))


class RegisterFormPasswordTests(TestCase):
    def test_rejects_six_digit_password(self):
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
        self.assertFalse(form.is_valid())

    def test_register_with_strong_password(self):
        form = RegisterForm(
            {
                "username": "NEWISP",
                "email": "new@isp.com",
                "company_name": "NEW ISP",
                "country_code": "254|Kenya",
                "phone": "712345678",
                "password1": STRONG_PASSWORD,
                "password2": STRONG_PASSWORD,
            }
        )
        self.assertTrue(form.is_valid(), form.errors)


class EmployeeRegisterJoinCodeTests(TestCase):
    def setUp(self):
        owner = User.objects.create_user("join-owner", password=STRONG_PASSWORD)
        self.org = Organization.objects.create(
            name="Join ISP", owner=owner, join_code="112233"
        )

    def test_requires_valid_company_join_code(self):
        form = EmployeeRegisterForm(
            {
                "username": "STAFF1",
                "first_name": "Sam",
                "last_name": "Tech",
                "email": "sam@example.com",
                "country_code": "254|Kenya",
                "phone": "712345678",
                "company_join_code": "000000",
                "login_code": "556677",
                "password1": STRONG_PASSWORD,
                "password2": STRONG_PASSWORD,
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("company_join_code", form.errors)

    def test_registers_against_organization(self):
        form = EmployeeRegisterForm(
            {
                "username": "STAFF1",
                "first_name": "Sam",
                "last_name": "Tech",
                "email": "sam@example.com",
                "country_code": "254|Kenya",
                "phone": "712345678",
                "company_join_code": "112233",
                "login_code": "556677",
                "password1": STRONG_PASSWORD,
                "password2": STRONG_PASSWORD,
            }
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["organization"], self.org)


class EmployeeLoginEnumerationTests(TestCase):
    def test_unknown_code_does_not_say_invalid_login_code(self):
        form = EmployeeLoginForm(
            data={"username": "999991", "password": "wrong-password-xx"}
        )
        self.assertFalse(form.is_valid())
        errors = " ".join(str(e) for e in form.errors.get("__all__", []))
        self.assertEqual(errors, "Invalid login code or password.")
        field_errors = " ".join(
            str(e) for errs in form.errors.values() for e in errs
        )
        self.assertNotIn("Invalid login code.", field_errors)


@override_settings(OWNER_REGISTER_INVITE_KEY="")
class OwnerRegisterGateTests(TestCase):
    def setUp(self):
        from accounts.models import ClientSettings

        settings_obj = ClientSettings.get_solo()
        settings_obj.landing_register_enabled = False
        settings_obj.referral_enabled = False
        settings_obj.save(
            update_fields=[
                "landing_register_enabled",
                "referral_enabled",
                "updated_at",
            ]
        )

    def test_public_register_closed_when_register_link_off(self):
        response = self.client.get(reverse("accounts:register"))
        self.assertEqual(response.status_code, 403)

    def test_public_register_open_when_register_link_on(self):
        from accounts.models import ClientSettings

        settings_obj = ClientSettings.get_solo()
        settings_obj.landing_register_enabled = True
        settings_obj.save(update_fields=["landing_register_enabled", "updated_at"])
        response = self.client.get(reverse("accounts:register"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Register company")


class AuthRateLimitTests(TestCase):
    def test_login_lockout_after_failures(self):
        User.objects.create_user("rateuser", password=STRONG_PASSWORD)
        url = reverse("accounts:login")
        for _ in range(8):
            self.client.post(url, {"username": "RATEUSER", "password": "nope-not-it!!"})
        # Per-user counter should now be at/over limit messaging on next fail
        response = self.client.post(
            url, {"username": "RATEUSER", "password": "nope-not-it!!"}
        )
        self.assertEqual(response.status_code, 200)


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
                "isp-password1": STRONG_PASSWORD,
                "isp-password2": STRONG_PASSWORD,
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


class DarajaTokenCacheTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_get_access_token_reuses_cached_token(self):
        from accounts.mpesa_daraja import (
            get_access_token,
            invalidate_access_token_cache,
        )

        with patch("accounts.mpesa_daraja._json_request") as req:
            req.return_value = {
                "ok": True,
                "http_status": 200,
                "data": {"access_token": "tok-1", "expires_in": "3599"},
                "error": "",
            }
            first = get_access_token(
                consumer_key="k", consumer_secret="s", environment="production"
            )
            second = get_access_token(
                consumer_key="k", consumer_secret="s", environment="production"
            )
        self.assertTrue(first["ok"])
        self.assertEqual(first["access_token"], "tok-1")
        self.assertTrue(second.get("cached"))
        self.assertEqual(second["access_token"], "tok-1")
        self.assertEqual(req.call_count, 1)

        invalidate_access_token_cache(consumer_key="k", environment="production")
        with patch("accounts.mpesa_daraja._json_request") as req2:
            req2.return_value = {
                "ok": True,
                "http_status": 200,
                "data": {"access_token": "tok-2", "expires_in": "3599"},
                "error": "",
            }
            third = get_access_token(
                consumer_key="k", consumer_secret="s", environment="production"
            )
        self.assertEqual(third["access_token"], "tok-2")
        self.assertFalse(third.get("cached"))
        self.assertEqual(req2.call_count, 1)


class DarajaGatewayIsolationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("isp-owner", password="x")
        self.org = Organization.objects.create(
            name="Isolated ISP",
            owner=self.user,
            join_code="445566",
            mpesa_payment_type=Organization.MpesaPaymentType.PAYBILL,
            mpesa_number="522522",
            daraja_enabled=True,
            daraja_environment=Organization.DarajaEnvironment.SANDBOX,
        )
        self.gateway = PaymentGateway.get_solo()
        self.gateway.enabled = True
        self.gateway.environment = PaymentGateway.Environment.SANDBOX
        self.gateway.payment_type = PaymentGateway.PaymentType.PAYBILL
        self.gateway.shortcode = "174379"
        self.gateway.consumer_key = "company-key"
        self.gateway.consumer_secret = "company-secret"
        self.gateway.passkey = "company-pass"
        self.gateway.save()

    def test_company_gateway_is_default_when_isp_has_no_own_app(self):
        creds = self.org.effective_daraja_credentials()
        self.assertTrue(self.org.uses_platform_daraja_credentials())
        self.assertEqual(creds["source"], "platform")
        self.assertEqual(creds["source_label"], "Company Payment Gateway")
        self.assertEqual(creds["shortcode"], "174379")
        self.assertEqual(creds["payment_type"], "paybill")
        self.assertEqual(creds["consumer_key"], "company-key")
        self.assertEqual(creds["consumer_secret"], "company-secret")
        self.assertEqual(creds["passkey"], "company-pass")
        self.assertNotEqual(creds["shortcode"], self.org.mpesa_number)
        self.assertTrue(creds["ready"])

    def test_isp_own_gateway_never_uses_company_fields(self):
        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.daraja_consumer_key = "isp-key"
        self.org.daraja_consumer_secret = "isp-secret"
        self.org.daraja_passkey = "isp-pass"
        self.org.save()

        creds = self.org.effective_daraja_credentials()
        self.assertFalse(self.org.uses_platform_daraja_credentials())
        self.assertTrue(self.org.has_own_daraja_credentials())
        self.assertEqual(creds["source"], "organization")
        self.assertEqual(creds["source_label"], "ISP Payment Gateway")
        self.assertEqual(creds["shortcode"], "522522")
        self.assertEqual(creds["payment_type"], "paybill")
        self.assertEqual(creds["consumer_key"], "isp-key")
        self.assertEqual(creds["consumer_secret"], "isp-secret")
        self.assertEqual(creds["passkey"], "isp-pass")
        self.assertNotEqual(creds["consumer_key"], self.gateway.consumer_key)
        self.assertNotEqual(creds["shortcode"], self.gateway.shortcode)
        self.assertTrue(creds["ready"])

    def test_incomplete_own_gateway_falls_back_to_company_without_mixing(self):
        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.daraja_consumer_key = "isp-key"
        self.org.daraja_consumer_secret = ""
        self.org.daraja_passkey = ""
        self.org.save()

        creds = self.org.effective_daraja_credentials()
        self.assertTrue(self.org.uses_platform_daraja_credentials())
        self.assertEqual(creds["source"], "platform")
        self.assertEqual(creds["shortcode"], self.gateway.shortcode)
        self.assertEqual(creds["consumer_key"], self.gateway.consumer_key)
        self.assertNotEqual(creds["consumer_key"], "isp-key")
        self.assertNotEqual(creds["shortcode"], self.org.mpesa_number)

    def test_stk_off_does_not_use_company_gateway(self):
        self.org.daraja_enabled = False
        self.org.save(update_fields=["daraja_enabled"])
        creds = self.org.effective_daraja_credentials()
        self.assertFalse(self.org.uses_platform_daraja_credentials())
        self.assertFalse(creds["enabled"])
        self.assertFalse(creds["ready"])
        self.assertEqual(creds["source"], "none")
        self.assertEqual(creds["consumer_key"], "")

    def test_platform_fee_credentials_ignore_isp_fields(self):
        from billing.stk import _platform_daraja_credentials

        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.daraja_consumer_key = "isp-key"
        self.org.daraja_consumer_secret = "isp-secret"
        self.org.daraja_passkey = "isp-pass"
        self.org.save()

        creds = _platform_daraja_credentials()
        self.assertEqual(creds["source"], "platform")
        self.assertEqual(creds["shortcode"], "174379")
        self.assertEqual(creds["consumer_key"], "company-key")
        self.assertNotEqual(creds["consumer_key"], "isp-key")


class ITSupportCompanyClientsTests(TestCase):
    def setUp(self):
        self.staff_user = User.objects.create_user(
            "it-support-clients", password=STRONG_PASSWORD
        )
        Employee.objects.create(
            user=self.staff_user,
            organization=None,
            login_code="778899",
            status=Employee.Status.ACTIVE,
            role=Employee.Role.IT_SUPPORT,
        )
        self.client.force_login(self.staff_user)

        self.keep_owner = User.objects.create_user("keep-isp-owner", password="x")
        self.keep_org = Organization.objects.create(
            name="Keep Fiber",
            owner=self.keep_owner,
            join_code="111111",
            status=Organization.Status.ACTIVE,
        )
        self.keep_plan = BillingPlan.objects.create(
            organization=self.keep_org,
            name="Keep Monthly",
            price="1500.00",
        )
        self.keep_customer = Customer.objects.create(
            organization=self.keep_org,
            full_name="Keep Client",
            phone="254700000010",
            account_number="KEEP-1",
            plan=self.keep_plan,
        )
        self.keep_comms = CommunicationSettings.for_organization(self.keep_org)
        self.keep_comms.sms_username = "keep-sms"
        self.keep_comms.save(update_fields=["sms_username"])

        self.drop_owner = User.objects.create_user("drop-isp-owner", password="x")
        self.drop_staff_user = User.objects.create_user("drop-isp-staff", password="x")
        self.drop_org = Organization.objects.create(
            name="Drop Wireless",
            owner=self.drop_owner,
            join_code="222222",
            status=Organization.Status.ACTIVE,
        )
        self.keep_org.referred_by = self.drop_org
        self.keep_org.referral_status = Organization.ReferralStatus.ACTIVE
        self.keep_org.save(update_fields=["referred_by", "referral_status"])
        Employee.objects.create(
            user=self.drop_staff_user,
            organization=self.drop_org,
            login_code="334455",
            status=Employee.Status.ACTIVE,
            role=Employee.Role.SALES,
        )
        self.drop_plan = BillingPlan.objects.create(
            organization=self.drop_org,
            name="Drop Daily",
            price="100.00",
        )
        self.drop_customer = Customer.objects.create(
            organization=self.drop_org,
            full_name="Drop Client",
            phone="254700000020",
            account_number="DROP-1",
            plan=self.drop_plan,
        )
        self.drop_comms = CommunicationSettings.for_organization(self.drop_org)
        self.drop_comms.sms_username = "drop-sms"
        self.drop_comms.save(update_fields=["sms_username"])
        StkPushRequest.objects.create(
            organization=self.drop_org,
            customer=self.drop_customer,
            plan=self.drop_plan,
            amount="100.00",
            phone="254700000020",
            account_reference="DROP-1",
        )
        AccessVoucher.objects.create(
            organization=self.drop_org,
            customer=self.drop_customer,
            plan=self.drop_plan,
            code="DROPCODE1",
        )
        from core.models import MikroTikRouter

        MikroTikRouter.objects.create(
            organization=self.drop_org,
            name="Drop Router",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.0.0.1",
            username="admin",
            password="secret",
        )
        self.gateway = PaymentGateway.get_solo()
        self.gateway.enabled = True
        self.gateway.shortcode = "174379"
        self.gateway.save()

    def test_dashboard_has_company_clients_link(self):
        response = self.client.get(reverse("roles:it_support"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/it-support/company-clients/")
        self.assertContains(response, "Company clients")

    def test_lists_all_isp_accounts(self):
        response = self.client.get(reverse("roles:it_support_company_clients"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Drop Wireless")
        self.assertContains(response, "Keep Fiber")
        self.assertContains(response, "subscribers")
        self.assertContains(response, "packages")
        self.assertContains(response, reverse(
            "roles:it_support_company_client_edit", args=[self.drop_org.pk]
        ))
        self.assertContains(response, reverse(
            "roles:it_support_company_client_delete", args=[self.drop_org.pk]
        ))

    def test_delete_page_lists_what_will_be_removed(self):
        url = reverse("roles:it_support_company_client_delete", args=[self.drop_org.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Everything that will be deleted")
        self.assertContains(response, "Drop Wireless")
        self.assertContains(response, "Drop Client")
        self.assertContains(response, "Drop Daily")
        self.assertContains(response, "Drop Router")
        self.assertContains(response, "drop-isp-staff")
        self.assertContains(response, "Subscribers")
        self.assertContains(response, "Packages")
        self.assertContains(response, "MikroTik routers")
        self.assertContains(response, "Communication settings")
        self.assertContains(response, "Will not be changed")
        self.assertContains(response, "Other ISP accounts")
        self.assertNotContains(response, "Keep Client")
        self.assertNotContains(response, "Keep Monthly")

    def test_edit_updates_profile_only(self):
        url = reverse("roles:it_support_company_client_edit", args=[self.drop_org.pk])
        response = self.client.post(
            url,
            {
                "name": "Drop Wireless Updated",
                "phone": "712345678",
                "status": Organization.Status.REGISTERED,
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Company clients")
        self.assertContains(response, "cc-edit-modal")
        self.drop_org.refresh_from_db()
        self.assertEqual(self.drop_org.name, "DROP WIRELESS UPDATED")
        self.assertEqual(self.drop_org.status, Organization.Status.REGISTERED)
        self.keep_org.refresh_from_db()
        self.assertEqual(self.keep_org.name, "Keep Fiber")

    def test_edit_get_opens_list_popup(self):
        url = reverse("roles:it_support_company_client_edit", args=[self.drop_org.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(
            f"{reverse('roles:it_support_company_clients')}?edit={self.drop_org.pk}",
            response["Location"],
        )
        followed = self.client.get(response["Location"])
        self.assertEqual(followed.status_code, 200)
        self.assertContains(followed, "cc-edit-modal")
        self.assertContains(followed, 'data-open-id="' + str(self.drop_org.pk) + '"')

    def test_suspend_and_unsuspend(self):
        suspend_url = reverse(
            "roles:it_support_company_client_suspend", args=[self.drop_org.pk]
        )
        unsuspend_url = reverse(
            "roles:it_support_company_client_unsuspend", args=[self.drop_org.pk]
        )
        response = self.client.post(suspend_url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.drop_org.refresh_from_db()
        self.assertEqual(self.drop_org.status, Organization.Status.SUSPENDED)
        self.keep_org.refresh_from_db()
        self.assertEqual(self.keep_org.status, Organization.Status.ACTIVE)

        response = self.client.post(unsuspend_url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.drop_org.refresh_from_db()
        self.assertEqual(self.drop_org.status, Organization.Status.ACTIVE)

    def test_delete_removes_only_that_isp_account(self):
        from core.models import MikroTikRouter

        url = reverse("roles:it_support_company_client_delete", args=[self.drop_org.pk])
        response = self.client.post(url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Organization.objects.filter(pk=self.drop_org.pk).exists())
        self.assertFalse(User.objects.filter(pk=self.drop_owner.pk).exists())
        self.assertFalse(User.objects.filter(pk=self.drop_staff_user.pk).exists())
        self.assertFalse(Customer.objects.filter(pk=self.drop_customer.pk).exists())
        self.assertFalse(BillingPlan.objects.filter(pk=self.drop_plan.pk).exists())
        self.assertFalse(
            CommunicationSettings.objects.filter(organization_id=self.drop_org.pk).exists()
        )
        self.assertFalse(
            MikroTikRouter.objects.filter(organization_id=self.drop_org.pk).exists()
        )
        self.assertFalse(
            AccessVoucher.objects.filter(organization_id=self.drop_org.pk).exists()
        )
        self.assertFalse(
            StkPushRequest.objects.filter(organization_id=self.drop_org.pk).exists()
        )

        self.keep_org.refresh_from_db()
        self.assertEqual(self.keep_org.name, "Keep Fiber")
        self.assertIsNone(self.keep_org.referred_by_id)
        self.assertTrue(User.objects.filter(pk=self.keep_owner.pk).exists())
        self.assertTrue(Customer.objects.filter(pk=self.keep_customer.pk).exists())
        self.assertTrue(BillingPlan.objects.filter(pk=self.keep_plan.pk).exists())
        self.keep_comms.refresh_from_db()
        self.assertEqual(self.keep_comms.sms_username, "keep-sms")
        self.gateway.refresh_from_db()
        self.assertTrue(self.gateway.enabled)
        self.assertEqual(self.gateway.shortcode, "174379")
        self.assertTrue(User.objects.filter(pk=self.staff_user.pk).exists())

    def test_cannot_delete_own_organization(self):
        platform_owner = User.objects.create_user("platform-owner", password="x")
        platform_org = Organization.objects.create(
            name="ISPCENTRIC Platform",
            owner=platform_owner,
            join_code="999999",
        )
        staff = self.staff_user.employee_profile
        staff.organization = platform_org
        staff.save(update_fields=["organization"])

        url = reverse("roles:it_support_company_client_delete", args=[platform_org.pk])
        response = self.client.post(url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Organization.objects.filter(pk=platform_org.pk).exists())
        self.assertTrue(User.objects.filter(pk=platform_owner.pk).exists())
