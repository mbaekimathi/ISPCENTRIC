import json
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from accounts.communications import (
    fetch_sms_senders,
    dispatch_platform_event,
    normalize_msisdn,
    send_email,
    send_sms,
    send_whatsapp,
    suggest_smtp,
)
from accounts.forms import CommunicationSettingsForm, PlatformCommunicationSettingsForm
from accounts.models import (
    CommunicationSettings,
    Employee,
    Organization,
    PlatformCommunicationSettings,
)


class CommunicationSettingsModelTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("comms-owner", password="x")
        self.org = Organization.objects.create(
            name="Comms ISP",
            owner=self.owner,
            join_code="121212",
        )
        self.comms = CommunicationSettings.for_organization(self.org)

    def test_for_organization_is_idempotent(self):
        again = CommunicationSettings.for_organization(self.org)
        self.assertEqual(self.comms.pk, again.pk)
        self.assertEqual(CommunicationSettings.objects.filter(organization=self.org).count(), 1)

    def test_sms_status_requires_credentials_when_enabled(self):
        self.comms.sms_enabled = True
        self.comms.sms_credential_source = CommunicationSettings.CredentialSource.OWN
        self.comms.sms_provider = CommunicationSettings.SmsProvider.AFRICASTALKING
        self.assertFalse(self.comms.sms_status()["ready"])
        self.comms.sms_username = "myisp"
        self.comms.sms_api_key = "secret-key"
        self.assertTrue(self.comms.sms_status()["ready"])

    def test_email_and_whatsapp_status(self):
        self.assertFalse(self.comms.email_status()["enabled"])
        self.comms.email_enabled = True
        self.comms.email_credential_source = CommunicationSettings.CredentialSource.OWN
        self.comms.email_host = "smtp.example.com"
        self.comms.email_host_user = "noreply@example.com"
        self.comms.email_host_password = "pass"
        self.comms.email_from_email = "billing@example.com"
        self.assertTrue(self.comms.email_status()["ready"])

        self.comms.whatsapp_enabled = True
        self.comms.whatsapp_credential_source = CommunicationSettings.CredentialSource.OWN
        self.comms.whatsapp_provider = CommunicationSettings.WhatsAppProvider.META
        self.assertFalse(self.comms.whatsapp_status()["ready"])
        self.comms.whatsapp_phone_number_id = "12345"
        self.comms.whatsapp_access_token = "token"
        self.assertTrue(self.comms.whatsapp_status()["ready"])

    def test_company_email_uses_platform_credentials(self):
        platform = PlatformCommunicationSettings.get_solo()
        platform.email_enabled = True
        platform.email_host = "mail.richcom.co.ke"
        platform.email_host_user = "noreply@richcom.co.ke"
        platform.email_host_password = "secret"
        platform.email_from_email = "noreply@richcom.co.ke"
        platform.save()

        self.comms.email_enabled = True
        self.comms.email_credential_source = CommunicationSettings.CredentialSource.COMPANY
        self.comms.email_host = ""
        self.comms.email_host_user = ""
        self.comms.email_host_password = ""
        status = self.comms.email_status()
        self.assertTrue(status["ready"])
        self.assertEqual(status["source"], "company")
        effective = self.comms.effective_credentials("email")
        self.assertEqual(effective.pk, platform.pk)
        self.assertEqual(effective.email_host, "mail.richcom.co.ke")


class CommunicationSettingsFormTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("comms-form-owner", password="x")
        self.org = Organization.objects.create(
            name="Form ISP",
            owner=self.owner,
            join_code="343434",
        )
        self.comms = CommunicationSettings.for_organization(self.org)

    def test_disabled_channels_do_not_require_credentials(self):
        form = CommunicationSettingsForm(
            {
                "sms_enabled": "",
                "email_enabled": "",
                "whatsapp_enabled": "",
                "sms_provider": CommunicationSettings.SmsProvider.AFRICASTALKING,
                "whatsapp_provider": CommunicationSettings.WhatsAppProvider.META,
                "email_port": "587",
                "email_use_tls": "on",
            },
            instance=self.comms,
        )
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save()
        self.assertFalse(saved.sms_enabled)
        self.assertFalse(saved.email_enabled)
        self.assertFalse(saved.whatsapp_enabled)

    def test_sms_enabled_requires_provider_credentials(self):
        form = CommunicationSettingsForm(
            {
                "sms_enabled": "on",
                "sms_credential_source": CommunicationSettings.CredentialSource.OWN,
                "sms_provider": CommunicationSettings.SmsProvider.AFRICASTALKING,
                "sms_username": "",
                "sms_api_key": "",
                "email_port": "587",
                "email_credential_source": CommunicationSettings.CredentialSource.COMPANY,
                "whatsapp_provider": CommunicationSettings.WhatsAppProvider.META,
                "whatsapp_credential_source": CommunicationSettings.CredentialSource.COMPANY,
            },
            instance=self.comms,
        )
        self.assertFalse(form.is_valid())
        self.assertIn("sms_username", form.errors)
        self.assertIn("sms_api_key", form.errors)

    def test_company_email_does_not_require_own_smtp(self):
        form = CommunicationSettingsForm(
            {
                "sms_enabled": "",
                "sms_credential_source": CommunicationSettings.CredentialSource.COMPANY,
                "sms_provider": CommunicationSettings.SmsProvider.AFRICASTALKING,
                "email_enabled": "on",
                "email_credential_source": CommunicationSettings.CredentialSource.COMPANY,
                "email_port": "587",
                "whatsapp_enabled": "",
                "whatsapp_credential_source": CommunicationSettings.CredentialSource.COMPANY,
                "whatsapp_provider": CommunicationSettings.WhatsAppProvider.META,
            },
            instance=self.comms,
        )
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save()
        self.assertTrue(saved.email_enabled)
        self.assertEqual(
            saved.email_credential_source,
            CommunicationSettings.CredentialSource.COMPANY,
        )

    def test_saves_africastalking_and_smtp(self):
        form = CommunicationSettingsForm(
            {
                "sms_enabled": "on",
                "sms_credential_source": CommunicationSettings.CredentialSource.OWN,
                "sms_provider": CommunicationSettings.SmsProvider.AFRICASTALKING,
                "sms_username": "myisp",
                "sms_api_key": "at-key",
                "sms_sender_id": "ISPCENTRIC",
                "email_enabled": "on",
                "email_credential_source": CommunicationSettings.CredentialSource.OWN,
                "email_host": "smtp.gmail.com",
                "email_port": "587",
                "email_use_tls": "on",
                "email_host_user": "noreply@example.com",
                "email_host_password": "app-pass",
                "email_from_email": "billing@example.com",
                "email_from_name": "Form ISP",
                "whatsapp_enabled": "",
                "whatsapp_credential_source": CommunicationSettings.CredentialSource.COMPANY,
                "whatsapp_provider": CommunicationSettings.WhatsAppProvider.META,
            },
            instance=self.comms,
        )
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save()
        self.assertTrue(saved.sms_enabled)
        self.assertEqual(saved.sms_username, "myisp")
        self.assertTrue(saved.email_enabled)
        self.assertEqual(saved.email_host, "smtp.gmail.com")
        self.assertEqual(
            saved.email_credential_source,
            CommunicationSettings.CredentialSource.OWN,
        )


class CommunicationSettingsViewTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("comms-view-owner", password="pass123")
        self.org = Organization.objects.create(
            name="View ISP",
            owner=self.owner,
            join_code="565656",
        )
        self.client.force_login(self.owner)
        self.url = reverse("core:my_account_communications")

    def test_get_shows_events_without_credential_form(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Your clients")
        self.assertContains(response, "This ISP account")
        self.assertContains(response, "Welcome / account created")
        self.assertContains(response, "Lead allocated to this ISP")
        self.assertContains(response, "MikroTik successfully onboarded")
        self.assertContains(response, "When messages are sent")
        self.assertContains(response, "comms-event-table")
        self.assertContains(response, "data-comms-message-open")
        self.assertContains(response, "comms-message-modal")
        self.assertContains(response, 'name="form_action"')
        self.assertContains(response, "save_enabled_messages")
        self.assertContains(response, ">Save<")
        self.assertContains(response, "/app/account/")
        self.assertContains(response, "/app/account/communications/")
        self.assertContains(response, "/app/settings/communications/")
        self.assertContains(response, "Communication settings")
        self.assertNotContains(response, "Save communications")
        self.assertNotContains(response, "Save communication settings")
        self.assertNotContains(response, "SMTP host")
        self.assertTrue(
            CommunicationSettings.objects.filter(organization=self.org).exists()
        )

    def test_account_post_saves_enabled_messages(self):
        comms = CommunicationSettings.for_organization(self.org)
        comms.sms_enabled = True
        comms.email_enabled = True
        # Own credentials so channel status is ready without company setup.
        comms.sms_credential_source = CommunicationSettings.CredentialSource.OWN
        comms.email_credential_source = CommunicationSettings.CredentialSource.OWN
        comms.sms_provider = CommunicationSettings.SmsProvider.AFRICASTALKING
        comms.sms_username = "sandbox"
        comms.sms_api_key = "key"
        comms.email_host = "smtp.example.com"
        comms.email_host_user = "noreply@example.com"
        comms.email_host_password = "secret"
        comms.email_from_email = "noreply@example.com"
        comms.save()

        response = self.client.post(
            self.url,
            {
                "form_action": "save_enabled_messages",
                "event_key": "isp_mikrotik_onboarded",
                "message": "MikroTik {router_name} onboarded for {company_name}.",
                "recipients": ["organization_owner"],
                "channels": ["email"],
                "include_link": "1",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/app/account/communications/", response["Location"])
        comms.refresh_from_db()
        rule = (comms.enabled_messages or {}).get("isp_mikrotik_onboarded")
        self.assertIsInstance(rule, dict)
        self.assertEqual(rule.get("channels"), ["email"])
        self.assertEqual(rule.get("recipients"), ["organization_owner"])
        self.assertTrue(rule.get("include_link"))

        page = self.client.get(self.url)
        self.assertContains(page, "is-enabled")
        self.assertContains(page, 'name="remove_event"')
        self.assertContains(page, "isp_mikrotik_onboarded")

        remove = self.client.post(
            self.url,
            {
                "form_action": "save_enabled_messages",
                "remove_event": "isp_mikrotik_onboarded",
            },
        )
        self.assertEqual(remove.status_code, 302)
        comms.refresh_from_db()
        self.assertNotIn("isp_mikrotik_onboarded", comms.enabled_messages or {})

    def test_settings_page_is_configuration_only(self):
        settings_url = reverse("core:settings_communications")
        response = self.client.get(reverse("core:system_settings"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Communication settings")
        self.assertContains(response, "/app/settings/communications/")

        response = self.client.get(settings_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Communication settings")
        self.assertContains(response, "Save communication settings")
        self.assertContains(response, "SMTP host")
        self.assertContains(response, "WhatsApp")
        self.assertContains(response, "Company communications")
        self.assertContains(response, "My own credentials")
        self.assertContains(response, "Email gateway")
        self.assertContains(response, "Fetch senders")
        self.assertContains(response, "/app/settings/communications/fetch/")
        self.assertNotContains(response, "Your clients")
        self.assertNotContains(response, "This ISP account")
        self.assertNotContains(response, "Welcome / account created")
        self.assertNotContains(response, "When messages are sent")

    def test_settings_post_saves_and_stays_on_settings(self):
        settings_url = reverse("core:settings_communications")
        response = self.client.post(
            settings_url,
            {
                "sms_enabled": "on",
                "sms_credential_source": CommunicationSettings.CredentialSource.OWN,
                "sms_provider": CommunicationSettings.SmsProvider.AFRICASTALKING,
                "sms_username": "settings-isp",
                "sms_api_key": "settings-key",
                "sms_sender_id": "ISP",
                "email_enabled": "",
                "email_credential_source": CommunicationSettings.CredentialSource.COMPANY,
                "email_port": "587",
                "email_use_tls": "on",
                "whatsapp_enabled": "",
                "whatsapp_credential_source": CommunicationSettings.CredentialSource.COMPANY,
                "whatsapp_provider": CommunicationSettings.WhatsAppProvider.META,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/app/settings/communications/", response["Location"])
        comms = CommunicationSettings.objects.get(organization=self.org)
        self.assertTrue(comms.sms_enabled)
        self.assertEqual(comms.sms_username, "settings-isp")

    def test_account_post_redirects_to_settings(self):
        response = self.client.post(
            self.url,
            {
                "sms_enabled": "on",
                "sms_provider": CommunicationSettings.SmsProvider.TWILIO,
                "sms_username": "ACxxxx",
                "sms_api_key": "twilio-token",
                "sms_from_number": "+254700000000",
                "email_enabled": "",
                "email_port": "587",
                "email_use_tls": "on",
                "whatsapp_enabled": "",
                "whatsapp_provider": CommunicationSettings.WhatsAppProvider.META,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/app/account/communications/", response["Location"])
        comms = CommunicationSettings.objects.get(organization=self.org)
        self.assertFalse(comms.sms_enabled)
        self.assertNotEqual(comms.sms_username, "ACxxxx")


class CommunicationSendTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("comms-send-owner", password="x")
        self.org = Organization.objects.create(
            name="Send ISP",
            owner=self.owner,
            join_code="787878",
        )
        self.comms = CommunicationSettings.for_organization(self.org)

    def test_normalize_msisdn(self):
        self.assertEqual(normalize_msisdn("0712345678"), "254712345678")
        self.assertEqual(normalize_msisdn("+254712345678"), "254712345678")
        self.assertEqual(normalize_msisdn(""), "")

    def test_send_sms_requires_ready_settings(self):
        result = send_sms(organization=self.org, to="0712345678", message="Hello")
        self.assertFalse(result["ok"])

    def test_send_sms_africastalking(self):
        self.comms.sms_enabled = True
        self.comms.sms_credential_source = CommunicationSettings.CredentialSource.OWN
        self.comms.sms_provider = CommunicationSettings.SmsProvider.AFRICASTALKING
        self.comms.sms_username = "myisp"
        self.comms.sms_api_key = "at-key"
        self.comms.sms_sender_id = "ISP"
        self.comms.save()
        with patch("accounts.communications._http_request", return_value={"ok": True, "data": {"SMSMessageData": {}}}) as http:
            result = send_sms(organization=self.org, to="0712345678", message="Hello")
        self.assertTrue(result["ok"])
        url, kwargs = http.call_args[0][0], http.call_args[1]
        self.assertIn("africastalking.com", url)
        self.assertEqual(kwargs["headers"]["apiKey"], "at-key")
        self.assertEqual(kwargs["data"]["to"], "+254712345678")
        self.assertEqual(kwargs["data"]["from"], "ISP")

    def test_send_email_uses_smtp(self):
        self.comms.email_enabled = True
        self.comms.email_credential_source = CommunicationSettings.CredentialSource.OWN
        self.comms.email_host = "smtp.example.com"
        self.comms.email_port = 587
        self.comms.email_use_tls = True
        self.comms.email_host_user = "noreply@example.com"
        self.comms.email_host_password = "secret"
        self.comms.email_from_email = "billing@example.com"
        self.comms.email_from_name = "Send ISP"
        self.comms.save()

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                self.args = args

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def starttls(self, context=None):
                self.tls = True

            def login(self, user, password):
                self.user = user
                self.password = password

            def sendmail(self, sender, recipients, message):
                self.sender = sender
                self.recipients = recipients
                self.message = message

        with patch("accounts.communications.smtplib.SMTP", FakeSMTP):
            result = send_email(
                organization=self.org,
                to="client@example.com",
                subject="Invoice",
                body="Pay now",
            )
        self.assertTrue(result["ok"], result)

    def test_send_whatsapp_meta(self):
        self.comms.whatsapp_enabled = True
        self.comms.whatsapp_credential_source = CommunicationSettings.CredentialSource.OWN
        self.comms.whatsapp_provider = CommunicationSettings.WhatsAppProvider.META
        self.comms.whatsapp_phone_number_id = "1099"
        self.comms.whatsapp_access_token = "meta-token"
        self.comms.save()
        with patch("accounts.communications._http_request", return_value={"ok": True, "data": {"messages": []}}) as http:
            result = send_whatsapp(organization=self.org, to="0712345678", message="Hi")
        self.assertTrue(result["ok"])
        url = http.call_args[0][0]
        self.assertIn("/1099/messages", url)
        self.assertEqual(
            http.call_args[1]["headers"]["Authorization"],
            "Bearer meta-token",
        )
        self.assertEqual(http.call_args[1]["data"]["to"], "254712345678")


class PlatformCommunicationSettingsTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("platform-isp-owner", password="pass123")
        self.org = Organization.objects.create(
            name="Platform Distinct ISP",
            owner=self.owner,
            join_code="909090",
        )
        self.isp_comms = CommunicationSettings.for_organization(self.org)
        self.isp_comms.sms_enabled = True
        self.isp_comms.sms_credential_source = CommunicationSettings.CredentialSource.OWN
        self.isp_comms.sms_provider = CommunicationSettings.SmsProvider.AFRICASTALKING
        self.isp_comms.sms_username = "isp-user"
        self.isp_comms.sms_api_key = "isp-key"
        self.isp_comms.save()

        self.staff_user = User.objects.create_user("it-support-comms", password="pass123")
        Employee.objects.create(
            user=self.staff_user,
            organization=None,
            login_code="445566",
            status=Employee.Status.ACTIVE,
            role=Employee.Role.IT_SUPPORT,
        )
        self.client.force_login(self.staff_user)
        self.url = reverse("roles:it_support_company_communications")
        self.company_profile_url = reverse("roles:it_support_company_profile")
        self.company_settings_url = reverse("roles:it_support_company_settings")

    def test_get_solo_is_singleton(self):
        first = PlatformCommunicationSettings.get_solo()
        second = PlatformCommunicationSettings.get_solo()
        self.assertEqual(first.pk, 1)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(PlatformCommunicationSettings.objects.count(), 1)

    def test_company_system_settings_sidebar_has_module_links(self):
        response = self.client.get(reverse("roles:it_support_company_system_settings"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/it-support/company-settings/communications/")
        self.assertContains(response, "Company communications settings")
        self.assertContains(response, "/it-support/communications/")
        self.assertContains(response, "Communications")
        self.assertContains(response, "Company profile")
        self.assertNotContains(response, "/app/account/communications/")

    def test_company_profile_sidebar_does_not_share_system_settings_links(self):
        response = self.client.get(self.company_profile_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Company communications settings")
        self.assertNotContains(response, "Company Payment Gateway")
        self.assertNotContains(response, "ISP onboarding settings")
        self.assertNotContains(response, "Company themes")
        self.assertNotContains(response, "/app/account/communications/")

    def test_legacy_company_settings_url_redirects_to_profile(self):
        response = self.client.get(self.company_settings_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/it-support/company-profile/", response["Location"])

    def test_get_shows_platform_form_not_isp_client_copy(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Company communications settings")
        self.assertContains(response, "Save company communications settings")
        self.assertContains(response, "ISPCENTRIC platform")
        self.assertContains(response, "Fetch senders")
        self.assertContains(response, "/app/settings/communications/")
        self.assertContains(response, "/it-support/communications/")
        self.assertContains(response, "/it-support/company-settings/communications/fetch/")
        self.assertNotContains(response, 'name="event_key"')
        self.assertNotContains(response, "Add enabled message")
        self.assertNotContains(response, "Your clients")
        self.assertNotContains(response, "This ISP account")
        self.assertNotContains(response, "Welcome / account created")
        self.assertNotContains(response, "When platform messages are sent")
        self.assertTrue(PlatformCommunicationSettings.objects.filter(pk=1).exists())

    def test_dashboard_sidebar_has_company_communications_link(self):
        from accounts.models import Employee
        from accounts.routing import nav_items_for_role

        nav = nav_items_for_role(Employee.Role.IT_SUPPORT, "dashboard")["main"]
        labels = [item["label"] for item in nav]
        self.assertIn("Company communications", labels)
        link = next(item for item in nav if item["label"] == "Company communications")
        self.assertEqual(link["url_name"], "roles:it_support_communications")
        response = self.client.get(reverse("roles:it_support"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/it-support/communications/")
        self.assertContains(response, "Company communications")

    def test_post_saves_enabled_messages(self):
        events_url = reverse("roles:it_support_communications")
        platform = PlatformCommunicationSettings.get_solo()
        platform.sms_enabled = True
        platform.email_enabled = True
        platform.save(update_fields=["sms_enabled", "email_enabled", "updated_at"])

        response = self.client.post(
            events_url,
            {
                "form_action": "save_enabled_messages",
                "event_key": "platform_isp_welcome",
                "message": "Welcome to ISPCENTRIC — your account is ready.",
                "recipients": ["isp_client", "it_support"],
                "channels": ["email"],
                "include_link": "1",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/it-support/communications/", response["Location"])
        platform.refresh_from_db()
        rule = platform.enabled_messages.get("platform_isp_welcome")
        self.assertIsInstance(rule, dict)
        self.assertEqual(rule.get("channels"), ["email"])
        self.assertEqual(rule.get("recipients"), ["isp_client", "it_support"])
        self.assertTrue(rule.get("include_link"))
        self.assertIn("Welcome to ISPCENTRIC", rule.get("message") or "")

        page = self.client.get(events_url)
        self.assertContains(page, "Platform messages")
        self.assertContains(page, 'name="event_key"')
        self.assertContains(page, "To whom")
        self.assertContains(page, 'name="recipients"')
        self.assertContains(page, "data-comms-multi")
        self.assertContains(page, "ISP Client")
        self.assertContains(page, 'name="channels"')
        self.assertContains(page, 'name="include_link"')
        self.assertContains(page, "data-comms-message-open")
        self.assertContains(page, "comms-message-modal")
        self.assertContains(page, "data-comms-preview-tab")
        self.assertContains(page, 'data-comms-preview-pane="email"')
        self.assertContains(page, 'data-comms-preview-pane="sms"')
        self.assertContains(page, 'data-comms-preview-pane="whatsapp"')
        self.assertContains(page, "IT support")
        self.assertContains(page, "Sales")
        self.assertContains(page, "Technician")
        self.assertContains(page, "Channel")
        self.assertContains(page, "Link")
        self.assertContains(page, "New ISP registered")
        self.assertContains(page, ">Off<")
        self.assertContains(page, ">Save<")
        self.assertContains(page, "comms-event-row")
        self.assertContains(page, "comms-event-table-head")

        remove = self.client.post(
            events_url,
            {
                "form_action": "save_enabled_messages",
                "remove_event": "platform_isp_welcome",
            },
        )
        self.assertEqual(remove.status_code, 302)
        platform.refresh_from_db()
        self.assertNotIn("platform_isp_welcome", platform.enabled_messages or {})

    def test_communications_events_page_and_sidebar_link(self):
        events_url = reverse("roles:it_support_communications")
        response = self.client.get(events_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Platform messages")
        self.assertContains(response, "ISP companies")
        self.assertContains(response, "Platform staff")
        self.assertContains(response, "New ISP registered")
        self.assertContains(response, "MikroTik successfully onboarded")
        self.assertContains(response, "To whom")
        self.assertContains(response, "Gateway settings")
        self.assertContains(response, "/it-support/company-settings/communications/")
        self.assertNotContains(response, "Save company communications settings")
        self.assertNotContains(response, "SMTP host")
        self.assertNotContains(response, "Message settings")
        self.assertNotContains(response, "Select a trigger")

        hub = self.client.get(reverse("roles:it_support_company_system_settings"))
        self.assertEqual(hub.status_code, 200)
        self.assertContains(hub, "/it-support/communications/")
        self.assertContains(hub, "Communications")
        # Sidebar before-meta link is present on company pages.
        self.assertContains(response, 'href="/it-support/communications/"')

    def test_dispatch_platform_mikrotik_onboarded_sends_when_enabled(self):
        owner = User.objects.create_user(
            "isp-owner-onboard",
            email="owner@example.com",
            password="x",
        )
        org = Organization.objects.create(
            name="Onboard ISP",
            owner=owner,
            phone="0712345678",
            join_code="343434",
        )
        platform = PlatformCommunicationSettings.get_solo()
        platform.email_enabled = True
        platform.email_host = "smtp.example.com"
        platform.email_host_user = "noreply@ispcentric.com"
        platform.email_host_password = "secret"
        platform.email_from_email = "noreply@ispcentric.com"
        platform.sms_enabled = True
        platform.sms_provider = PlatformCommunicationSettings.SmsProvider.AFRICASTALKING
        platform.sms_username = "sandbox"
        platform.sms_api_key = "key"
        platform.enabled_messages = {
            "platform_isp_mikrotik_onboarded": {
                "message": (
                    "Your MikroTik “{router_name}” was successfully onboarded "
                    "on ISPCENTRIC for {company_name}."
                ),
                "recipients": ["isp_client"],
                "channels": ["email", "sms"],
                "include_link": False,
            }
        }
        platform.save()

        with patch("accounts.communications.send_email") as mock_email, patch(
            "accounts.communications.send_sms"
        ) as mock_sms:
            mock_email.return_value = {"ok": True}
            mock_sms.return_value = {"ok": True}
            result = dispatch_platform_event(
                "platform_isp_mikrotik_onboarded",
                organization=org,
                context={"router_name": "Edge-01", "company_name": org.name},
            )

        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("sent"), 2)
        self.assertIn("Edge-01", result.get("message") or "")
        self.assertIn("Onboard ISP", result.get("message") or "")
        mock_email.assert_called_once()
        mock_sms.assert_called_once()
        self.assertEqual(mock_email.call_args.kwargs["to"], "owner@example.com")
        self.assertEqual(mock_sms.call_args.kwargs["to"], "0712345678")

    def test_legacy_system_settings_url_redirects(self):
        response = self.client.get(reverse("roles:it_support_settings_communications"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/it-support/company-settings/communications/", response["Location"])

    def test_post_saves_platform_credentials_separately_from_isp(self):
        response = self.client.post(
            self.url,
            {
                "sms_enabled": "on",
                "sms_provider": PlatformCommunicationSettings.SmsProvider.TWILIO,
                "sms_username": "ACplatform",
                "sms_api_key": "platform-token",
                "sms_from_number": "+254711111111",
                "email_enabled": "",
                "email_port": "587",
                "email_use_tls": "on",
                "whatsapp_enabled": "",
                "whatsapp_provider": PlatformCommunicationSettings.WhatsAppProvider.META,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/it-support/company-settings/communications/", response["Location"])

        platform = PlatformCommunicationSettings.objects.get(pk=1)
        self.assertTrue(platform.sms_enabled)
        self.assertEqual(platform.sms_provider, PlatformCommunicationSettings.SmsProvider.TWILIO)
        self.assertEqual(platform.sms_username, "ACplatform")

        self.isp_comms.refresh_from_db()
        self.assertEqual(self.isp_comms.sms_username, "isp-user")
        self.assertEqual(
            self.isp_comms.sms_provider,
            CommunicationSettings.SmsProvider.AFRICASTALKING,
        )

    def test_platform_form_does_not_write_isp_row(self):
        platform = PlatformCommunicationSettings.get_solo()
        form = PlatformCommunicationSettingsForm(
            {
                "sms_enabled": "on",
                "sms_provider": PlatformCommunicationSettings.SmsProvider.AFRICASTALKING,
                "sms_username": "ispcentric",
                "sms_api_key": "platform-at-key",
                "sms_sender_id": "ISPCENTRIC",
                "email_enabled": "",
                "email_port": "587",
                "email_use_tls": "on",
                "whatsapp_enabled": "",
                "whatsapp_provider": PlatformCommunicationSettings.WhatsAppProvider.META,
            },
            instance=platform,
        )
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save()
        self.assertEqual(saved.pk, 1)
        self.assertEqual(PlatformCommunicationSettings.objects.count(), 1)
        self.assertEqual(
            CommunicationSettings.objects.get(organization=self.org).sms_username,
            "isp-user",
        )


class CommunicationProviderFetchTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("comms-fetch-owner", password="pass123")
        self.org = Organization.objects.create(
            name="Fetch ISP",
            owner=self.owner,
            join_code="112244",
        )
        self.client.force_login(self.owner)

    def test_suggest_smtp_for_common_mailboxes(self):
        gmail = suggest_smtp("billing@gmail.com")
        self.assertEqual(gmail["host"], "smtp.gmail.com")
        self.assertEqual(gmail["port"], 587)
        self.assertTrue(gmail["use_tls"])
        outlook = suggest_smtp("support@outlook.com")
        self.assertEqual(outlook["host"], "smtp.office365.com")
        self.assertIsNone(suggest_smtp("noreply@myisp.co.ke"))

    def test_fetch_sms_africastalking_lists_any_sender_type(self):
        def fake_http(url, **kwargs):
            if "/user" in url:
                return {"ok": True, "data": {"UserData": {"balance": "10.00"}}}
            return {
                "ok": True,
                "data": {"SenderIds": [{"SenderId": "ISPCENTRIC"}, {"SenderId": "22445"}]},
            }

        with patch("accounts.communications._http_request", side_effect=fake_http):
            result = fetch_sms_senders(
                provider=CommunicationSettings.SmsProvider.AFRICASTALKING,
                username="myisp",
                api_key="at-key",
            )
        self.assertTrue(result["ok"], result)
        values = [item["value"] for item in result["items"]]
        self.assertIn("ISPCENTRIC", values)
        self.assertIn("22445", values)

    def test_fetch_view_returns_json(self):
        url = reverse("core:settings_communications_fetch")
        with patch(
            "core.views.fetch_provider_options",
            return_value={
                "ok": True,
                "channel": "sms",
                "items": [{"value": "ISP", "label": "ISP", "type": "sender"}],
                "message": "Fetched.",
            },
        ):
            response = self.client.post(
                url,
                data=json.dumps(
                    {
                        "channel": "sms",
                        "sms_provider": CommunicationSettings.SmsProvider.AFRICASTALKING,
                        "sms_username": "myisp",
                        "sms_api_key": "at-key",
                    }
                ),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["items"][0]["value"], "ISP")

    def test_twilio_can_save_without_from_until_fetch(self):
        comms = CommunicationSettings.for_organization(self.org)
        form = CommunicationSettingsForm(
            {
                "sms_enabled": "on",
                "sms_credential_source": CommunicationSettings.CredentialSource.OWN,
                "sms_provider": CommunicationSettings.SmsProvider.TWILIO,
                "sms_username": "ACxxxx",
                "sms_api_key": "token",
                "email_port": "587",
                "email_credential_source": CommunicationSettings.CredentialSource.COMPANY,
                "whatsapp_credential_source": CommunicationSettings.CredentialSource.COMPANY,
                "whatsapp_provider": CommunicationSettings.WhatsAppProvider.META,
            },
            instance=comms,
        )
        self.assertTrue(form.is_valid(), form.errors)


class OrgEventDispatchTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            "org-dispatch-owner",
            password="x",
            email="owner@example.com",
        )
        self.org = Organization.objects.create(
            name="Dispatch ISP",
            owner=self.owner,
            join_code="112233",
            phone="0712345678",
        )
        self.comms = CommunicationSettings.for_organization(self.org)
        self.comms.sms_enabled = True
        self.comms.email_enabled = True
        self.comms.sms_credential_source = CommunicationSettings.CredentialSource.OWN
        self.comms.email_credential_source = CommunicationSettings.CredentialSource.OWN
        self.comms.sms_provider = CommunicationSettings.SmsProvider.AFRICASTALKING
        self.comms.sms_username = "sandbox"
        self.comms.sms_api_key = "key"
        self.comms.email_host = "smtp.example.com"
        self.comms.email_host_user = "noreply@example.com"
        self.comms.email_host_password = "secret"
        self.comms.email_from_email = "noreply@example.com"
        self.comms.enabled_messages = {
            "payment_received": {
                "message": "Payment received for {client_name}: {amount}.",
                "recipients": ["client"],
                "channels": ["sms", "email"],
                "include_link": False,
            },
            "package_pause_resume": {
                "message": "Package {status} for {client_name}.",
                "recipients": ["client"],
                "channels": ["sms"],
                "include_link": False,
            },
        }
        self.comms.save()

    def test_dispatch_org_event_sends_to_client(self):
        from accounts.communications import dispatch_org_event
        from billing.models import Customer

        customer = Customer.objects.create(
            organization=self.org,
            full_name="Pay Client",
            phone="0711000001",
            email="client@example.com",
            account_number="PPP-PAY1",
            status=Customer.Status.ACTIVE,
        )
        with patch("accounts.communications.send_email") as mock_email, patch(
            "accounts.communications.send_sms"
        ) as mock_sms:
            mock_email.return_value = {"ok": True}
            mock_sms.return_value = {"ok": True}
            result = dispatch_org_event(
                "payment_received",
                organization=self.org,
                client=customer,
                context={"amount": "500.00"},
            )
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("sent"), 2)
        self.assertIn("Pay Client", result.get("message") or "")
        self.assertIn("500.00", result.get("message") or "")
        mock_email.assert_called_once()
        mock_sms.assert_called_once()
        self.assertEqual(mock_email.call_args.kwargs["to"], "client@example.com")
        self.assertEqual(mock_sms.call_args.kwargs["to"], "0711000001")

    def test_pause_customer_package_triggers_notify(self):
        from datetime import timedelta

        from django.utils import timezone

        from billing.models import BillingPlan, Customer
        from billing.services import pause_customer_package

        plan = BillingPlan.objects.create(
            organization=self.org,
            name="Pause Plan",
            price="50.00",
            duration=BillingPlan.Duration.HOURLY,
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )
        now = timezone.localtime()
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Pause Client",
            phone="0711000002",
            account_number="PPP-PAUSE1",
            status=Customer.Status.ACTIVE,
            plan=plan,
            package_start=now - timedelta(minutes=10),
            package_end=now + timedelta(minutes=50),
        )
        with patch("accounts.communications.notify_org_event") as mock_notify:
            mock_notify.return_value = {"ok": True}
            pause_customer_package(customer, now=now)
        mock_notify.assert_called()
        self.assertEqual(mock_notify.call_args.args[0], "package_pause_resume")
        self.assertEqual(mock_notify.call_args.kwargs.get("client"), customer)
