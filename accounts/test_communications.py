import json
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from accounts.communications import (
    fetch_sms_senders,
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
        self.comms.sms_provider = CommunicationSettings.SmsProvider.AFRICASTALKING
        self.assertFalse(self.comms.sms_status()["ready"])
        self.comms.sms_username = "myisp"
        self.comms.sms_api_key = "secret-key"
        self.assertTrue(self.comms.sms_status()["ready"])

    def test_email_and_whatsapp_status(self):
        self.assertFalse(self.comms.email_status()["enabled"])
        self.comms.email_enabled = True
        self.comms.email_host = "smtp.example.com"
        self.comms.email_host_user = "noreply@example.com"
        self.comms.email_host_password = "pass"
        self.comms.email_from_email = "billing@example.com"
        self.assertTrue(self.comms.email_status()["ready"])

        self.comms.whatsapp_enabled = True
        self.comms.whatsapp_provider = CommunicationSettings.WhatsAppProvider.META
        self.assertFalse(self.comms.whatsapp_status()["ready"])
        self.comms.whatsapp_phone_number_id = "12345"
        self.comms.whatsapp_access_token = "token"
        self.assertTrue(self.comms.whatsapp_status()["ready"])


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
                "sms_provider": CommunicationSettings.SmsProvider.AFRICASTALKING,
                "sms_username": "",
                "sms_api_key": "",
                "email_port": "587",
                "whatsapp_provider": CommunicationSettings.WhatsAppProvider.META,
            },
            instance=self.comms,
        )
        self.assertFalse(form.is_valid())
        self.assertIn("sms_username", form.errors)
        self.assertIn("sms_api_key", form.errors)

    def test_saves_africastalking_and_smtp(self):
        form = CommunicationSettingsForm(
            {
                "sms_enabled": "on",
                "sms_provider": CommunicationSettings.SmsProvider.AFRICASTALKING,
                "sms_username": "myisp",
                "sms_api_key": "at-key",
                "sms_sender_id": "ISPCENTRIC",
                "email_enabled": "on",
                "email_host": "smtp.gmail.com",
                "email_port": "587",
                "email_use_tls": "on",
                "email_host_user": "noreply@example.com",
                "email_host_password": "app-pass",
                "email_from_email": "billing@example.com",
                "email_from_name": "Form ISP",
                "whatsapp_enabled": "",
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
                "sms_provider": CommunicationSettings.SmsProvider.AFRICASTALKING,
                "sms_username": "settings-isp",
                "sms_api_key": "settings-key",
                "sms_sender_id": "ISP",
                "email_enabled": "",
                "email_port": "587",
                "email_use_tls": "on",
                "whatsapp_enabled": "",
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
        self.assertIn("/app/settings/communications/", response["Location"])
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
        self.company_settings_url = reverse("roles:it_support_company_settings")

    def test_get_solo_is_singleton(self):
        first = PlatformCommunicationSettings.get_solo()
        second = PlatformCommunicationSettings.get_solo()
        self.assertEqual(first.pk, 1)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(PlatformCommunicationSettings.objects.count(), 1)

    def test_company_settings_sidebar_has_communications_link(self):
        response = self.client.get(self.company_settings_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/it-support/company-settings/communications/")
        self.assertContains(response, "Company communications settings")
        self.assertNotContains(response, "/app/account/communications/")

    def test_get_shows_platform_form_not_isp_client_copy(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Company communications settings")
        self.assertContains(response, "Save company communications settings")
        self.assertContains(response, "ISPCENTRIC platform")
        self.assertContains(response, "Fetch senders")
        self.assertContains(response, "/app/settings/communications/")
        self.assertContains(response, "/it-support/company-settings/communications/fetch/")
        self.assertNotContains(response, "Your clients")
        self.assertNotContains(response, "This ISP account")
        self.assertNotContains(response, "Welcome / account created")
        self.assertNotContains(response, "When platform messages are sent")
        self.assertTrue(PlatformCommunicationSettings.objects.filter(pk=1).exists())

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
                "sms_provider": CommunicationSettings.SmsProvider.TWILIO,
                "sms_username": "ACxxxx",
                "sms_api_key": "token",
                "email_port": "587",
                "whatsapp_provider": CommunicationSettings.WhatsAppProvider.META,
            },
            instance=comms,
        )
        self.assertTrue(form.is_valid(), form.errors)
