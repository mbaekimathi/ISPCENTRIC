import json
import smtplib
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from accounts.communications import fetch_provider_options, test_provider_connection
from accounts.models import Employee, PlatformCommunicationSettings


class FakeSMTP:
    instances = []
    login_error = None

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port = host, port
        self.tls = False
        self.sent = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def starttls(self, context=None):
        self.tls = True

    def login(self, user, password):
        if FakeSMTP.login_error:
            raise FakeSMTP.login_error
        self.user, self.password = user, password

    def sendmail(self, sender, recipients, message):
        self.sent.append((sender, recipients))

    def close(self):
        pass


EMAIL_PAYLOAD = {
    "channel": "email",
    "email_host": "mail.richcom.co.ke",
    "email_port": "465",
    "email_use_tls": "1",
    "email_host_user": "noreply@richcom.co.ke",
    "email_host_password": "mailbox-pass",
    "email_from_email": "noreply@richcom.co.ke",
    "email_from_name": "ISP-CENTRIC",
}


class ProviderConnectionTestTests(TestCase):
    def setUp(self):
        FakeSMTP.instances = []
        FakeSMTP.login_error = None

    def test_email_port_465_uses_ssl_and_logs_in_without_sending(self):
        with patch("accounts.communications.smtplib.SMTP_SSL", FakeSMTP), patch(
            "accounts.communications.smtplib.SMTP"
        ) as plain:
            result = test_provider_connection(dict(EMAIL_PAYLOAD))
        self.assertTrue(result["ok"], result)
        plain.assert_not_called()
        smtp = FakeSMTP.instances[0]
        self.assertEqual((smtp.host, smtp.port), ("mail.richcom.co.ke", 465))
        self.assertFalse(smtp.tls)
        self.assertEqual(smtp.user, "noreply@richcom.co.ke")
        self.assertEqual(smtp.sent, [])

    def test_email_bad_password_gives_plain_reason(self):
        FakeSMTP.login_error = smtplib.SMTPAuthenticationError(535, b"bad")
        with patch("accounts.communications.smtplib.SMTP_SSL", FakeSMTP):
            result = test_provider_connection(dict(EMAIL_PAYLOAD))
        self.assertFalse(result["ok"])
        self.assertIn("username or password", result["error"])

    def test_email_test_to_sends_a_message(self):
        payload = dict(EMAIL_PAYLOAD, email_port="587", test_to="owner@example.com")
        with patch("accounts.communications.smtplib.SMTP", FakeSMTP):
            result = test_provider_connection(payload)
        self.assertTrue(result["ok"], result)
        self.assertTrue(FakeSMTP.instances[0].tls)
        self.assertEqual(FakeSMTP.instances[-1].sent[0][1], ["owner@example.com"])

    def test_blank_secret_falls_back_to_saved(self):
        saved = PlatformCommunicationSettings.get_solo()
        saved.email_host_password = "saved-pass"
        saved.save()
        payload = dict(EMAIL_PAYLOAD, email_host_password="")
        with patch("accounts.communications.smtplib.SMTP_SSL", FakeSMTP):
            result = test_provider_connection(payload, saved=saved)
        self.assertTrue(result["ok"], result)
        self.assertEqual(FakeSMTP.instances[0].password, "saved-pass")

    def test_sms_africastalking_checks_account(self):
        with patch(
            "accounts.communications._http_request",
            return_value={"ok": True, "data": {"UserData": {"balance": "KES 120.00"}}},
        ) as http:
            result = test_provider_connection(
                {"channel": "sms", "sms_provider": "africastalking", "sms_username": "myisp", "sms_api_key": "k" * 20}
            )
        self.assertTrue(result["ok"], result)
        self.assertIn("KES 120.00", result["message"])
        self.assertIn("/version1/user", http.call_args[0][0])

    def test_sms_africastalking_rejected_key(self):
        with patch("accounts.communications._http_request", return_value={"ok": False, "status": 401, "error": "x"}):
            result = test_provider_connection(
                {"channel": "sms", "sms_provider": "africastalking", "sms_username": "myisp", "sms_api_key": "bad"}
            )
        self.assertFalse(result["ok"])
        self.assertIn("rejected", result["error"])

    def test_whatsapp_meta_requires_phone_number_id(self):
        result = test_provider_connection(
            {"channel": "whatsapp", "whatsapp_provider": "meta", "whatsapp_access_token": "tok"}
        )
        self.assertFalse(result["ok"])
        self.assertIn("phone number ID", result["error"])

    def test_whatsapp_meta_checks_number(self):
        with patch(
            "accounts.communications._http_request",
            return_value={"ok": True, "data": {"display_phone_number": "+254 700 000000", "verified_name": "ISP"}},
        ):
            result = test_provider_connection(
                {
                    "channel": "whatsapp",
                    "whatsapp_provider": "meta",
                    "whatsapp_access_token": "tok",
                    "whatsapp_phone_number_id": "1234567890",
                }
            )
        self.assertTrue(result["ok"], result)
        self.assertIn("+254 700 000000", result["message"])

    def test_own_domain_email_guesses_mail_host(self):
        result = fetch_provider_options({"channel": "email", "email_host_user": "noreply@richcom.co.ke"})
        self.assertEqual(result["smtp"]["host"], "mail.richcom.co.ke")


class CompanyCommunicationsTestViewTests(TestCase):
    def setUp(self):
        user = User.objects.create_user("it-comms-test", password="pass123")
        Employee.objects.create(
            user=user,
            organization=None,
            login_code="778899",
            status=Employee.Status.ACTIVE,
            role=Employee.Role.IT_SUPPORT,
        )
        self.client.force_login(user)

    def test_page_renders_test_buttons(self):
        response = self.client.get(reverse("roles:it_support_company_communications"))
        self.assertContains(response, 'data-comms-test-url="')
        for channel in ("sms", "email", "whatsapp"):
            self.assertContains(response, f'data-comms-test="{channel}"')

    def test_endpoint_returns_result(self):
        with patch("accounts.communications.smtplib.SMTP_SSL", FakeSMTP):
            response = self.client.post(
                reverse("roles:it_support_company_communications_test"),
                data=json.dumps(EMAIL_PAYLOAD),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.json()["ok"])
