from unittest.mock import patch

from django.core.cache import cache
from django.test import SimpleTestCase, override_settings

from core.mikrotik_auto_restore import (
    attach_auto_restore_to_rows,
    get_auto_restore_record,
    record_auto_restore_attempt,
)


class _StubRouter:
    pk = 7
    name = "Tower"
    host = "10.0.0.1"
    organization_id = 1

    class organization:
        phone = "254712345678"

        class owner:
            email = "owner@example.com"
            phone = ""


class MikroTikAutoRestoreTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def test_record_persists_and_attaches_to_status_rows(self):
        router = _StubRouter()
        outcome = {
            "ok": True,
            "restore_kind": "management",
            "status_before": "disconnected",
        }
        public = record_auto_restore_attempt(router, outcome)
        self.assertTrue(public["ok"])
        self.assertEqual(public["restore_kind"], "management")
        self.assertIn("auto-restored", public["message"].lower())

        stored = get_auto_restore_record(router.pk)
        self.assertIsNotNone(stored)
        self.assertTrue(stored["ok"])

        rows = [{"id": router.pk, "status": "connected"}]
        attach_auto_restore_to_rows(rows)
        self.assertIn("auto_restore", rows[0])
        self.assertTrue(rows[0]["auto_restore"]["ok"])

    @override_settings(
        MIKROTIK_AUTO_RESTORE_ALERTS=True,
        MIKROTIK_AUTO_RESTORE_ALERT_COOLDOWN_SEC=3600,
        PUBLIC_BASE_URL="https://app.example.com",
    )
    @patch("accounts.communications.send_sms")
    @patch("accounts.communications.send_email")
    def test_notify_on_failure_dedupes_repeat_alerts(self, mock_email, mock_sms):
        router = _StubRouter()
        fail = {
            "ok": False,
            "restore_kind": "internet",
            "status_before": "connected",
            "error": "No default route",
        }
        record_auto_restore_attempt(router, fail)
        self.assertEqual(mock_email.call_count, 1)
        self.assertEqual(mock_sms.call_count, 1)

        record_auto_restore_attempt(router, fail)
        self.assertEqual(mock_email.call_count, 1)
        self.assertEqual(mock_sms.call_count, 1)

        success = {
            "ok": True,
            "restore_kind": "internet",
            "status_before": "connected",
        }
        record_auto_restore_attempt(router, success)
        self.assertEqual(mock_email.call_count, 2)
        self.assertEqual(mock_sms.call_count, 2)

    @override_settings(MIKROTIK_AUTO_RESTORE_ALERTS=True)
    @patch("accounts.communications.send_sms")
    @patch("accounts.communications.send_email")
    def test_skipped_outcomes_do_not_alert(self, mock_email, mock_sms):
        router = _StubRouter()
        record_auto_restore_attempt(
            router,
            {"ok": False, "skipped": True, "reason": "account_suspended"},
        )
        mock_email.assert_not_called()
        mock_sms.assert_not_called()
