from django.test import SimpleTestCase

from accounts.email_design import (
    build_transactional_email_html,
    plain_body_to_html_blocks,
    theme_for_event,
)


class EmailDesignTests(SimpleTestCase):
    def test_theme_for_fup_is_warning(self):
        theme = theme_for_event("fup_limit_reached")
        self.assertEqual(theme["label"], "Attention")
        self.assertEqual(theme["accent"], "#e09a12")

    def test_theme_for_payment_is_success(self):
        theme = theme_for_event("payment_received")
        self.assertEqual(theme["label"], "Success")
        self.assertEqual(theme["accent"], "#145c3c")

    def test_theme_for_mikrotik_off_is_danger(self):
        theme = theme_for_event("isp_mikrotik_off")
        self.assertEqual(theme["label"], "Alert")
        self.assertEqual(theme["accent"], "#c0392b")

    def test_plain_body_escapes_and_preserves_breaks(self):
        html = plain_body_to_html_blocks('Hello <b>x</b>\nLine 2\n\nhttps://example.com/pay')
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", html)
        self.assertIn("<br />", html)
        self.assertIn('href="https://example.com/pay"', html)

    def test_build_html_includes_brand_and_badge(self):
        html = build_transactional_email_html(
            body="Client Ada hit the FUP limit.\nService is now throttled.",
            subject="FUP alert",
            title="Client hit fair usage limit",
            company_name="Richcom ISP",
            event_key="isp_fup_limit_reached",
            recipient_name="Ops Desk",
        )
        self.assertIn("Richcom ISP", html)
        self.assertIn("Client hit fair usage limit", html)
        self.assertIn("Hi Ops Desk,", html)
        self.assertIn("Attention", html)
        self.assertIn("#e09a12", html)
        self.assertIn("throttled", html)
        self.assertNotIn("<script", html.lower())
