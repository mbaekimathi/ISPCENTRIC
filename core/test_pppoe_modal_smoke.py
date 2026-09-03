from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from accounts.models import Organization


class PppoeModalRenderTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("owner-modal", password="x")
        self.org = Organization.objects.create(
            name="Modal ISP",
            owner=self.owner,
            join_code="909090",
        )
        self.client.force_login(self.owner)

    def test_pppoe_modal_renders_new_controls(self):
        res = self.client.get(reverse("core:my_clients"), {"tab": "pppoe"})
        self.assertEqual(res.status_code, 200)
        html = res.content.decode()
        self.assertIn("pppoe-register-modal", html)
        self.assertIn("data-generate-password=\"id_pppoe_password\"", html)
        self.assertIn("pppoe-section--slim", html)
        self.assertIn("pppoe-advanced", html)
        self.assertIn("data-pppoe-submit", html)
        self.assertIn("id_pppoe_activate", html)
        self.assertIn("id_pppoe_activation_date", html)
        self.assertIn("css/main.css", html)
