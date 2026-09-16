"""NOC ops console tests."""

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from accounts.models import FaultTicket, Organization
from billing.models import Customer
from core.models import MikroTikRouter
from core.noc_board import build_noc_board

User = get_user_model()


class NocBoardTests(TestCase):
    def setUp(self):
        cache.clear()
        self.owner = User.objects.create_user("noc-owner", password="x")
        self.org = Organization.objects.create(
            name="NOC ISP",
            owner=self.owner,
            join_code="noc001",
            login_code="123456",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Edge A",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.9.0.10",
            username="admin",
            password="secret",
            location="Westlands",
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Alice Client",
            account_number="ACC-NOC-1",
            phone="0700000001",
            service_type=Customer.ServiceType.PPPOE,
            status=Customer.Status.ACTIVE,
            router=self.router,
            pppoe_username="alice",
        )

    def test_build_noc_board_builds_alarms_sites_and_timeline(self):
        cache.set(
            f"mikrotik_status:{self.org.pk}",
            [
                {
                    "id": self.router.pk,
                    "name": "Edge A",
                    "host": "10.9.0.10",
                    "online": False,
                    "status": "disconnected",
                    "error": "unreachable",
                    "via": "",
                }
            ],
            60,
        )
        FaultTicket.objects.create(
            ticket_number="FLT-NOC1",
            customer=self.customer,
            organization=self.org,
            issue=FaultTicket.Issue.NO_CONNECTIVITY,
            status=FaultTicket.Status.OPEN,
            notes="No internet since morning",
            created_by=self.owner,
        )

        board = build_noc_board(self.org)
        self.assertTrue(board["ok"])
        self.assertEqual(board["summary"]["routers_total"], 1)
        self.assertEqual(board["summary"]["routers_down"], 1)
        self.assertGreaterEqual(board["summary"]["alarms_critical"], 1)
        self.assertEqual(board["summary"]["customers_at_risk"], 1)
        self.assertEqual(board["routers"][0]["severity"], "critical")
        self.assertEqual(board["routers"][0]["site_label"], "Westlands")
        self.assertTrue(any(a["kind"] == "router" for a in board["alarms"]))
        self.assertTrue(any(a["kind"] == "fault" for a in board["alarms"]))
        self.assertEqual(board["sites"][0]["label"], "Westlands")
        self.assertTrue(board["timeline"])

    def test_noc_page_and_summary_require_owner_workspace(self):
        self.client.force_login(self.owner)
        page = self.client.get(reverse("core:noc"))
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Ops console")
        self.assertContains(page, "data-noc-view=\"ops\"")
        self.assertContains(page, "noc-mode-tabs")
        self.assertNotContains(page, "workspace-dash-kpi")

        down = self.client.get(reverse("core:noc") + "?focus=down")
        self.assertEqual(down.status_code, 200)
        self.assertContains(down, "Down routers")
        self.assertContains(down, 'data-noc-view="down"')
        self.assertContains(down, "Problem routers")
        self.assertContains(down, "Clients on down NAS")

        impact = self.client.get(reverse("core:noc") + "?focus=impact")
        self.assertEqual(impact.status_code, 200)
        self.assertContains(impact, "Client impact")
        self.assertContains(impact, 'data-noc-view="impact"')
        self.assertContains(impact, "Stuck sessions")
        self.assertContains(impact, "Impact groups")

        faults = self.client.get(reverse("core:noc") + "?focus=faults")
        self.assertEqual(faults.status_code, 200)
        self.assertContains(faults, "Open faults")
        self.assertContains(faults, 'data-noc-view="faults"')
        self.assertContains(faults, "Active tickets")
        self.assertContains(faults, "Unassigned")

        summary = self.client.get(reverse("core:noc_summary"))
        self.assertEqual(summary.status_code, 200)
        payload = summary.json()
        self.assertTrue(payload["ok"])
        self.assertIn("alarms", payload)
        self.assertIn("sites", payload)
        self.assertIn("timeline", payload)

    def test_mikrotik_nav_includes_noc_not_workspace(self):
        self.client.force_login(self.owner)
        dash = self.client.get(reverse("core:workspace"))
        self.assertEqual(dash.status_code, 200)
        # Workspace sidebar should not advertise NOC; entry is under MikroTik.
        self.assertNotContains(dash, ">NOC<")

        mikrotik = self.client.get(reverse("core:mikrotik"))
        self.assertEqual(mikrotik.status_code, 200)
        self.assertContains(mikrotik, reverse("core:noc"))
        self.assertContains(mikrotik, ">NOC<")
