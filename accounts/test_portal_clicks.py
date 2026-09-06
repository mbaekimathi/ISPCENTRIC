from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from accounts.models import HotspotPortalClick, Organization
from accounts.portal_clicks import (
    interest_score,
    interest_tier,
    portal_leads_for_organization,
    record_portal_click,
)
from billing.models import Customer


class PortalLeadsLogicTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="portalowner",
            email="portal@example.com",
            password="CorrectHorseBattery9!",
        )
        self.org = Organization.objects.create(
            name="Portal ISP",
            owner=self.owner,
            join_code="PORTAL1",
            hotspot_welcome_link1_label="Naivas",
            hotspot_welcome_link1_url="https://example.com/naivas",
            hotspot_welcome_link2_label="KFC",
            hotspot_welcome_link2_url="https://example.com/kfc",
        )

    def test_interest_score_weights_earn_and_recency(self):
        now = timezone.now()
        score = interest_score(
            earn_clicks=2,
            partner_1_clicks=1,
            partner_2_clicks=0,
            last_clicked_at=now,
            now=now,
        )
        self.assertEqual(score, 2 * 3 + 1 * 2 + 8)
        self.assertEqual(interest_tier(score=score, earn_clicks=2, total_clicks=3), "hot")

    def test_portal_leads_merge_and_rank(self):
        mac = "AA:BB:CC:DD:EE:FF"
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Jane Hotspot",
            phone="0712345678",
            phone_normalized="0712345678",
            account_number="ACC-PORTAL-1",
            hotspot_mac=mac,
            status=Customer.Status.ACTIVE,
        )
        record_portal_click(self.org, "earn", mac=mac, customer=customer)
        record_portal_click(self.org, "earn", mac=mac, customer=customer)
        record_portal_click(self.org, "partner_1", mac=mac, customer=customer)
        # Same person under a phone-only key should merge after enrichment.
        HotspotPortalClick.objects.create(
            organization=self.org,
            kind=HotspotPortalClick.Kind.PARTNER_2,
            contact_key="phone:0712345678",
            phone="0712345678",
            display_name="0712345678",
            click_count=4,
        )

        leads, summary = portal_leads_for_organization(self.org)
        self.assertEqual(summary["contacts"], 1)
        self.assertEqual(summary["earn_clicks"], 2)
        self.assertTrue(summary["show_partner_1"])
        self.assertTrue(summary["show_partner_2"])

        lead = leads[0]
        self.assertEqual(lead["earn_clicks"], 2)
        self.assertEqual(lead["partner_1_clicks"], 1)
        self.assertEqual(lead["partner_2_clicks"], 4)
        self.assertEqual(lead["total_clicks"], 7)
        self.assertTrue(lead["is_matched"])
        self.assertEqual(lead["customer_id"], customer.pk)
        self.assertEqual(lead["interest_tier"], "hot")
        self.assertGreaterEqual(lead["interest_score"], 12)

    def test_portal_filter_hot_and_search(self):
        record_portal_click(self.org, "partner_1", mac="11:22:33:44:55:66")
        record_portal_click(self.org, "earn", mac="AA:BB:CC:DD:EE:01")
        record_portal_click(self.org, "earn", mac="AA:BB:CC:DD:EE:01")
        record_portal_click(self.org, "partner_2", mac="AA:BB:CC:DD:EE:01")

        hot_leads, summary = portal_leads_for_organization(self.org, filter_key="hot")
        self.assertEqual(summary["contacts"], 2)
        self.assertEqual(len(hot_leads), 1)
        self.assertEqual(hot_leads[0]["hotspot_mac"], "AA:BB:CC:DD:EE:01")

        searched, _ = portal_leads_for_organization(self.org, query="11:22:33")
        self.assertEqual(len(searched), 1)
        self.assertEqual(searched[0]["partner_1_clicks"], 1)
