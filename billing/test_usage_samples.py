from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from unittest.mock import patch

from accounts.models import Organization, User
from billing.models import Customer, CustomerUsageSample
from billing.usage_samples import (
    network_performance_drops,
    org_usage_payload,
    parse_uptime_seconds,
    router_network_performance_trend,
    sample_organization_usage,
    usage_trend_payload,
)
from core.models import MikroTikRouter


class ParseUptimeSecondsTests(SimpleTestCase):
    def test_parses_routeros_uptime(self):
        self.assertEqual(parse_uptime_seconds("1h2m3s"), 3723)
        self.assertEqual(parse_uptime_seconds("2d"), 2 * 24 * 3600)
        self.assertEqual(parse_uptime_seconds(""), 0)


class UsageTrendPayloadTests(TestCase):
    def setUp(self):
        owner = User.objects.create_user("usage-owner", password="x")
        self.org = Organization.objects.create(name="Usage Org", owner=owner, join_code="USE001")
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Trend Client",
            phone="0700000000",
            account_number="PPP-USAGE-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="trend1",
        )

    def test_builds_series_and_data_deltas(self):
        now = timezone.now()
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(minutes=2),
            session_active=True,
            uptime_seconds=60,
            download_bps=1000,
            upload_bps=500,
            bytes_in=1000,
            bytes_out=200,
        )
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(minutes=1),
            session_active=True,
            uptime_seconds=120,
            download_bps=2000,
            upload_bps=800,
            bytes_in=5000,
            bytes_out=700,
        )
        payload = usage_trend_payload(self.customer, hours=24, use_cache=False)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["sample_count"], 2)
        self.assertEqual(payload["summary"]["peak_download_bps"], 2000)
        self.assertEqual(payload["summary"]["data_used_bytes"], 4500)
        self.assertGreaterEqual(len(payload["series"]["download_kbps"]), 1)
        self.assertEqual(len(payload["labels"]), len(payload["series"]["download_kbps"]))
        prime = payload["summary"]["prime_point"]
        self.assertIsNotNone(prime)
        self.assertEqual(prime["download_bps"], 2000)
        self.assertEqual(prime["upload_bps"], 800)
        lowest = payload["summary"]["lowest_point"]
        self.assertIsNotNone(lowest)
        self.assertEqual(lowest["download_bps"], 1000)

    def test_marks_stopped_surfing_and_filter_window(self):
        now = timezone.now()
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(hours=3),
            session_active=True,
            uptime_seconds=600,
            download_bps=500000,
            upload_bps=100000,
            bytes_in=10_000,
            bytes_out=2_000,
        )
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(hours=2),
            session_active=False,
            uptime_seconds=0,
            download_bps=0,
            upload_bps=0,
            bytes_in=0,
            bytes_out=0,
        )
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(hours=1),
            session_active=True,
            uptime_seconds=120,
            download_bps=50_000,
            upload_bps=10_000,
            bytes_in=12_000,
            bytes_out=2_500,
        )
        payload = usage_trend_payload(self.customer, hours=6, use_cache=False)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["hours"], 6)
        self.assertGreaterEqual(payload["summary"]["stopped_count"], 1)
        self.assertTrue(payload["summary"]["latest_active"])
        self.assertIsNotNone(payload["summary"]["last_stopped"])
        self.assertGreaterEqual(payload["summary"]["prime_point"]["combined_bps"], 500000)
        self.assertLessEqual(
            payload["summary"]["lowest_point"]["combined_bps"],
            payload["summary"]["prime_point"]["combined_bps"],
        )
        # Presence series should span the filter window without excess points.
        self.assertGreaterEqual(len(payload["labels"]), 20)
        self.assertLessEqual(len(payload["labels"]), 48)
        self.assertIn(0, payload["series"]["online"])
        self.assertIn(1, payload["series"]["online"])
        self.assertEqual(
            len(payload["labels"]), len(payload["series"]["download_kbps"])
        )


class RouterNetworkPerformanceTrendTests(TestCase):
    def setUp(self):
        owner = User.objects.create_user("net-trend-owner", password="x")
        self.org = Organization.objects.create(name="Net Trend Org", owner=owner, join_code="NET001")
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Tower A",
            host="10.0.0.1",
            username="admin",
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            router=self.router,
            full_name="Net Client",
            phone="0700000001",
            account_number="PPP-NET-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="net1",
        )

    def test_groups_online_clients_by_router(self):
        now = timezone.now()
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(minutes=10),
            session_active=True,
            download_bps=500000,
            upload_bps=100000,
            bytes_in=1000,
            bytes_out=200,
        )
        trend = router_network_performance_trend(self.org, hours=24, use_cache=False)
        self.assertTrue(trend["ok"])
        self.assertEqual(len(trend["routers"]), 1)
        self.assertEqual(trend["summary"]["clients_online"], 1)
        router_ds = [ds for ds in trend["datasets"] if ds.get("router_id") == self.router.pk]
        self.assertEqual(len(router_ds), 1)
        self.assertTrue(any(v and v >= 1 for v in router_ds[0]["data"]))

    def test_explains_wifi_drop_when_clients_leave(self):
        now = timezone.now()
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(hours=1, minutes=20),
            session_active=True,
            download_bps=500000,
            upload_bps=100000,
            bytes_in=1000,
            bytes_out=200,
        )
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(minutes=10),
            session_active=False,
            download_bps=0,
            upload_bps=0,
            bytes_in=1000,
            bytes_out=200,
        )
        payload = network_performance_drops(self.org, hours=24)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["events"])
        event = payload["events"][0]
        self.assertEqual(event["router_id"], self.router.pk)
        self.assertGreaterEqual(event["from_online"], 1)
        self.assertEqual(event["to_online"], 0)
        self.assertIn("PPPoE", event["reason"])

    def test_wifi_drop_blames_mikrotik_outage(self):
        from core.models import MikroTikStatusSample

        now = timezone.now()
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(hours=1, minutes=10),
            session_active=True,
            download_bps=250000,
            upload_bps=50000,
            bytes_in=800,
            bytes_out=100,
        )
        MikroTikStatusSample.objects.create(
            organization=self.org,
            router=self.router,
            sampled_at=now - timezone.timedelta(minutes=20),
            status="disconnected",
            score=0,
            online=False,
        )
        payload = network_performance_drops(self.org, hours=24)
        self.assertTrue(payload["events"])
        reason = payload["events"][0]["reason"].lower()
        self.assertTrue(
            "offline" in reason or "unreachable" in reason,
            reason,
        )


class SampleOrganizationUsageTests(TestCase):
    def setUp(self):
        owner = User.objects.create_user("org-sample-owner", password="x")
        self.org = Organization.objects.create(
            name="Org Sample", owner=owner, join_code="ORG001"
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Core",
            host="10.0.0.2",
            username="admin",
            password="secret",
        )
        self.online = Customer.objects.create(
            organization=self.org,
            router=self.router,
            full_name="Online Client",
            phone="0700000100",
            account_number="PPP-ON-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="online1",
        )
        self.offline = Customer.objects.create(
            organization=self.org,
            router=self.router,
            full_name="Offline Client",
            phone="0700000101",
            account_number="PPP-OFF-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="offline1",
        )
        self.unassigned = Customer.objects.create(
            organization=self.org,
            full_name="Unassigned Client",
            phone="0700000102",
            account_number="PPP-NONE-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="none1",
        )

    @patch("core.mikrotik_connect.fetch_router_bulk_hotspot_usage")
    @patch("core.mikrotik_connect.fetch_router_bulk_pppoe_usage")
    def test_records_online_and_offline_clients(self, mock_pppoe, mock_hotspot):
        mock_pppoe.return_value = {
            "ok": True,
            "sessions": {
                "online1": {
                    "session_active": True,
                    "bytes_in": 5000,
                    "bytes_out": 1000,
                    "uptime_raw": "1h",
                    "address": "10.10.0.5",
                }
            },
            "error": "",
        }
        mock_hotspot.return_value = {"ok": True, "sessions": {}, "error": ""}

        result = sample_organization_usage(self.org, force=True)
        self.assertTrue(result["ok"])
        self.assertFalse(result["skipped"])
        self.assertGreaterEqual(result["sampled"], 2)

        online_sample = (
            CustomerUsageSample.objects.filter(customer=self.online)
            .order_by("-sampled_at")
            .first()
        )
        offline_sample = (
            CustomerUsageSample.objects.filter(customer=self.offline)
            .order_by("-sampled_at")
            .first()
        )
        self.assertIsNotNone(online_sample)
        self.assertTrue(online_sample.session_active)
        self.assertEqual(online_sample.bytes_in, 5000)
        self.assertIsNotNone(offline_sample)
        self.assertFalse(offline_sample.session_active)
        self.assertFalse(
            CustomerUsageSample.objects.filter(customer=self.unassigned).exists()
        )

    @patch("core.mikrotik_connect.fetch_router_bulk_hotspot_usage")
    @patch("core.mikrotik_connect.fetch_router_bulk_pppoe_usage")
    def test_failed_probe_does_not_mark_everyone_offline(self, mock_pppoe, mock_hotspot):
        mock_pppoe.return_value = {
            "ok": False,
            "sessions": {},
            "error": "Connection timed out.",
        }
        mock_hotspot.return_value = {"ok": False, "sessions": {}, "error": "timeout"}

        result = sample_organization_usage(self.org, force=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["sampled"], 0)
        self.assertEqual(CustomerUsageSample.objects.count(), 0)

    @patch("core.mikrotik_connect.fetch_router_bulk_hotspot_usage")
    @patch("core.mikrotik_connect.fetch_router_bulk_pppoe_usage")
    def test_org_payload_lists_all_clients_after_sweep(self, mock_pppoe, mock_hotspot):
        mock_pppoe.return_value = {
            "ok": True,
            "sessions": {
                "online1": {
                    "session_active": True,
                    "bytes_in": 9000,
                    "bytes_out": 2000,
                    "uptime_raw": "30m",
                }
            },
            "error": "",
        }
        mock_hotspot.return_value = {"ok": True, "sessions": {}, "error": ""}
        sample_organization_usage(self.org, force=True)

        payload = org_usage_payload(
            self.org, hours=24, service="pppoe", top_n=0, use_cache=False, auto_widen=False
        )
        self.assertTrue(payload["ok"])
        ids = {u["customer_id"] for u in payload["top_users"]}
        self.assertIn(self.online.pk, ids)
        self.assertIn(self.offline.pk, ids)
        self.assertIn(self.unassigned.pk, ids)
        self.assertEqual(payload["summary"]["clients_total"], 3)
        online_row = next(
            u for u in payload["top_users"] if u["customer_id"] == self.online.pk
        )
        offline_row = next(
            u for u in payload["top_users"] if u["customer_id"] == self.offline.pk
        )
        self.assertTrue(online_row["latest_active"])
        self.assertFalse(offline_row["latest_active"])
