from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from unittest.mock import patch

from accounts.models import Organization, User
from billing.models import Customer, CustomerUsageSample
from billing.usage_samples import (
    network_performance_drops,
    org_usage_payload,
    parse_uptime_seconds,
    parse_usage_filter,
    resolve_usage_window,
    router_network_performance_trend,
    sample_organization_usage,
    usage_filter_querystring,
    usage_trend_payload,
)
from core.models import MikroTikRouter


class ParseUptimeSecondsTests(SimpleTestCase):
    def test_parses_routeros_uptime(self):
        self.assertEqual(parse_uptime_seconds("1h2m3s"), 3723)
        self.assertEqual(parse_uptime_seconds("2d"), 2 * 24 * 3600)
        self.assertEqual(parse_uptime_seconds(""), 0)


class ParseUsageFilterTests(SimpleTestCase):
    class _Req:
        def __init__(self, params):
            self.GET = params

    def test_time_presets(self):
        filt = parse_usage_filter(self._Req({"range": "time", "time": "12"}), default_time="6")
        self.assertEqual(filt["range"], "time")
        self.assertEqual(filt["hours"], 12)
        self.assertTrue(filt["relative"])
        self.assertEqual(filt["label"], "Last half day")

    def test_day_mode(self):
        filt = parse_usage_filter(
            self._Req({"range": "day", "day": "2026-03-15"}), default_time="6"
        )
        self.assertEqual(filt["range"], "day")
        self.assertFalse(filt["relative"])
        self.assertEqual(filt["hours"], 24)
        self.assertIn("15", filt["label"])

    def test_period_mode_swaps_reversed_dates(self):
        filt = parse_usage_filter(
            self._Req({"range": "period", "start": "2026-03-20", "end": "2026-03-10"}),
            default_time="6",
        )
        self.assertEqual(filt["start"], "2026-03-10")
        self.assertEqual(filt["end"], "2026-03-20")
        self.assertFalse(filt["relative"])

    def test_month_and_year(self):
        month = parse_usage_filter(
            self._Req({"range": "month", "month": "2026-02"}), default_time="6"
        )
        self.assertEqual(month["label"], "February 2026")
        year = parse_usage_filter(
            self._Req({"range": "year", "year": "2025"}), default_time="6"
        )
        self.assertEqual(year["label"], "2025")
        self.assertGreaterEqual(year["hours"], 24 * 365)

    def test_legacy_hours_still_works(self):
        filt = parse_usage_filter(self._Req({"hours": "18"}), default_time="6")
        self.assertEqual(filt["hours"], 18)
        self.assertTrue(filt["relative"])
        self.assertEqual(filt["range"], "time")

    def test_querystring_roundtrip_keys(self):
        filt = parse_usage_filter(
            self._Req({"range": "period", "start": "2026-01-01", "end": "2026-01-07"}),
            default_time="6",
        )
        qs = usage_filter_querystring(filt, extra={"tab": "pppoe"})
        self.assertIn("range=period", qs)
        self.assertIn("start=2026-01-01", qs)
        self.assertIn("end=2026-01-07", qs)
        self.assertIn("tab=pppoe", qs)

    def test_resolve_usage_window_absolute(self):
        from django.utils import timezone as dj_tz

        until = dj_tz.now()
        since = until - dj_tz.timedelta(hours=3)
        s, u, hours = resolve_usage_window(since=since, until=until)
        self.assertEqual(hours, 3)
        self.assertEqual(s, since)
        self.assertEqual(u, until)


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

    def test_plain_language_story_fields(self):
        now = timezone.now()
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(minutes=2),
            session_active=True,
            download_bps=2_000_000,
            upload_bps=500_000,
            bytes_in=1000,
            bytes_out=5000,
        )
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(minutes=1),
            session_active=True,
            download_bps=3_000_000,
            upload_bps=600_000,
            bytes_in=4000,
            bytes_out=12000,
        )
        payload = usage_trend_payload(self.customer, hours=24, use_cache=False)
        summary = payload["summary"]
        self.assertEqual(summary["tracking"], "ready")
        self.assertIn(summary["status"], {"Surfing", "Not surfing", "Disconnected"})
        self.assertTrue(summary["insight"])
        self.assertIn("download_mbps", payload["series"])
        self.assertIn("surf_state", payload["series"])
        self.assertIn("access", payload)
        self.assertTrue(summary["online_time_label"])

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
        self.assertEqual(len(payload["labels"]), len(payload["series"]["surf_state"]))

    def test_access_timeline_flags_early_offline_before_package_end(self):
        from billing.models import BillingPlan

        now = timezone.now()
        plan = BillingPlan.objects.create(
            organization=self.org,
            name="Hourly early",
            price=10,
            duration=BillingPlan.Duration.HOURLY,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        self.customer.status = Customer.Status.ACTIVE
        self.customer.plan = plan
        self.customer.package_start = now - timezone.timedelta(hours=5)
        self.customer.package_end = now + timezone.timedelta(hours=5)
        self.customer.save(
            update_fields=["status", "plan", "package_start", "package_end"]
        )
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(hours=3),
            session_active=True,
            bytes_in=1000,
            bytes_out=2000,
            download_bps=50000,
            upload_bps=10000,
        )
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(hours=2),
            session_active=False,
            bytes_in=0,
            bytes_out=0,
        )
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(minutes=30),
            session_active=False,
            bytes_in=0,
            bytes_out=0,
        )
        payload = usage_trend_payload(self.customer, hours=6, use_cache=False)
        access = payload["access"]
        kinds = {ev["kind"] for ev in access["events"]}
        self.assertIn("subscription_started", kinds)
        self.assertIn("subscription_ended", kinds)
        self.assertIn("early_offline", kinds)
        self.assertTrue(access["alert"])
        self.assertIn(2, payload["series"]["surf_state"])  # surfing while active
        self.assertEqual(payload["summary"]["access_state"], "disconnected")

    def test_access_timeline_marks_not_surfing_after_deadline(self):
        from billing.models import BillingPlan

        now = timezone.now()
        plan = BillingPlan.objects.create(
            organization=self.org,
            name="Hourly test",
            price=10,
            duration=BillingPlan.Duration.HOURLY,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        self.customer.status = Customer.Status.ACTIVE
        self.customer.plan = plan
        self.customer.package_start = now - timezone.timedelta(hours=10)
        self.customer.package_end = now - timezone.timedelta(hours=2)
        self.customer.save(
            update_fields=["status", "plan", "package_start", "package_end"]
        )
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(minutes=20),
            session_active=True,
            bytes_in=5000,
            bytes_out=8000,
            download_bps=1000,
            upload_bps=500,
        )
        payload = usage_trend_payload(self.customer, hours=6, use_cache=False)
        self.assertEqual(payload["summary"]["access_state"], "not_surfing")
        self.assertIn(1, payload["series"]["surf_state"])
        kinds = {ev["kind"] for ev in payload["access"]["events"]}
        self.assertIn("blocked_connected", kinds)

    def test_multiple_pay_to_start_periods_classify_surfing(self):
        """Expire → pay again must keep earlier surfing classified correctly."""
        from billing.models import BillingPlan, Invoice, Payment

        now = timezone.now()
        plan = BillingPlan.objects.create(
            organization=self.org,
            name="Hourly multi",
            price=10,
            duration=BillingPlan.Duration.HOURLY,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        self.customer.status = Customer.Status.ACTIVE
        self.customer.plan = plan
        first_pay_at = now - timezone.timedelta(hours=5)
        second_pay_at = now - timezone.timedelta(hours=1)
        # Live package is only the latest pay-to-start window.
        self.customer.package_start = second_pay_at
        self.customer.package_end = second_pay_at + timezone.timedelta(hours=1)
        self.customer.save(
            update_fields=["status", "plan", "package_start", "package_end"]
        )

        for stamp, ref in ((first_pay_at, "PAY1"), (second_pay_at, "PAY2")):
            inv = Invoice.objects.create(
                organization=self.org,
                customer=self.customer,
                invoice_number=f"REN-MULTI-{ref}",
                amount=10,
                status=Invoice.Status.PAID,
                due_date=stamp.date(),
                issued_at=stamp,
                paid_at=stamp,
            )
            Payment.objects.create(
                organization=self.org,
                invoice=inv,
                amount=10,
                method=Payment.Method.MPESA,
                reference=ref,
                received_at=stamp,
            )

        # Surfing during the first paid hour (before current package_start).
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=first_pay_at + timezone.timedelta(minutes=20),
            session_active=True,
            bytes_in=1000,
            bytes_out=2000,
            download_bps=50_000,
            upload_bps=10_000,
        )
        # Gap after first expiry, before second payment — should be not surfing.
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=first_pay_at + timezone.timedelta(hours=2),
            session_active=True,
            bytes_in=2000,
            bytes_out=3000,
            download_bps=40_000,
            upload_bps=8_000,
        )
        # Surfing in the second paid hour.
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=second_pay_at + timezone.timedelta(minutes=15),
            session_active=True,
            bytes_in=3000,
            bytes_out=4000,
            download_bps=60_000,
            upload_bps=12_000,
        )

        payload = usage_trend_payload(self.customer, hours=6, use_cache=False)
        access = payload["access"]
        start_events = [
            ev for ev in access["events"] if ev["kind"] == "subscription_started"
        ]
        end_events = [
            ev for ev in access["events"] if ev["kind"] == "subscription_ended"
        ]
        payment_events = [ev for ev in access["events"] if ev["kind"] == "payment"]
        self.assertGreaterEqual(len(payment_events), 2)
        self.assertGreaterEqual(len(start_events), 2)
        self.assertGreaterEqual(len(end_events), 2)
        self.assertGreaterEqual(access.get("period_count") or 0, 2)
        # Chart should show both surfing (2) and not_surfing (1) across periods.
        self.assertIn(2, payload["series"]["surf_state"])
        self.assertIn(1, payload["series"]["surf_state"])

    def test_stacked_payment_marks_subscription_extended(self):
        from billing.models import BillingPlan, Invoice, Payment

        now = timezone.now()
        plan = BillingPlan.objects.create(
            organization=self.org,
            name="Hourly stack",
            price=10,
            duration=BillingPlan.Duration.HOURLY,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        first_pay_at = now - timezone.timedelta(minutes=50)
        second_pay_at = now - timezone.timedelta(minutes=20)
        self.customer.status = Customer.Status.ACTIVE
        self.customer.plan = plan
        self.customer.package_start = first_pay_at
        self.customer.package_end = first_pay_at + timezone.timedelta(hours=2)
        self.customer.save(
            update_fields=["status", "plan", "package_start", "package_end"]
        )

        for stamp, ref in ((first_pay_at, "STACK1"), (second_pay_at, "STACK2")):
            inv = Invoice.objects.create(
                organization=self.org,
                customer=self.customer,
                invoice_number=f"REN-STACK-{ref}",
                amount=10,
                status=Invoice.Status.PAID,
                due_date=stamp.date(),
                issued_at=stamp,
                paid_at=stamp,
            )
            Payment.objects.create(
                organization=self.org,
                invoice=inv,
                amount=10,
                method=Payment.Method.MPESA,
                reference=ref,
                received_at=stamp,
            )

        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(minutes=5),
            session_active=True,
            bytes_in=1000,
            bytes_out=2000,
            download_bps=10_000,
            upload_bps=2_000,
        )
        payload = usage_trend_payload(self.customer, hours=6, use_cache=False)
        labels = [ev["label"] for ev in payload["access"]["events"]]
        self.assertTrue(any("extended" in (label or "").lower() for label in labels))
        self.assertGreaterEqual(
            sum(1 for ev in payload["access"]["events"] if ev["kind"] == "payment"),
            2,
        )

    def test_counter_reset_does_not_spike_data_used(self):
        now = timezone.now()
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(minutes=3),
            session_active=True,
            bytes_in=10_000,
            bytes_out=5_000,
            download_bps=1000,
            upload_bps=500,
        )
        # New session after reconnect — counters restart near zero.
        CustomerUsageSample.objects.create(
            customer=self.customer,
            organization=self.org,
            sampled_at=now - timezone.timedelta(minutes=1),
            session_active=True,
            bytes_in=200,
            bytes_out=100,
            download_bps=800,
            upload_bps=400,
        )
        payload = usage_trend_payload(self.customer, hours=24, use_cache=False)
        # Only growth within a continuous counter series counts; resets do not.
        self.assertEqual(payload["summary"]["data_used_bytes"], 0)

    def test_failed_probe_is_not_recorded_as_offline(self):
        from billing.usage_samples import record_customer_usage_sample

        written = record_customer_usage_sample(
            self.customer,
            {
                "ok": False,
                "session_active": False,
                "error": "Connection timed out reaching the router.",
                "bytes_in": 0,
                "bytes_out": 0,
            },
        )
        self.assertFalse(written)
        self.assertEqual(CustomerUsageSample.objects.filter(customer=self.customer).count(), 0)

    def test_force_bypasses_offline_throttle(self):
        from django.core.cache import cache
        from billing.usage_samples import record_customer_usage_sample

        cache.set(f"usage_sample_offline:{self.customer.pk}", 1, 300)
        blocked = record_customer_usage_sample(
            self.customer,
            {"ok": True, "session_active": False, "bytes_in": 0, "bytes_out": 0},
        )
        self.assertFalse(blocked)
        written = record_customer_usage_sample(
            self.customer,
            {"ok": True, "session_active": False, "bytes_in": 0, "bytes_out": 0},
            force=True,
        )
        self.assertTrue(written)
        self.assertEqual(CustomerUsageSample.objects.filter(customer=self.customer).count(), 1)

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
    def test_records_unassigned_hotspot_by_mac(self, mock_pppoe, mock_hotspot):
        hotspot = Customer.objects.create(
            organization=self.org,
            full_name="Hotspot Roamer",
            phone="0700000199",
            account_number="HS-ROAM-1",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:01",
        )
        mock_pppoe.return_value = {"ok": True, "sessions": {}, "error": ""}
        mock_hotspot.return_value = {
            "ok": True,
            "sessions": {
                "AABBCCDDEE01": {
                    "session_active": True,
                    "bytes_in": 4000,
                    "bytes_out": 9000,
                    "download_bps": 1500,
                    "upload_bps": 400,
                    "uptime_raw": "10m",
                    "address": "10.10.0.9",
                }
            },
            "error": "",
        }
        result = sample_organization_usage(self.org, force=True)
        self.assertTrue(result["ok"])
        sample = (
            CustomerUsageSample.objects.filter(customer=hotspot)
            .order_by("-sampled_at")
            .first()
        )
        self.assertIsNotNone(sample)
        self.assertTrue(sample.session_active)
        self.assertEqual(sample.bytes_out, 9000)

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

    def test_org_payload_ranks_highest_data_usage_first(self):
        now = timezone.now()
        heavy = Customer.objects.create(
            organization=self.org,
            router=self.router,
            full_name="AAA Low Name Heavy Usage",
            phone="0700000199",
            account_number="PPP-HEAVY-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="heavy1",
        )
        light = Customer.objects.create(
            organization=self.org,
            router=self.router,
            full_name="ZZZ High Name Light Usage",
            phone="0700000198",
            account_number="PPP-LIGHT-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="light1",
        )
        for customer, bi0, bo0, bi1, bo1 in (
            (heavy, 1_000, 500, 50_000, 20_000),
            (light, 100, 50, 400, 150),
        ):
            CustomerUsageSample.objects.create(
                customer=customer,
                organization=self.org,
                sampled_at=now - timezone.timedelta(minutes=5),
                session_active=True,
                bytes_in=bi0,
                bytes_out=bo0,
                download_bps=1_000,
                upload_bps=200,
            )
            CustomerUsageSample.objects.create(
                customer=customer,
                organization=self.org,
                sampled_at=now - timezone.timedelta(minutes=1),
                session_active=True,
                bytes_in=bi1,
                bytes_out=bo1,
                download_bps=2_000,
                upload_bps=400,
            )

        payload = org_usage_payload(
            self.org, hours=24, service="pppoe", top_n=0, use_cache=False, auto_widen=False
        )
        self.assertTrue(payload["ok"])
        users = payload["top_users"]
        self.assertGreaterEqual(len(users), 2)
        self.assertEqual(users[0]["customer_id"], heavy.pk)
        self.assertEqual(users[0]["rank"], 1)
        self.assertGreater(users[0]["data_used_bytes"], users[1]["data_used_bytes"])
        heavy_bytes = next(u["data_used_bytes"] for u in users if u["customer_id"] == heavy.pk)
        light_bytes = next(u["data_used_bytes"] for u in users if u["customer_id"] == light.pk)
        self.assertGreater(heavy_bytes, light_bytes)
        self.assertEqual(payload["summary"]["top_user_name"], heavy.full_name)
