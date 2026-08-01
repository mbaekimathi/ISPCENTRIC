from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from accounts.models import Organization, User
from billing.models import Customer, CustomerUsageSample
from billing.usage_samples import parse_uptime_seconds, usage_trend_payload


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
        payload = usage_trend_payload(self.customer, hours=24)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["sample_count"], 2)
        self.assertEqual(payload["summary"]["peak_download_bps"], 2000)
        self.assertEqual(payload["summary"]["data_used_bytes"], 4500)
        self.assertEqual(len(payload["series"]["uptime_minutes"]), 2)
