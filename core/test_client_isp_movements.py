from datetime import timedelta

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from accounts.models import Organization
from core.client_isp_movements import record_client_isp_movement, record_client_isp_movements
from core.models import ClientIspMovement, MikroTikRouter


class ClientIspMovementRecordTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("move-owner", password="x")
        self.org = Organization.objects.create(
            name="Move ISP",
            owner=self.owner,
            join_code="881122",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Edge",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.9.0.3",
            username="admin",
            password="secret",
        )

    def test_record_skips_same_port(self):
        row = record_client_isp_movement(
            router=self.router,
            from_isp_port="ether1",
            to_isp_port="ether1",
        )
        self.assertIsNone(row)
        self.assertEqual(ClientIspMovement.objects.count(), 0)

    def test_record_writes_movement(self):
        row = record_client_isp_movement(
            router=self.router,
            customer_name="Jane Doe",
            client_ip="10.10.0.5",
            from_isp_port="ether1",
            to_isp_port="ether2",
            source=ClientIspMovement.Source.MANUAL,
            actor=self.owner,
        )
        self.assertIsNotNone(row)
        self.assertEqual(row.to_isp_port, "ether2")
        self.assertEqual(row.source, ClientIspMovement.Source.MANUAL)
        self.assertEqual(row.actor_id, self.owner.pk)

    def test_record_batch(self):
        count = record_client_isp_movements(
            self.router,
            [
                {
                    "customer_id": "",
                    "name": "A",
                    "client_ip": "10.10.0.1",
                    "from_isp": "ether1",
                    "to_isp": "ether2",
                },
                {
                    "customer_id": "",
                    "name": "B",
                    "client_ip": "10.10.0.2",
                    "from_isp": "ether2",
                    "to_isp": "ether1",
                },
            ],
            source=ClientIspMovement.Source.AUTO_REBALANCE,
            imbalance_reason="count",
        )
        self.assertEqual(count, 2)
        self.assertEqual(ClientIspMovement.objects.count(), 2)


class ClientIspMovementViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user("move-view", password="x")
        self.org = Organization.objects.create(
            name="View ISP",
            owner=self.owner,
            join_code="991133",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Edge",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.9.0.4",
            username="admin",
            password="secret",
        )
        self.client.force_login(self.owner)

        old = ClientIspMovement.objects.create(
            organization=self.org,
            router=self.router,
            customer_name="Old move",
            from_isp_port="ether1",
            to_isp_port="ether2",
            source=ClientIspMovement.Source.MANUAL,
        )
        ClientIspMovement.objects.filter(pk=old.pk).update(
            created_at=timezone.now() - timedelta(days=10)
        )
        ClientIspMovement.objects.create(
            organization=self.org,
            router=self.router,
            customer_name="Today move",
            from_isp_port="ether2",
            to_isp_port="ether1",
            source=ClientIspMovement.Source.AUTO_REBALANCE,
        )

    def test_movements_page_filters_by_day(self):
        today = timezone.localdate().isoformat()
        url = reverse(
            "core:mikrotik_assigned_ports_movements",
            args=[self.router.pk],
        )
        response = self.client.get(url, {"range": "day", "day": today})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Today move")
        self.assertNotContains(response, "Old move")

    def test_movements_page_filters_by_source(self):
        url = reverse(
            "core:mikrotik_assigned_ports_movements",
            args=[self.router.pk],
        )
        response = self.client.get(
            url,
            {
                "range": "month",
                "month": timezone.localdate().strftime("%Y-%m"),
                "source": ClientIspMovement.Source.MANUAL,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Old move")
        self.assertNotContains(response, "Today move")
