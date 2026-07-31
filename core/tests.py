from io import StringIO

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings

from core import mikrotik_connect, wireguard
from core.mikrotik_connect import (
    _router_api_host_candidates,
    dial_host,
    on_router_lan,
)
from core.models import MikroTikRouter


SERVER_PUBLIC_KEY = "YT2T/XV2GM3rnkxNPd6b4SFEgQzCScWEfKgSn2J2gWI="


def _router(**kwargs):
    return MikroTikRouter(id=9, name="Site A", host="192.168.1.104", **kwargs)


class WireGuardKeyTests(SimpleTestCase):
    def test_public_key_is_derivable_from_private_key(self):
        private_key, public_key = wireguard.generate_keypair()

        self.assertEqual(wireguard.public_key_for(private_key), public_key)

    @override_settings(
        WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
        WIREGUARD_SUBNET="10.9.0.0/24",
    )
    def test_routeros_script_carries_both_sides_of_the_tunnel(self):
        private_key, _ = wireguard.generate_keypair()

        script = wireguard.routeros_script("10.9.0.3", private_key)

        self.assertIn(f'private-key="{private_key}"', script)
        self.assertIn(f'public-key="{SERVER_PUBLIC_KEY}"', script)
        self.assertIn("endpoint-address=isp.richcom.co.ke", script)
        self.assertIn("endpoint-port=51820", script)
        self.assertIn("address=10.9.0.3/24", script)
        # The API has to survive the router's input chain to be of any use.
        self.assertIn("dst-port=8728", script)

    @override_settings(
        WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
        WIREGUARD_SUBNET="10.9.0.0/24",
    )
    def test_routeros_script_hardens_api_skips_nat_and_verifies_tunnel(self):
        private_key, _ = wireguard.generate_keypair()

        script = wireguard.routeros_script("10.9.0.3", private_key)

        # API must not be open to the public internet.
        self.assertIn(
            "set [find name=api] disabled=no port=8728 "
            "address=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
            script,
        )
        self.assertIn('comment="ispcentric-vpn-api"', script)
        self.assertIn('comment="ispcentric-vpn-icmp"', script)
        # Masquerade must not rewrite sources talking to the billing tunnel.
        self.assertIn('comment="ispcentric-vpn-no-nat"', script)
        self.assertIn("action=accept", script)
        self.assertIn("dst-address=10.9.0.0/24", script)
        # Prove reachability to the VPS tunnel address.
        self.assertIn("/ping 10.9.0.1 count=4", script)
        self.assertIn("ispcentric OK", script)
        self.assertIn("save name=ispcentric-tunnel", script)
        # Idempotent cleanup for re-runs.
        self.assertIn('remove [find comment~"ispcentric-vpn-"]', script)
        # Avoid :local so paste works cleanly in New Terminal.
        self.assertNotIn(":local ", script)
        if_line = next(line for line in script.splitlines() if line.startswith(":if"))
        self.assertIn(
            'do={:put "ispcentric OK: tunnel 10.9.0.3 reaches 10.9.0.1 - Connect in ISPCENTRIC"} else={:put',
            if_line,
        )
        self.assertTrue(if_line.endswith('"}'))
        self.assertEqual(if_line.count("{"), if_line.count("}"))

    @override_settings(WIREGUARD_ENDPOINT="", WIREGUARD_SERVER_PUBLIC_KEY="")
    def test_script_refuses_to_render_without_server_settings(self):
        with self.assertRaises(ValueError):
            wireguard.routeros_script("10.9.0.3", "x")

    def test_placeholder_public_key_is_not_configured(self):
        with override_settings(
            WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
            WIREGUARD_SERVER_PUBLIC_KEY="<public key from wireguard_peer --server-keys>",
        ):
            self.assertFalse(wireguard.configured())

    def test_real_public_key_counts_as_configured(self):
        with override_settings(
            WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
            WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
        ):
            self.assertTrue(wireguard.configured())


@override_settings(
    WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
    WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
    WIREGUARD_SUBNET="10.9.0.0/24",
)
class ReservationTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization

        self.org = Organization.objects.create(
            name="Richcom",
            owner=User.objects.create_user("owner", password="x"),
            join_code="123456",
        )

    def test_reserved_peer_is_adopted_by_the_router_onboarded_onto_it(self):
        from core.models import WireGuardReservation

        call_command("wireguard_peer", new="Kariobangi", stdout=StringIO())
        reservation = WireGuardReservation.objects.get()

        # The operator onboards using the reserved address as the router's host.
        router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Kariobangi",
            model=MikroTikRouter.ModelChoice.HEX,
            host=reservation.address,
            username="admin",
            password="secret",
        )
        call_command("wireguard_peer", router.pk, stdout=StringIO())

        router.refresh_from_db()
        self.assertEqual(router.vpn_address, reservation.address)
        self.assertEqual(router.vpn_private_key, reservation.private_key)
        # The peer now belongs to the router, so it must not be listed twice.
        self.assertFalse(WireGuardReservation.objects.exists())

    def test_a_second_reservation_does_not_reuse_the_first_address(self):
        from core.models import WireGuardReservation

        call_command("wireguard_peer", new="Site A", stdout=StringIO())
        call_command("wireguard_peer", new="Site B", stdout=StringIO())

        addresses = set(WireGuardReservation.objects.values_list("address", flat=True))
        self.assertEqual(addresses, {"10.9.0.2", "10.9.0.3"})

    def test_reserving_the_same_site_twice_keeps_one_peer(self):
        from core.models import WireGuardReservation

        call_command("wireguard_peer", new="Site A", stdout=StringIO())
        call_command("wireguard_peer", new="Site A", stdout=StringIO())

        self.assertEqual(WireGuardReservation.objects.count(), 1)


class RouterDialTargetTests(SimpleTestCase):
    @override_settings(HOSTED=True)
    def test_hosted_prefers_the_tunnel_and_skips_lan_guesses(self):
        hosts = _router_api_host_candidates(_router(vpn_address="10.9.0.3"))

        self.assertFalse(on_router_lan())
        self.assertEqual(hosts[0], "10.9.0.3")
        self.assertNotIn("192.168.88.1", hosts)

    @override_settings(HOSTED=False)
    def test_on_lan_still_falls_back_to_the_default_address(self):
        hosts = _router_api_host_candidates(_router(), candidate_hosts=[])

        self.assertEqual(hosts[0], "192.168.1.104")
        self.assertIn("192.168.88.1", hosts)

    @override_settings(HOSTED=False)
    def test_on_lan_dials_the_saved_address_untouched(self):
        self._set_tunnel_map({"192.168.1.104": "10.9.0.3"})

        self.assertEqual(dial_host("192.168.1.104"), "192.168.1.104")

    @override_settings(HOSTED=True)
    def test_hosted_dials_the_tunnel_for_a_saved_lan_address(self):
        self._set_tunnel_map({"192.168.1.104": "10.9.0.3"})

        self.assertEqual(dial_host("192.168.1.104"), "10.9.0.3")
        self.assertEqual(dial_host("192.168.1.200"), "192.168.1.200")

    def _set_tunnel_map(self, mapping):
        original = mikrotik_connect._TUNNEL_HOST_CACHE
        original_at = mikrotik_connect._TUNNEL_HOST_CACHE_AT
        mikrotik_connect._TUNNEL_HOST_CACHE = mapping
        mikrotik_connect._TUNNEL_HOST_CACHE_AT = float("inf")

        def restore():
            mikrotik_connect._TUNNEL_HOST_CACHE = original
            mikrotik_connect._TUNNEL_HOST_CACHE_AT = original_at

        self.addCleanup(restore)
