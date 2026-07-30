from django.test import SimpleTestCase, override_settings

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
        router = _router(vpn_address="10.9.0.3", vpn_private_key=private_key)

        script = wireguard.routeros_script(router)

        self.assertIn(f'private-key="{private_key}"', script)
        self.assertIn(f'public-key="{SERVER_PUBLIC_KEY}"', script)
        self.assertIn("endpoint-address=isp.richcom.co.ke", script)
        self.assertIn("endpoint-port=51820", script)
        self.assertIn("address=10.9.0.3/24", script)
        # The API has to survive the router's input chain to be of any use.
        self.assertIn("dst-port=8728", script)

    @override_settings(WIREGUARD_ENDPOINT="", WIREGUARD_SERVER_PUBLIC_KEY="")
    def test_script_refuses_to_render_without_server_settings(self):
        router = _router(vpn_address="10.9.0.3", vpn_private_key="x")

        with self.assertRaises(ValueError):
            wireguard.routeros_script(router)


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
