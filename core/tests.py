from io import StringIO
import socket
from unittest.mock import patch

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


class MikroTikModelDetectionTests(SimpleTestCase):
    def test_rb951ui_board_is_mapped_to_the_exact_catalog_model(self):
        from core.mikrotik_discovery import guess_model

        self.assertEqual(guess_model("RB951Ui-2HnD"), "rb951ui_2hnd")
        self.assertEqual(guess_model("RB951Ui-2HnD r2"), "rb951ui_2hnd")
        self.assertIn(
            ("rb951ui_2hnd", "RB951Ui-2HnD"),
            MikroTikRouter.ModelChoice.choices,
        )


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

        with patch(
            "core.wireguard.socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("203.0.113.50", 0))],
        ):
            script = wireguard.routeros_script("10.9.0.3", private_key, factory_reset=False)

        self.assertIn(f'private-key="{private_key}"', script)
        self.assertIn(f'public-key="{SERVER_PUBLIC_KEY}"', script)
        self.assertIn("endpoint-address=203.0.113.50", script)
        self.assertNotIn("endpoint-address=isp.richcom.co.ke", script)
        self.assertIn("endpoint-port=51820", script)
        self.assertIn("listen-port=13203", script)
        self.assertIn("address=10.9.0.3/24", script)
        # The API has to survive the router's input chain to be of any use.
        self.assertIn("dst-port=8728", script)

    def test_routeros_script_keeps_literal_ip_endpoint(self):
        with override_settings(WIREGUARD_ENDPOINT="203.0.113.50:51820"):
            private_key, _ = wireguard.generate_keypair()
            script = wireguard.routeros_script("10.9.0.12", private_key, factory_reset=False)
        self.assertIn("endpoint-address=203.0.113.50", script)
        self.assertIn("listen-port=13212", script)

    @override_settings(
        WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
        WIREGUARD_SUBNET="10.9.0.0/24",
    )
    def test_routeros_script_hardens_api_skips_nat_and_verifies_tunnel(self):
        private_key, _ = wireguard.generate_keypair()

        script = wireguard.routeros_script("10.9.0.3", private_key, factory_reset=False)

        # Compulsory API enable — Connect dials 8728 over the tunnel / LAN.
        self.assertIn(
            ':do { /ip service set [find where name=api] disabled=no port=8728 '
            'address=0.0.0.0/0 } on-error={}',
            script,
        )
        self.assertIn(
            ":do { /ip service set api disabled=no port=8728 address=0.0.0.0/0 } "
            "on-error={}",
            script,
        )
        self.assertIn(":do { /ip service enable [find where name=api] } on-error={}", script)
        self.assertIn("[ISPCENTRIC OK] RouterOS API enabled on port 8728", script)
        self.assertIn("name=api and disabled=no and port=8728", script)
        # Hotspot bypass is tunnel-subnet only — never whole customer LAN ranges.
        self.assertIn('comment="ispcentric-vpn-hotspot-bypass"', script)
        self.assertIn("type=bypassed address=10.9.0.0/24", script)
        self.assertNotIn("type=bypassed address=192.168.0.0/16", script)
        self.assertNotIn("type=bypassed address=10.0.0.0/8", script)
        self.assertNotIn("type=bypassed address=172.16.0.0/12", script)
        self.assertNotIn('comment="ispcentric-hotspot-bypass-192"', script)
        self.assertIn(
            ':do { /ip hotspot ip-binding remove [find where comment~"ispcentric-hotspot-bypass"] } '
            "on-error={}",
            script,
        )
        # Firewall (not /ip service address=) keeps API off the public WAN.
        self.assertIn('comment="ispcentric-vpn-api"', script)
        self.assertIn('comment="ispcentric-vpn-api-net"', script)
        self.assertIn('comment="ispcentric-vpn-icmp"', script)
        self.assertIn("in-interface=ispcentric-vpn", script)
        self.assertIn("src-address=10.9.0.0/24", script)
        self.assertIn(
            'comment="ispcentric-vpn-api-lan-192"',
            script,
        )
        self.assertNotIn('place-before=0 comment', script)
        self.assertIn("place-before=([find where chain=input", script)
        # Masquerade must not rewrite sources talking to the billing tunnel.
        self.assertIn('comment="ispcentric-vpn-no-nat"', script)
        self.assertIn("action=accept", script)
        self.assertIn("dst-address=10.9.0.0/24", script)
        # Prove reachability to the VPS tunnel address (retried, one line per paste).
        self.assertIn("/ping 10.9.0.1 count=2", script)
        self.assertIn(":delay 5s", script)
        self.assertIn("/ping 178.162.241.99 count=1", script)
        self.assertIn(":for IspTry from=1 to=12 do={", script)
        self.assertIn("WAN path ready", script)
        self.assertNotIn(":delay 3s :delay 5s", script)
        self.assertIn("[ISPCENTRIC OK] Tunnel 10.9.0.3 reaches billing server", script)
        self.assertIn("[ISPCENTRIC FAIL] No ping from 10.9.0.1", script)
        self.assertIn(
            '[:len [/ip firewall filter find where comment="ispcentric-vpn-api"]] > 0',
            script,
        )
        self.assertIn("[ISPCENTRIC OK] WireGuard interface ispcentric-vpn created", script)
        self.assertIn("[ISPCENTRIC OK] Input firewall rules for API and ICMP installed", script)
        self.assertIn("---------- ISPCENTRIC summary ----------", script)
        self.assertIn("Required: creates ispcentric-vpn", script)
        self.assertIn("save name=ispcentric-tunnel", script)
        # Idempotent cleanup for re-runs.
        self.assertIn(
            '/ip firewall filter remove [find where comment~"ispcentric-vpn-"]',
            script,
        )
        # Avoid :local / multi-line foreach so paste works cleanly in New Terminal.
        self.assertNotIn(":local ", script)
        self.assertNotIn(":foreach ", script)
        ping_checks = [
            line
            for line in script.splitlines()
            if "/ping 10.9.0.1 count=2" in line and line.startswith(":if")
        ]
        self.assertEqual(len(ping_checks), 6)
        self.assertIn(
            '[ISPCENTRIC OK] Tunnel 10.9.0.3 reaches billing server 10.9.0.1 - '
            'click Connect in ISPCENTRIC',
            ping_checks[0],
        )
        self.assertIn("[ISPCENTRIC FAIL] No ping from 10.9.0.1", ping_checks[-1])
        for line in ping_checks:
            self.assertEqual(line.count("{"), line.count("}"))

    @override_settings(
        WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
        WIREGUARD_SUBNET="10.9.0.0/24",
    )
    def test_routeros_script_smart_install_resets_only_when_customized(self):
        private_key, _ = wireguard.generate_keypair()
        with (
            patch(
                "core.wireguard.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("203.0.113.50", 0))],
            ),
            patch(
                "core.wireguard._script_public_base_url",
                return_value="http://isp.richcom.co.ke",
            ),
        ):
            script = wireguard.routeros_script("10.9.0.12", private_key, factory_reset=True)
            install = wireguard.install_rsc_body("10.9.0.12", private_key)
            mac = wireguard.rsc_download_mac("10.9.0.12")
            install_url, _ = wireguard.short_rsc_url("10.9.0.12", "i")
        self.assertIn("one-paste bootstrap", script)
        self.assertTrue(install_url.endswith("/i/"), "trailing slash required (Django 301 breaks fetch)")
        self.assertIn(f"/app/m/10.9.0.12/{mac}/i/", install_url)
        self.assertIn(":local IspUrlInst", script)
        self.assertIn("/tool fetch url=$IspUrlInst", script)
        self.assertIn(":for IspTry from=1 to=8 do={", script)
        self.assertIn(":for IspTry from=1 to=12 do={", script)
        self.assertIn("WAN path ready", script)
        self.assertIn("Fetch try ", script)
        self.assertNotIn("tunnel-rsc/?token=", script)
        self.assertIn("http-header-field=\"Host:isp.richcom.co.ke\"", script)
        self.assertIn("/import file-name=ispcentric-install.rsc", script)
        self.assertIn("dhcp-client add interface=ether1", script)
        self.assertNotIn("/file add name=", script)
        self.assertNotIn("/queue simple", script)
        self.assertNotIn("IspCentricCustom", script)
        self.assertIn(f"/app/m/10.9.0.12/{mac}/p/", install)
        self.assertIn(":global IspCentricCustom 0", install)
        self.assertIn("[:len [/ip hotspot find]] > 0", install)
        self.assertIn("keep-users=yes", install)
        self.assertIn("run-after-reset=flash/ispcentric-post-reset.rsc", install)
        self.assertIn("Clean router - continuing tunnel install (no reset)", install)
        self.assertIn("Custom config - factory reset", install)
        self.assertTrue(wireguard.verify_rsc_download_mac("10.9.0.12", mac))
        self.assertFalse(wireguard.verify_rsc_download_mac("10.9.0.12", "deadbeefdead"))

    @override_settings(
        WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
        WIREGUARD_SUBNET="10.9.0.0/24",
    )
    def test_new_script_removes_every_old_tunnel_component_before_replacing_it(self):
        old_private_key, _ = wireguard.generate_keypair()
        latest_private_key, _ = wireguard.generate_keypair()

        old_script = wireguard.routeros_script("10.9.0.3", old_private_key, factory_reset=False)
        latest_script = wireguard.routeros_script("10.9.0.4", latest_private_key, factory_reset=False)

        self.assertIn(f'private-key="{old_private_key}"', old_script)
        self.assertNotIn(old_private_key, latest_script)
        self.assertIn(f'private-key="{latest_private_key}"', latest_script)
        self.assertIn("address=10.9.0.4/24", latest_script)

        lines = latest_script.splitlines()
        cleanup_lines = [
            '/system script remove [find where name~"ispcentric"]',
            '/ip firewall filter remove [find where comment~"ispcentric-vpn-"]',
            '/ip firewall nat remove [find where comment="ispcentric-vpn-no-nat"]',
            ':do { /ip hotspot ip-binding remove [find where comment~"ispcentric-hotspot-bypass"] } '
            "on-error={}",
            ':do { /ip hotspot ip-binding remove [find where comment~"ispcentric-vpn-hotspot-bypass"] } '
            "on-error={}",
            "/interface wireguard peers remove [find where interface=ispcentric-vpn]",
            "/ip address remove [find where interface=ispcentric-vpn]",
            "/interface wireguard remove [find where name=ispcentric-vpn]",
        ]
        add_interface = next(
            index
            for index, line in enumerate(lines)
            if "/interface wireguard add " in line
        )
        previous_index = -1
        for cleanup in cleanup_lines:
            cleanup_index = next(
                index for index, line in enumerate(lines) if cleanup in line
            )
            self.assertLess(cleanup_index, add_interface)
            self.assertGreater(cleanup_index, previous_index)
            previous_index = cleanup_index

        remove_backup = (
            ':do { /file remove [find where name="ispcentric-tunnel.backup"] } '
            "on-error={}"
        )
        self.assertLess(
            lines.index(remove_backup),
            lines.index("save name=ispcentric-tunnel dont-encrypt=yes"),
        )

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

    def test_sync_command_allows_peer_apply_off_tunnel(self):
        with (
            override_settings(
                WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
                WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
                WIREGUARD_SYNC_COMMAND="sudo /opt/ispcentric/scripts/wireguard_apply_peer.sh",
            ),
            patch("core.wireguard.server_on_tunnel", return_value=False),
        ):
            self.assertTrue(wireguard.can_apply_server_peers())

    def test_without_sync_command_off_tunnel_cannot_apply_peers(self):
        with (
            override_settings(
                WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
                WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
                WIREGUARD_SYNC_COMMAND="",
            ),
            patch("core.wireguard.server_on_tunnel", return_value=False),
        ):
            self.assertFalse(wireguard.can_apply_server_peers())

    def test_ensure_tunnel_runtime_skips_when_unconfigured(self):
        with override_settings(WIREGUARD_ENDPOINT="", WIREGUARD_SERVER_PUBLIC_KEY=""):
            result = wireguard.ensure_tunnel_runtime()
        self.assertTrue(result["skipped"])
        self.assertEqual(result["reason"], "not_configured")

    def test_apply_server_peer_uses_sync_command_when_not_on_tunnel(self):
        with (
            override_settings(
                WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
                WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
                WIREGUARD_SYNC_COMMAND="wg-sync-helper",
            ),
            patch("core.wireguard.server_on_tunnel", return_value=False),
            patch("core.wireguard.subprocess.run") as run,
        ):
            run.return_value.returncode = 0
            run.return_value.stdout = ""
            run.return_value.stderr = ""
            result = wireguard.apply_server_peer(
                "Site A", "10.9.0.8", SERVER_PUBLIC_KEY
            )
        self.assertTrue(result["ok"])
        self.assertTrue(result["runtime"])
        self.assertTrue(run.called)

    def test_boot_tasks_skip_migrate_and_test(self):
        from core.boot import should_start_runtime_tasks

        with patch("core.boot.sys.argv", ["manage.py", "migrate"]):
            self.assertFalse(should_start_runtime_tasks())
        with patch("core.boot.sys.argv", ["manage.py", "test", "core.tests"]):
            self.assertFalse(should_start_runtime_tasks())

    def test_subscription_sweep_startup_is_delayed(self):
        from core.boot import _subscription_sweep_startup_delay_sec

        self.assertGreaterEqual(_subscription_sweep_startup_delay_sec(), 15)

    def test_nas_access_ready_ignores_pending_cpe(self):
        from core.subscription_sync import nas_access_ready

        self.assertFalse(nas_access_ready(None))
        self.assertFalse(nas_access_ready({"ok": False, "allowed": False}))
        self.assertTrue(nas_access_ready({"ok": True, "allowed": True}))
        self.assertTrue(
            nas_access_ready(
                {
                    "ok": False,
                    "allowed": True,
                    "provision": {"ok": True},
                    "cpe_renew_clear_pending": True,
                }
            )
        )
        self.assertFalse(
            nas_access_ready(
                {"ok": False, "allowed": True, "provision": {"ok": False}}
            )
        )


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
    def test_discover_false_skips_lan_discovery_scan(self):
        with patch(
            "core.mikrotik_discovery.discover_mikrotik_devices",
            return_value=[{"ip": "192.168.88.50"}],
        ) as discover:
            hosts = _router_api_host_candidates(
                _router(),
                candidate_hosts=[],
                discover=False,
            )

        discover.assert_not_called()
        self.assertEqual(hosts[0], "192.168.1.104")
        self.assertNotIn("192.168.88.50", hosts)

    @override_settings(HOSTED=False, WIREGUARD_SUBNET="10.9.0.0/24")
    def test_tunnel_saved_host_on_lan_skips_lan_guess(self):
        from core.models import MikroTikRouter

        hosts = _router_api_host_candidates(
            MikroTikRouter(id=9, name="Remote", host="10.9.0.8"),
            discover=False,
        )

        self.assertEqual(hosts, ["10.9.0.8"])
        self.assertNotIn("192.168.88.1", hosts)

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


class AccessPoolHelpersTests(SimpleTestCase):
    def test_pppoe_and_hotspot_pool_detection(self):
        from core.mikrotik_connect import is_hotspot_pool_ip, is_pppoe_pool_ip

        self.assertTrue(is_pppoe_pool_ip("10.20.0.55"))
        self.assertFalse(is_pppoe_pool_ip("10.50.50.55"))
        self.assertTrue(is_hotspot_pool_ip("10.50.50.55"))
        self.assertFalse(is_hotspot_pool_ip("10.20.0.55"))
        self.assertFalse(is_pppoe_pool_ip("not-an-ip"))


class LanInterfaceResolutionTests(SimpleTestCase):
    INTERFACES = [
        {"name": "ether1", "type": "ether"},
        {"name": "ether2", "type": "ether"},
        {"name": "bridge", "type": "bridge"},
    ]

    def _resolve(self, preferred, exclude="ether1"):
        from core.mikrotik_connect import _resolve_lan_interface

        with patch("core.mikrotik_connect._print", return_value=self.INTERFACES):
            return _resolve_lan_interface(object(), preferred, exclude=exclude)

    def test_missing_saved_bridge_falls_back_to_the_real_bridge(self):
        self.assertEqual(self._resolve("bridgeLocal"), "bridge")

    def test_existing_saved_interface_is_kept(self):
        self.assertEqual(self._resolve("ether2"), "ether2")

    def test_wan_interface_is_never_used_as_lan(self):
        with patch(
            "core.mikrotik_connect._print",
            return_value=[{"name": "ether1", "type": "ether"}],
        ):
            from core.mikrotik_connect import _resolve_lan_interface

            self.assertNotEqual(
                _resolve_lan_interface(object(), "ether1", exclude="ether1"),
                "ether1",
            )

    def test_mismatch_error_lists_available_interfaces(self):
        from core.mikrotik_connect import _interface_mismatch_error

        with patch("core.mikrotik_connect._print", return_value=self.INTERFACES):
            message = _interface_mismatch_error(
                object(), "Could not enable Hotspot.", "bridgeLocal"
            )
        self.assertIn("bridgeLocal", message)
        self.assertIn("bridge", message)
        self.assertIn("ether2", message)


class ReachabilityFingerprintTests(SimpleTestCase):
    def _probe(self, identified):
        from unittest.mock import MagicMock

        from core.mikrotik_connect import check_mikrotik_reachable

        def only_web_answers(address, timeout=None):
            if address[1] == 80:
                return MagicMock()
            raise ConnectionRefusedError("refused")

        with (
            patch(
                "core.mikrotik_connect.socket.create_connection",
                side_effect=only_web_answers,
            ),
            patch(
                "core.mikrotik_connect._looks_like_routeros_http",
                return_value=identified,
            ),
            patch("core.mikrotik_connect._icmp_ping", return_value=False),
        ):
            return check_mikrotik_reachable("192.168.88.1", timeout=0.1)

    def test_http_only_host_that_is_not_routeros_is_not_reachable(self):
        result = self._probe(False)

        self.assertFalse(result["online"])
        self.assertTrue(result["foreign_http"])
        self.assertIn("not a MikroTik", result["error"])

    def test_http_only_host_that_is_routeros_stays_reachable(self):
        result = self._probe(True)

        self.assertTrue(result["online"])
        self.assertEqual(result["via"], "http")

    def test_unidentifiable_http_host_is_still_trusted(self):
        result = self._probe(None)

        self.assertTrue(result["online"])
        self.assertEqual(result["via"], "http")

    def test_api_port_returns_without_waiting_for_other_probes(self):
        import time
        from unittest.mock import MagicMock

        from core.mikrotik_connect import check_mikrotik_reachable

        def api_fast_others_slow(address, timeout=None):
            port = address[1]
            if port == 8728:
                return MagicMock()
            time.sleep(0.35)
            raise TimeoutError("timed out")

        started = time.perf_counter()
        with (
            patch(
                "core.mikrotik_connect.socket.create_connection",
                side_effect=api_fast_others_slow,
            ),
            patch("core.mikrotik_connect._icmp_ping", return_value=False),
        ):
            result = check_mikrotik_reachable("192.168.88.1", timeout=0.5)
        elapsed = time.perf_counter() - started

        self.assertTrue(result["online"])
        self.assertEqual(result["via"], "api")
        self.assertLess(elapsed, 0.25)

    def test_hotspot_redirect_page_identifies_the_router(self):
        from core.mikrotik_connect import _looks_like_routeros_http

        # A Hotspot router serves this instead of WebFig on port 80.
        portal = (
            "http/1.1 302 found\r\n"
            "location: http://isp.example.co.ke/hotspot/534970/pay/"
            "?dst=&mac=84%3a2a%3afd&link-login-only=http%3a%2f%2f192.168.88.1%2flogin\r\n"
            "\r\n<html><title>pay to connect</title></html>"
        )
        with patch(
            "core.mikrotik_connect._http_probe_body",
            return_value=portal,
        ):
            self.assertTrue(_looks_like_routeros_http("192.168.88.1", 80))


class HotspotCaptiveLockoutTests(SimpleTestCase):
    def test_refused_api_behind_a_hotspot_portal_explains_the_captive_pc(self):
        from core.mikrotik_connect import recover_mikrotik_connection

        with (
            patch(
                "core.mikrotik_connect.check_mikrotik_reachable",
                return_value={"online": True, "via": "http", "port": 80},
            ),
            patch(
                "core.mikrotik_connect._api_session",
                side_effect=ConnectionRefusedError("refused"),
            ),
            patch(
                "core.mikrotik_connect._serves_hotspot_portal",
                return_value=True,
            ),
        ):
            result = recover_mikrotik_connection(
                "192.168.88.1",
                "admin",
                "secret",
                timeout=0.1,
            )

        self.assertFalse(result["ok"])
        self.assertTrue(result["hotspot_lockout"])
        self.assertIn("not logged in", result["error"])
        self.assertIn("connect by MAC", result["error"])
        self.assertIn("ip-binding", result["error"])
        # The old advice was misleading: the PC is already on the LAN.
        self.assertNotIn("Plug this PC into MikroTik ether2", result["error"])

    def test_refused_api_without_a_portal_still_reports_api_disabled(self):
        from core.mikrotik_connect import recover_mikrotik_connection

        with (
            patch(
                "core.mikrotik_connect.check_mikrotik_reachable",
                return_value={"online": True, "via": "winbox", "port": 8291},
            ),
            patch(
                "core.mikrotik_connect._api_session",
                side_effect=ConnectionRefusedError("refused"),
            ),
            patch(
                "core.mikrotik_connect._serves_hotspot_portal",
                return_value=False,
            ),
        ):
            result = recover_mikrotik_connection(
                "192.168.88.1",
                "admin",
                "secret",
                timeout=0.1,
            )

        self.assertFalse(result["ok"])
        self.assertTrue(result["api_disabled"])
        self.assertIn("IP → Services", result["error"])


class PppoeSecretProfileSyncTests(SimpleTestCase):
    def test_bulk_sync_uses_blocked_profile_for_unpaid_clients(self):
        from core.mikrotik_connect import (
            PPPOE_BLOCKED_PROFILE_NAME,
            PPPOE_PROFILE_NAME,
            _sync_organization_pppoe_secrets_on_socket,
        )

        paid = type(
            "Customer",
            (),
            {
                "pppoe_username": "paid",
                "pppoe_password": "pw",
                "account_number": "A1",
                "status": "active",
                "package_end": timezone_aware_future(),
                "plan": None,
                "organization": type("Org", (), {"pppoe_compulsory": True})(),
                "service_type": "pppoe",
                "router_id": 1,
            },
        )()
        unpaid = type(
            "Customer",
            (),
            {
                "pppoe_username": "unpaid",
                "pppoe_password": "pw",
                "account_number": "A2",
                "status": "active",
                "package_end": None,
                "plan": None,
                "organization": type("Org", (), {"pppoe_compulsory": True})(),
                "service_type": "pppoe",
                "router_id": 1,
            },
        )()

        captured = []

        def fake_ensure(sock, **kwargs):
            captured.append(kwargs)
            return "updated"

        router = type("Router", (), {"pk": 1})()
        with (
            patch(
                "core.mikrotik_connect._pppoe_customers_for_router",
                return_value=[paid, unpaid],
            ),
            patch(
                "core.mikrotik_connect._ensure_ppp_secret",
                side_effect=fake_ensure,
            ),
            patch(
                "core.mikrotik_connect._current_ppp_secret_profile",
                return_value=PPPOE_PROFILE_NAME,
            ),
            patch("core.mikrotik_connect._disconnect_pppoe_sessions", return_value=0),
        ):
            synced = _sync_organization_pppoe_secrets_on_socket(object(), router)

        self.assertEqual(synced, 2)
        by_user = {item["username"]: item["profile"] for item in captured}
        self.assertEqual(by_user["paid"], PPPOE_PROFILE_NAME)
        self.assertEqual(by_user["unpaid"], PPPOE_BLOCKED_PROFILE_NAME)


def timezone_aware_future():
    from datetime import timedelta

    from django.utils import timezone

    return timezone.localtime() + timedelta(days=1)


class CaptiveOrganizationResolutionTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization

        self.org_hotspot = Organization.objects.create(
            name="Hotspot Org",
            owner=User.objects.create_user("owner-hs", password="x"),
            join_code="101010",
            hotspot_enabled=True,
            pppoe_compulsory=False,
        )
        self.org_pppoe = Organization.objects.create(
            name="PPPoE Org",
            owner=User.objects.create_user("owner-pp", password="x"),
            join_code="202020",
            hotspot_enabled=False,
            pppoe_compulsory=True,
        )

    def test_fallback_prefers_hotspot_enabled_org(self):
        from core.mikrotik_connect import _fallback_captive_organization

        org = _fallback_captive_organization()
        self.assertEqual(org.pk, self.org_hotspot.pk)

    def test_single_captive_org_shortcut(self):
        from core.mikrotik_connect import resolve_captive_organization

        self.org_hotspot.hotspot_enabled = False
        self.org_hotspot.save(update_fields=["hotspot_enabled"])
        org = resolve_captive_organization("192.168.88.50")
        self.assertEqual(org.pk, self.org_pppoe.pk)

    def test_cpe_renew_pool_resolves_org_from_cached_pppoe_session(self):
        from billing.models import Customer
        from core.mikrotik_connect import (
            remember_pppoe_customer_session_ip,
            resolve_captive_organization,
        )

        customer = Customer.objects.create(
            organization=self.org_pppoe,
            full_name="Renew WiFi",
            phone="254700000099",
            account_number="PPP-RENEW",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="renew99",
            status=Customer.Status.ACTIVE,
        )
        remember_pppoe_customer_session_ip(customer, "192.168.189.44")
        org = resolve_captive_organization("192.168.189.44")
        self.assertEqual(org.pk, self.org_pppoe.pk)

    def test_multi_tenant_unmatched_ip_does_not_guess_org(self):
        from core.mikrotik_connect import resolve_captive_organization

        # Both orgs are captive candidates; unmatched LAN IP must not pick the
        # first Hotspot org (wrong join_code).
        self.assertIsNone(resolve_captive_organization("192.168.88.50"))
        self.assertIsNone(resolve_captive_organization(""))


class CaptiveRedirectCacheTests(SimpleTestCase):
    def test_invalidate_bumps_redirect_generation(self):
        from django.core.cache import cache

        from core.mikrotik_connect import (
            captive_redirect_cache_key,
            invalidate_captive_redirect_cache,
        )

        cache.clear()
        first = captive_redirect_cache_key("10.20.0.44", "")
        invalidate_captive_redirect_cache("10.20.0.44")
        second = captive_redirect_cache_key("10.20.0.44", "")
        self.assertNotEqual(first, second)


class PayPagePoolMismatchGuardTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization

        self.org = Organization.objects.create(
            name="Pool Guard Org",
            owner=User.objects.create_user("owner-pool-guard", password="x"),
            join_code="424242",
            hotspot_enabled=True,
            pppoe_compulsory=True,
        )

    def test_pppoe_pay_redirects_hotspot_pool_client(self):
        response = self.client.get(
            f"/pppoe/{self.org.join_code}/pay/?mac=AABBCCDDEEFF",
            REMOTE_ADDR="10.50.50.99",
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/hotspot/{self.org.join_code}/pay/", response.url)
        self.assertIn("mac=AABBCCDDEEFF", response.url)

    def test_hotspot_pay_redirects_pppoe_pool_client(self):
        response = self.client.get(
            f"/hotspot/{self.org.join_code}/pay/?account=PPP-1",
            REMOTE_ADDR="10.20.0.44",
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/pppoe/{self.org.join_code}/pay/", response.url)
        self.assertIn("account=PPP-1", response.url)

    def test_hotspot_pay_redirects_cpe_renew_pool_client(self):
        response = self.client.get(
            f"/hotspot/{self.org.join_code}/pay/",
            REMOTE_ADDR="192.168.189.22",
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/pppoe/{self.org.join_code}/pay/", response.url)


class CaptiveProbeMiddlewareTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization

        self.org = Organization.objects.create(
            name="Probe Org",
            owner=User.objects.create_user("owner-probe", password="x"),
            join_code="303030",
            hotspot_enabled=True,
            pppoe_compulsory=True,
        )

    @override_settings(PUBLIC_BASE_URL="http://billing.example:8000")
    def test_hotspot_probe_redirects_to_org_pay_page(self):
        from django.http import HttpResponse
        from django.test import RequestFactory

        from ispcentric.middleware import HotspotCaptiveProbeMiddleware

        def get_response(_request):
            return HttpResponse("ok")

        middleware = HotspotCaptiveProbeMiddleware(get_response)
        request = RequestFactory().get(
            "/generate_204",
            HTTP_HOST="connectivitycheck.gstatic.com",
            REMOTE_ADDR="10.50.50.20",
        )
        response = middleware(request)
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/hotspot/{self.org.join_code}/pay/", response.url)

    @override_settings(PUBLIC_BASE_URL="http://billing.example:8000")
    def test_hotspot_probe_attaches_mac_when_host_known(self):
        from django.core.cache import cache
        from django.http import HttpResponse
        from django.test import RequestFactory
        from unittest.mock import patch
        from urllib.parse import parse_qs, urlparse

        from ispcentric.middleware import HotspotCaptiveProbeMiddleware

        cache.clear()

        def get_response(_request):
            return HttpResponse("ok")

        middleware = HotspotCaptiveProbeMiddleware(get_response)
        request = RequestFactory().get(
            "/generate_204",
            HTTP_HOST="connectivitycheck.gstatic.com",
            REMOTE_ADDR="10.50.50.20",
        )
        with patch(
            "core.mikrotik_connect.resolve_captive_organization",
            return_value=self.org,
        ), patch(
            "core.mikrotik_connect.find_hotspot_mac_for_ip",
            return_value="AA:BB:CC:DD:EE:20",
        ):
            response = middleware(request)

        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/hotspot/{self.org.join_code}/pay/", response.url)
        mac = parse_qs(urlparse(response.url).query).get("mac", [""])[0]
        self.assertEqual(mac, "AA:BB:CC:DD:EE:20")

    @override_settings(PUBLIC_BASE_URL="http://billing.example:8000")
    def test_pppoe_pool_probe_redirects_to_pppoe_pay_page(self):
        from django.http import HttpResponse
        from django.test import RequestFactory

        from ispcentric.middleware import HotspotCaptiveProbeMiddleware

        def get_response(_request):
            return HttpResponse("ok")

        middleware = HotspotCaptiveProbeMiddleware(get_response)
        request = RequestFactory().get(
            "/redirect",
            HTTP_HOST="www.msftconnecttest.com",
            REMOTE_ADDR="10.20.0.44",
        )
        response = middleware(request)
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/pppoe/{self.org.join_code}/pay/", response.url)

    @override_settings(PUBLIC_BASE_URL="http://billing.example:8000")
    def test_cpe_renew_pool_probe_redirects_to_pppoe_pay_page(self):
        """Phones on expired CPE renew Wi‑Fi must renew on /pppoe/…/pay/, not Hotspot."""
        from django.core.cache import cache
        from django.http import HttpResponse
        from django.test import RequestFactory
        from unittest.mock import patch

        from ispcentric.middleware import HotspotCaptiveProbeMiddleware

        cache.clear()

        def get_response(_request):
            return HttpResponse("ok")

        middleware = HotspotCaptiveProbeMiddleware(get_response)
        request = RequestFactory().get(
            "/generate_204",
            HTTP_HOST="connectivitycheck.gstatic.com",
            REMOTE_ADDR="192.168.189.44",
        )
        with patch(
            "core.mikrotik_connect.resolve_captive_organization",
            return_value=self.org,
        ), patch(
            "core.mikrotik_connect.find_pppoe_customer_for_ip",
            return_value=None,
        ):
            response = middleware(request)
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/pppoe/{self.org.join_code}/pay/", response.url)
        self.assertNotIn("/hotspot/", response.url)

    @override_settings(PUBLIC_BASE_URL="http://billing.example:8000")
    def test_known_pppoe_customer_prefers_pppoe_even_outside_pool(self):
        from django.core.cache import cache
        from django.http import HttpResponse
        from django.test import RequestFactory
        from unittest.mock import patch

        from billing.models import Customer
        from ispcentric.middleware import HotspotCaptiveProbeMiddleware

        cache.clear()
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Known PPPoE",
            phone="254700000055",
            account_number="PPP-055",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="user055",
            status=Customer.Status.ACTIVE,
        )

        def get_response(_request):
            return HttpResponse("ok")

        middleware = HotspotCaptiveProbeMiddleware(get_response)
        # Not in 10.20.0.0/24 or renew pool — but IP maps to a PPPoE customer.
        request = RequestFactory().get(
            "/generate_204",
            HTTP_HOST="connectivitycheck.gstatic.com",
            REMOTE_ADDR="10.50.50.77",
        )
        with patch(
            "core.mikrotik_connect.resolve_captive_organization",
            return_value=self.org,
        ), patch(
            "core.mikrotik_connect.find_pppoe_customer_for_ip",
            return_value=customer,
        ):
            response = middleware(request)
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/pppoe/{self.org.join_code}/pay/", response.url)
        self.assertIn("t=", response.url)
        self.assertNotIn("/hotspot/", response.url)

    @override_settings(PUBLIC_BASE_URL="http://billing.example:8000")
    def test_pppoe_pool_probe_attaches_account_token_when_customer_known(self):
        from django.core import signing
        from django.core.cache import cache
        from django.http import HttpResponse
        from django.test import RequestFactory
        from unittest.mock import patch
        from urllib.parse import parse_qs, urlparse

        from billing.models import Customer
        from ispcentric.middleware import HotspotCaptiveProbeMiddleware

        cache.clear()
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Expired PPPoE",
            phone="254700000044",
            account_number="PPP-044",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="user044",
            status=Customer.Status.ACTIVE,
        )

        def get_response(_request):
            return HttpResponse("ok")

        middleware = HotspotCaptiveProbeMiddleware(get_response)
        request = RequestFactory().get(
            "/redirect",
            HTTP_HOST="www.msftconnecttest.com",
            REMOTE_ADDR="10.20.0.44",
        )
        with patch(
            "core.mikrotik_connect.resolve_captive_organization",
            return_value=self.org,
        ), patch(
            "core.mikrotik_connect.find_pppoe_customer_for_ip",
            return_value=customer,
        ):
            response = middleware(request)

        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/pppoe/{self.org.join_code}/pay/", response.url)
        self.assertIn("t=", response.url)
        token = parse_qs(urlparse(response.url).query).get("t", [""])[0]
        payload = signing.loads(token, salt="pppoe-payment", max_age=60 * 60)
        self.assertEqual(payload["cid"], customer.pk)
        self.assertEqual(payload["org"], self.org.pk)
        self.assertEqual(payload["mode"], "pppoe")

    @override_settings(PUBLIC_BASE_URL="http://billing.example:8000")
    def test_repeated_probe_uses_redirect_cache(self):
        from django.core.cache import cache
        from django.http import HttpResponse
        from django.test import RequestFactory
        from unittest.mock import patch

        from ispcentric.middleware import HotspotCaptiveProbeMiddleware

        cache.clear()

        def get_response(_request):
            return HttpResponse("ok")

        middleware = HotspotCaptiveProbeMiddleware(get_response)
        request = RequestFactory().get(
            "/generate_204",
            HTTP_HOST="connectivitycheck.gstatic.com",
            REMOTE_ADDR="10.50.50.33",
        )
        with patch(
            "core.mikrotik_connect.resolve_captive_organization",
            return_value=self.org,
        ) as resolve:
            first = middleware(request)
            second = middleware(request)
        self.assertEqual(first.status_code, 302)
        self.assertEqual(second.status_code, 302)
        self.assertEqual(first.url, second.url)
        self.assertEqual(resolve.call_count, 1)

    @override_settings(PUBLIC_BASE_URL="http://billing.example:8000")
    def test_host_rewrite_still_redirects_android_probe(self):
        """
        CaptiveHostRewrite runs first and replaces Host with PUBLIC_BASE_URL.
        Probe middleware must still 302 using the preserved original host —
        otherwise phones never open the pay page after PPPoE expiry.
        """
        from django.core.cache import cache
        from django.http import HttpResponse
        from django.test import RequestFactory

        from ispcentric.middleware import (
            CaptiveHostRewriteMiddleware,
            HotspotCaptiveProbeMiddleware,
        )

        cache.clear()

        def get_response(_request):
            return HttpResponse("ok")

        probe = HotspotCaptiveProbeMiddleware(get_response)
        rewrite = CaptiveHostRewriteMiddleware(probe)
        request = RequestFactory().get(
            "/generate_204",
            HTTP_HOST="connectivitycheck.gstatic.com",
            REMOTE_ADDR="10.20.0.88",
        )
        response = rewrite(request)
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/pppoe/{self.org.join_code}/pay/", response.url)
        self.assertEqual(
            getattr(request, "captive_original_host", ""),
            "connectivitycheck.gstatic.com",
        )

    @override_settings(PUBLIC_BASE_URL="http://billing.example:8000")
    def test_mobile_oem_probe_hosts_redirect(self):
        from django.core.cache import cache
        from django.http import HttpResponse
        from django.test import RequestFactory
        from unittest.mock import patch

        from ispcentric.middleware import HotspotCaptiveProbeMiddleware

        cache.clear()

        def get_response(_request):
            return HttpResponse("ok")

        middleware = HotspotCaptiveProbeMiddleware(get_response)
        cases = (
            ("connectivitycheck.android.com", "/generate_204", "10.50.50.40"),
            ("captive.apple.com", "/hotspot-detect.html", "10.50.50.41"),
            ("www.appleiphonecell.com", "/library/test/success.html", "10.50.50.42"),
            ("connectivitycheck.platform.hicloud.com", "/generate_204", "10.50.50.43"),
        )
        with patch(
            "core.mikrotik_connect.resolve_captive_organization",
            return_value=self.org,
        ):
            for host, path, remote in cases:
                cache.clear()
                request = RequestFactory().get(
                    path, HTTP_HOST=host, REMOTE_ADDR=remote
                )
                response = middleware(request)
                self.assertEqual(response.status_code, 302, msg=host)
                self.assertIn(
                    f"/hotspot/{self.org.join_code}/pay/",
                    response.url,
                    msg=host,
                )

    @override_settings(PUBLIC_BASE_URL="http://billing.example:8000")
    def test_pppoe_pool_any_http_path_redirects_after_host_rewrite(self):
        """Expired PPPoE dst-nat lands every :80 request on Django — redirect all."""
        from django.core.cache import cache
        from django.http import HttpResponse
        from django.test import RequestFactory

        from ispcentric.middleware import (
            CaptiveHostRewriteMiddleware,
            HotspotCaptiveProbeMiddleware,
        )

        cache.clear()

        def get_response(_request):
            return HttpResponse("ok")

        stack = CaptiveHostRewriteMiddleware(HotspotCaptiveProbeMiddleware(get_response))
        request = RequestFactory().get(
            "/some/random/site",
            HTTP_HOST="example.com",
            REMOTE_ADDR="10.20.0.99",
        )
        response = stack(request)
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/pppoe/{self.org.join_code}/pay/", response.url)


class HotspotAuthorizeFastPathTests(TestCase):
    def setUp(self):
        from datetime import timedelta

        from django.contrib.auth.models import User
        from django.utils import timezone

        from accounts.models import Organization
        from billing.models import Customer

        self.owner = User.objects.create_user("hs-fast-owner", password="x")
        self.org = Organization.objects.create(
            name="Fast Hotspot ISP",
            owner=self.owner,
            join_code="778899",
            hotspot_enabled=True,
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Fast NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="192.168.88.1",
            username="admin",
            password="secret",
        )
        now = timezone.now()
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Phone",
            phone="0700000000",
            account_number="HOT-FAST-1",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:FF",
            status=Customer.Status.ACTIVE,
            router=self.router,
            package_start=now,
            package_end=now + timedelta(hours=1),
        )

    def test_warm_stack_skips_full_hotspot_push(self):
        from unittest.mock import patch

        from core.mikrotik_connect import (
            _mark_hotspot_stack_ready,
            authorize_hotspot_customer,
        )

        _mark_hotspot_stack_ready(self.router.pk)
        with (
            patch("core.mikrotik_connect.socket.create_connection"),
            patch("core.mikrotik_connect.check_mikrotik_reachable") as reachable,
            patch("core.mikrotik_connect._api_session"),
            patch(
                "core.mikrotik_connect._apply_hotspot_customer_on_socket",
                return_value={
                    "ok": True,
                    "profile": "ispcentric-hs-5u-10d",
                    "rate_limit": "5M/10M",
                },
            ) as apply_one,
            patch("core.mikrotik_connect.apply_hotspot_on_router") as full_push,
        ):
            result = authorize_hotspot_customer(
                self.customer, router=self.router, reauthenticate=False
            )
        self.assertTrue(result.get("ok"))
        self.assertTrue(result.get("fast_path"))
        apply_one.assert_called_once()
        full_push.assert_not_called()
        reachable.assert_not_called()

    def test_warm_authorize_probes_tcp_once_without_full_scan(self):
        from unittest.mock import patch

        from core.mikrotik_connect import (
            _mark_hotspot_stack_ready,
            authorize_hotspot_customer,
        )

        _mark_hotspot_stack_ready(self.router.pk)
        with (
            patch(
                "core.mikrotik_connect.socket.create_connection"
            ) as tcp,
            patch("core.mikrotik_connect.check_mikrotik_reachable") as reachable,
            patch("core.mikrotik_connect._api_session"),
            patch(
                "core.mikrotik_connect._apply_hotspot_customer_on_socket",
                return_value={
                    "ok": True,
                    "profile": "ispcentric-hs-5u-10d",
                    "rate_limit": "5M/10M",
                },
            ),
        ):
            authorize_hotspot_customer(
                self.customer, router=self.router, reauthenticate=False
            )
        reachable.assert_not_called()
        self.assertGreaterEqual(tcp.call_count, 1)

    def test_offline_router_authorize_is_skipped_not_failed(self):
        from unittest.mock import patch

        from core.mikrotik_connect import (
            _mark_hotspot_stack_ready,
            authorize_hotspot_customer,
        )

        _mark_hotspot_stack_ready(self.router.pk)
        with (
            patch(
                "core.mikrotik_connect.socket.create_connection",
                side_effect=TimeoutError("offline"),
            ),
            patch(
                "core.mikrotik_connect._api_session",
                side_effect=TimeoutError("offline"),
            ),
        ):
            result = authorize_hotspot_customer(
                self.customer, router=self.router, reauthenticate=False
            )
        self.assertTrue(result.get("skipped"))
        self.assertTrue(result.get("timeout"))

    def test_renew_skips_pppoe_ensure_stack(self):
        from unittest.mock import patch

        from billing.models import Customer
        from core.mikrotik_connect import sync_customer_subscription_access

        pppoe = Customer.objects.create(
            organization=self.org,
            full_name="Dialer",
            phone="0700000001",
            account_number="PPP-FAST-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="user1",
            pppoe_password="pass1",
            status=Customer.Status.ACTIVE,
            router=self.router,
            package_start=self.customer.package_start,
            package_end=self.customer.package_end,
        )
        with (
            patch(
                "core.mikrotik_connect.provision_customer_pppoe",
                return_value={"ok": True, "profile": "default"},
            ) as provision,
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
                return_value={"ok": True, "enabled": False},
            ),
        ):
            sync_customer_subscription_access(pppoe, provision=True)
        self.assertTrue(provision.called)
        self.assertFalse(provision.call_args.kwargs.get("ensure_stack"))

    def test_expiry_enables_cpe_renew_portal_before_block(self):
        from datetime import timedelta
        from unittest.mock import patch

        from django.utils import timezone

        from billing.models import Customer
        from core.mikrotik_connect import (
            PPPOE_BLOCKED_PROFILE_NAME,
            sync_customer_subscription_access,
        )

        pppoe = Customer.objects.create(
            organization=self.org,
            full_name="Expired Dialer",
            phone="0700000002",
            account_number="PPP-EXP-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="expired1",
            pppoe_password="pass1",
            status=Customer.Status.ACTIVE,
            router=self.router,
            package_start=timezone.now() - timedelta(days=3),
            package_end=timezone.now() - timedelta(days=1),
        )
        order = []

        def portal_side_effect(customer, *, enabled, portal_url=""):
            order.append(("portal", enabled))
            return {"ok": True, "enabled": enabled}

        def provision_side_effect(customer, **kwargs):
            order.append(("provision", kwargs.get("force_disabled")))
            return {"ok": True, "profile": PPPOE_BLOCKED_PROFILE_NAME}

        with (
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
                side_effect=portal_side_effect,
            ),
            patch(
                "core.mikrotik_connect.provision_customer_pppoe",
                side_effect=provision_side_effect,
            ),
        ):
            result = sync_customer_subscription_access(pppoe, provision=True)

        self.assertFalse(result.get("allowed"))
        self.assertEqual(order[0], ("portal", True))
        self.assertEqual(order[1], ("provision", False))
        self.assertTrue(result.get("portal", {}).get("ok"))

    def test_restore_clears_cpe_renew_portal_before_provision(self):
        """Paid period restore must remove the CPE WAN-block while PPP is still up."""
        from datetime import timedelta
        from unittest.mock import patch

        from django.utils import timezone

        from billing.models import Customer
        from core.mikrotik_connect import sync_customer_subscription_access

        pppoe = Customer.objects.create(
            organization=self.org,
            full_name="Restored Dialer",
            phone="0700000003",
            account_number="PPP-OK-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="restored1",
            pppoe_password="pass1",
            status=Customer.Status.ACTIVE,
            router=self.router,
            package_start=timezone.now() - timedelta(hours=1),
            package_end=timezone.now() + timedelta(days=1),
        )
        order = []

        def portal_side_effect(customer, *, enabled, portal_url=""):
            order.append(("portal", enabled))
            return {"ok": True, "enabled": enabled}

        def provision_side_effect(customer, **kwargs):
            order.append(("provision", kwargs.get("force_disabled")))
            return {"ok": True, "profile": "ispcentric-pppoe-5u-10d"}

        with (
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
                side_effect=portal_side_effect,
            ),
            patch(
                "core.mikrotik_connect.provision_customer_pppoe",
                side_effect=provision_side_effect,
            ),
        ):
            result = sync_customer_subscription_access(pppoe, provision=True)

        self.assertTrue(result.get("allowed"))
        self.assertEqual(order[0], ("portal", False))
        self.assertEqual(order[1], ("provision", False))
        self.assertTrue(result.get("portal", {}).get("ok"))


class CaptiveGatewayHostTests(TestCase):
    """Opening the router IP must show the portal, not a 400 error page."""

    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization

        self.org = Organization.objects.create(
            name="Gateway Org",
            owner=User.objects.create_user("owner-gateway", password="x"),
            join_code="313131",
            hotspot_enabled=True,
            pppoe_compulsory=True,
        )

    @override_settings(
        PUBLIC_BASE_URL="http://192.168.88.254:8000",
        ALLOWED_HOSTS=["192.168.88.254", "localhost"],
        HOSTED=False,
    )
    def test_gateway_ip_host_is_rewritten_and_redirected(self):
        with patch(
            "core.hotspot_portal.local_ipv4_addresses",
            return_value={"192.168.88.254"},
        ):
            response = self.client.get(
                "/generate_204",
                HTTP_HOST="192.168.88.1",
                REMOTE_ADDR="192.168.88.77",
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/hotspot/{self.org.join_code}/pay/", response.url)

    @override_settings(ALLOWED_HOSTS=["192.168.88.254"])
    def test_allowed_private_host_is_left_alone(self):
        from ispcentric.middleware import _is_unlisted_private_host

        self.assertFalse(_is_unlisted_private_host("192.168.88.254"))
        self.assertFalse(_is_unlisted_private_host("billing.example.com"))
        self.assertTrue(_is_unlisted_private_host("192.168.88.1"))


class HotspotPortalContextTests(SimpleTestCase):
    def test_payment_form_shows_when_mac_present_without_link_login(self):
        from django.test import RequestFactory

        from core.views import _hotspot_portal_context

        org = type(
            "Org",
            (),
            {
                "name": "Portal ISP",
                "join_code": "404040",
                "hotspot_portal_title": "",
                "hotspot_login_message": "",
                "mpesa_payment_type": "paybill",
                "mpesa_number": "123456",
                "mpesa_account": "",
                "pppoe_compulsory": False,
                "effective_daraja_credentials": lambda self: {"ready": True},
                "pk": 1,
            },
        )()
        request = RequestFactory().get("/hotspot/404040/pay/", {"mac": "AABBCCDDEEFF"})
        with (
            patch("billing.services.plans_for_router", return_value=[]),
            patch("core.views._find_hotspot_customer_for_mac", return_value=None),
            patch(
                "core.mikrotik_connect.find_hotspot_router_for_mac",
                return_value=None,
            ),
        ):
            ctx = _hotspot_portal_context(org, mikrotik_login=False, request=request)
        self.assertTrue(ctx["show_payment_form"])
        self.assertEqual(ctx["hotspot_mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(ctx["portal_mode"], "hotspot")


class PppoeRouterFallbackTests(TestCase):
    """A client with no router FK must still provision on the org's only NAS."""

    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization
        from billing.models import Customer

        self.owner = User.objects.create_user("fallback-owner", password="x")
        self.org = Organization.objects.create(
            name="Fallback ISP",
            owner=self.owner,
            join_code="776655",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Only NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="192.168.88.1",
            username="admin",
            password="secret",
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="No Router Client",
            phone="254700000077",
            account_number="FB-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="fbuser",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            router=None,
        )

    def test_single_org_router_is_used_instead_of_erroring(self):
        from core.mikrotik_connect import provision_customer_pppoe

        with patch("core.mikrotik_connect._api_session") as session:
            session.side_effect = OSError("router offline")
            result = provision_customer_pppoe(self.customer, ensure_stack=False)

        # The router was resolved, so the failure is a reachability error rather
        # than the "assign a MikroTik router" bail-out that skipped the push.
        self.assertFalse(result["ok"])
        self.assertNotIn("Assign a MikroTik router", result.get("error", ""))
        self.assertEqual(result.get("router_id"), self.router.pk)

    def test_error_still_raised_when_org_has_no_router(self):
        from core.mikrotik_connect import provision_customer_pppoe

        MikroTikRouter.objects.filter(pk=self.router.pk).delete()
        self.customer.refresh_from_db()

        result = provision_customer_pppoe(self.customer, ensure_stack=False)

        self.assertFalse(result["ok"])
        self.assertIn("Assign a MikroTik router", result["error"])


class FastPppoeProvisionTests(TestCase):
    """Registration pushes only /ppp/secret — no full stack rebuild."""

    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization
        from billing.models import Customer

        self.owner = User.objects.create_user("fast-pppoe-owner", password="x")
        self.org = Organization.objects.create(
            name="Fast PPPoE ISP",
            owner=self.owner,
            join_code="112233",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Edge NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.9.0.8",
            username="admin",
            password="secret",
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="FAST CLIENT",
            phone="254711223344",
            account_number="254711223344",
            house_number="B12",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="254711223344",
            pppoe_password="dialpass",
            status=Customer.Status.ACTIVE,
            router=self.router,
        )

    def _capture_discover(self, *, ensure_stack: bool) -> bool:
        captured = {}

        def fake_candidates(router, candidate_hosts=None, *, discover=True):
            captured["discover"] = discover
            return []

        original = mikrotik_connect._router_api_host_candidates
        mikrotik_connect._router_api_host_candidates = fake_candidates
        try:
            mikrotik_connect.provision_customer_pppoe(
                self.customer,
                ensure_stack=ensure_stack,
            )
        finally:
            mikrotik_connect._router_api_host_candidates = original
        return bool(captured.get("discover"))

    def test_ensure_stack_false_disables_host_discovery(self):
        self.assertFalse(self._capture_discover(ensure_stack=False))

    def test_ensure_stack_true_keeps_host_discovery(self):
        self.assertTrue(self._capture_discover(ensure_stack=True))


class PppoeClientRegisterFormTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization

        self.owner = User.objects.create_user("form-pppoe-owner", password="x")
        self.org = Organization.objects.create(
            name="Form PPPoE ISP",
            owner=self.owner,
            join_code="998877",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Form NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.9.0.9",
            username="admin",
            password="secret",
        )

    def test_uppercases_fields_autofills_username_and_saves_house_number(self):
        from billing.forms import PppoeClientRegisterForm
        from billing.models import Customer

        form = PppoeClientRegisterForm(
            {
                "full_name": "jane doe",
                "phone": "0711223344",
                "email": "Jane@Example.COM",
                "router": str(self.router.pk),
                "address": "ngong road",
                "house_number": "a-14",
                "plan": "",
                "pppoe_username": "",
                "pppoe_password": "secret1",
                "cpe_username": "admin",
                "cpe_password": "",
            },
            organization=self.org,
        )
        self.assertTrue(form.is_valid(), form.errors)
        customer = form.save()
        self.assertEqual(customer.full_name, "JANE DOE")
        self.assertEqual(customer.phone, "0711223344")
        self.assertEqual(customer.email, "jane@example.com")
        self.assertEqual(customer.address, "NGONG ROAD")
        self.assertEqual(customer.house_number, "A-14")
        self.assertEqual(customer.pppoe_username, "0711223344")
        self.assertEqual(customer.router_id, self.router.pk)
        self.assertEqual(customer.service_type, Customer.ServiceType.PPPOE)


class MyClientsRegisterViewTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization

        self.owner = User.objects.create_user("clients-owner", password="x")
        self.org = Organization.objects.create(
            name="Clients ISP",
            owner=self.owner,
            join_code="556677",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Clients NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.9.0.10",
            username="admin",
            password="secret",
        )
        self.client.force_login(self.owner)

    def test_register_saves_immediately_and_provisions_in_background(self):
        from billing.models import Customer

        started = []

        class FakeThread:
            def __init__(self, target=None, daemon=None):
                self.target = target
                self.daemon = daemon

            def start(self):
                started.append(self)

        with (
            patch("core.views.threading.Thread", FakeThread),
            patch(
                "core.views.provision_customer_pppoe",
                return_value={"ok": True, "message": "pushed"},
            ) as provision,
        ):
            response = self.client.post(
                "/app/clients/",
                {
                    "action": "register_pppoe",
                    "full_name": "john smith",
                    "phone": "0722334455",
                    "email": "",
                    "router": str(self.router.pk),
                    "address": "westlands",
                    "house_number": "12b",
                    "plan": "",
                    "pppoe_username": "",
                    "pppoe_password": "pass1234",
                    "cpe_username": "admin",
                    "cpe_password": "",
                },
            )
            self.assertEqual(response.status_code, 302)
            self.assertIn("tab=pppoe", response["Location"])
            self.assertEqual(len(started), 1)
            self.assertTrue(started[0].daemon)

            customer = Customer.objects.get(phone="0722334455")
            self.assertEqual(customer.full_name, "JOHN SMITH")
            self.assertEqual(customer.house_number, "12B")
            self.assertEqual(customer.pppoe_username, "0722334455")

            # Run the deferred worker while the provision mock is still active.
            with patch("django.db.connection.close"):
                started[0].target()

            provision.assert_called_once()
            self.assertFalse(provision.call_args.kwargs.get("ensure_stack", True))
            self.assertEqual(provision.call_args.args[0].pk, customer.pk)


class CaptivePortalDhcpOptionTests(SimpleTestCase):
    """RFC 8910 option 114 is what raises the sign-in popup on connect."""

    def test_option_is_created_and_attached_to_dhcp_networks(self):
        from core.mikrotik_connect import (
            CAPTIVE_PORTAL_DHCP_OPTION_NAME,
            _ensure_captive_portal_dhcp_option,
        )

        printed = {
            "/ip/dhcp-server/option": [],
            "/ip/dhcp-server/network": [
                {".id": "*1", "address": "192.168.88.0/24", "dhcp-option": ""},
            ],
        }
        sets: list[tuple] = []

        with (
            patch(
                "core.mikrotik_connect._print",
                side_effect=lambda sock, path, **kw: printed.get(path, []),
            ),
            patch(
                "core.mikrotik_connect._add_or_set_attempts",
                return_value=({"_reply": "!done"}, "*9"),
            ) as add_or_set,
            patch(
                "core.mikrotik_connect._set",
                side_effect=lambda sock, path, item_id, **kw: (
                    sets.append((path, item_id, kw)) or {"_reply": "!done"}
                ),
            ),
        ):
            notes = _ensure_captive_portal_dhcp_option(
                object(),
                "http://192.168.88.254:8000/hotspot/823444/pay/",
                comment="ispcentric-hotspot",
            )

        attempts = add_or_set.call_args.args[3]
        self.assertEqual(attempts[0]["code"], "114")
        self.assertEqual(
            attempts[0]["value"],
            "'http://192.168.88.254:8000/hotspot/823444/pay/'",
        )
        self.assertEqual(
            sets[0][2]["dhcp-option"], CAPTIVE_PORTAL_DHCP_OPTION_NAME
        )
        self.assertTrue(any("option 114" in note for note in notes))

    def test_existing_dhcp_options_are_preserved(self):
        from core.mikrotik_connect import _ensure_captive_portal_dhcp_option

        printed = {
            "/ip/dhcp-server/option": [],
            "/ip/dhcp-server/network": [
                {".id": "*1", "address": "10.0.0.0/24", "dhcp-option": "wpad"},
            ],
        }
        sets: list[tuple] = []

        with (
            patch(
                "core.mikrotik_connect._print",
                side_effect=lambda sock, path, **kw: printed.get(path, []),
            ),
            patch(
                "core.mikrotik_connect._add_or_set_attempts",
                return_value=({"_reply": "!done"}, "*9"),
            ),
            patch(
                "core.mikrotik_connect._set",
                side_effect=lambda sock, path, item_id, **kw: (
                    sets.append((path, item_id, kw)) or {"_reply": "!done"}
                ),
            ),
        ):
            _ensure_captive_portal_dhcp_option(
                object(), "http://10.0.0.2:8000/hotspot/1/pay/", comment="tag"
            )

        self.assertEqual(
            sets[0][2]["dhcp-option"], "wpad,ispcentric-captive-portal"
        )

    def test_no_option_without_a_pay_url(self):
        from core.mikrotik_connect import _ensure_captive_portal_dhcp_option

        with patch("core.mikrotik_connect._print") as printed:
            notes = _ensure_captive_portal_dhcp_option(
                object(), "", comment="tag"
            )
        printed.assert_not_called()
        self.assertEqual(notes, [])


class HotspotPushUrlDerivationTests(TestCase):
    """Background pushes must not degrade the captive portal."""

    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization

        self.owner = User.objects.create_user("derive-owner", password="x")
        self.org = Organization.objects.create(
            name="Derive ISP",
            owner=self.owner,
            join_code="665544",
            hotspot_enabled=True,
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Derive NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="192.168.88.1",
            username="admin",
            password="secret",
        )

    @override_settings(PUBLIC_BASE_URL="http://192.168.88.254:8000", HOSTED=False, DEBUG=True)
    def test_sweep_style_push_still_sends_portal_urls(self):
        from core.mikrotik_connect import apply_hotspot_on_router

        with (
            patch(
                "core.hotspot_portal.local_ipv4_addresses",
                return_value={"192.168.88.254"},
            ),
            patch(
                "core.mikrotik_connect.check_mikrotik_reachable",
                return_value={"online": True, "via": "api"},
            ),
            patch("core.mikrotik_connect._api_session"),
            patch(
                "core.mikrotik_connect._ensure_isp_hotspot_stack",
                return_value=[],
            ) as stack,
            patch(
                "core.mikrotik_connect._sync_organization_hotspot_users_on_socket",
                return_value=0,
            ),
            patch("core.mikrotik_connect._ensure_pppoe_stack", return_value=("", [])),
            patch("core.mikrotik_connect._resolve_lan_interface", return_value="bridge"),
        ):
            # The subscription sweep calls exactly this way — no URLs supplied.
            apply_hotspot_on_router(self.router, enabled=True)

        kwargs = stack.call_args.kwargs
        base = f"http://192.168.88.254:8000/hotspot/{self.org.join_code}"
        self.assertEqual(kwargs["pay_url"], f"{base}/pay/")
        self.assertEqual(kwargs["welcome_url"], f"{base}/welcome/")
        self.assertTrue(kwargs["login_url"].startswith(base))


class PppoeClientDnsRuleTests(SimpleTestCase):
    """PPPoE clients need DNS from the NAS or no captive redirect ever fires."""

    def _build_rules(self, *, compulsory: bool = False):
        from core.mikrotik_connect import _ensure_pppoe_stack

        added: list[tuple[dict, str]] = []
        filter_rows = [
            {".id": "*2B", "chain": "input", "action": "drop"},
            {".id": "*A", "chain": "forward", "action": "drop"},
        ]

        def fake_print(sock, path, **kwargs):
            if path == "/ip/firewall/filter":
                return filter_rows
            return []

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._add"),
            patch("core.mikrotik_connect._set", return_value={"_reply": "!done"}),
            patch("core.mikrotik_connect._remove", return_value={"_reply": "!done"}),
            patch("core.mikrotik_connect._command", return_value=([], {"_reply": "!done"})),
            patch("core.mikrotik_connect._add_or_set_attempts", return_value=({"_reply": "!done"}, "*1")),
            patch("core.mikrotik_connect._ensure_pppoe_nat"),
            patch("core.mikrotik_connect._ensure_pppoe_blocked_profile", return_value=[]),
            patch("core.mikrotik_connect._ensure_pppoe_expired_redirect", return_value=[]),
            patch(
                "core.mikrotik_connect._add_filter_rule",
                side_effect=lambda sock, rule, place_before="": (
                    added.append((rule, place_before)) or {"_reply": "!done"}
                ),
            ),
        ):
            _ensure_pppoe_stack(
                object(),
                lan_interface="bridge",
                wan_interface="ether1",
                compulsory=compulsory,
            )
        return added

    def test_dns_accept_is_added_for_the_pppoe_pool(self):
        from core.mikrotik_connect import PPPOE_POOL_NETWORK

        added = self._build_rules()
        dns_rules = [
            rule
            for rule, _ in added
            if rule.get("chain") == "input" and rule.get("dst-port") == "53"
        ]
        self.assertEqual(len(dns_rules), 2)
        self.assertEqual(
            {rule["protocol"] for rule in dns_rules}, {"udp", "tcp"}
        )
        for rule in dns_rules:
            self.assertEqual(rule["src-address"], PPPOE_POOL_NETWORK)
            self.assertEqual(rule["action"], "accept")

    def test_input_rules_are_anchored_above_the_input_drop(self):
        added = self._build_rules()
        for rule, place_before in added:
            expected = "*2B" if rule.get("chain") == "input" else "*A"
            self.assertEqual(
                place_before,
                expected,
                msg=f"{rule.get('comment')} anchored to {place_before}",
            )

    def test_blocked_clients_get_tcp_reset_instead_of_silent_drop(self):
        from core.mikrotik_connect import PPPOE_BLOCKED_ADDRESS_LIST

        added = self._build_rules()
        reject_rules = [
            rule
            for rule, _ in added
            if rule.get("action") == "reject"
            and rule.get("src-address-list") == PPPOE_BLOCKED_ADDRESS_LIST
        ]
        self.assertEqual(len(reject_rules), 1)
        self.assertEqual(reject_rules[0].get("reject-with"), "tcp-reset")
        self.assertEqual(reject_rules[0].get("protocol"), "tcp")
        self.assertEqual(reject_rules[0].get("out-interface-list"), "WAN")

    def test_compulsory_mode_does_not_allow_whole_hotspot_pool_to_wan(self):
        from core.mikrotik_connect import ISP_HOTSPOT_OK_LIST, ISP_HOTSPOT_POOL_NETWORK

        added = self._build_rules(compulsory=True)
        pool_rules = [
            rule
            for rule, _ in added
            if rule.get("src-address") == ISP_HOTSPOT_POOL_NETWORK
        ]
        self.assertEqual(pool_rules, [])
        ok_rules = [
            rule
            for rule, _ in added
            if rule.get("src-address-list") == ISP_HOTSPOT_OK_LIST
        ]
        self.assertEqual(len(ok_rules), 1)
        self.assertEqual(ok_rules[0].get("action"), "accept")


class PppoePaidSessionRestoreTests(SimpleTestCase):
    def test_live_session_on_blocked_address_list_is_detected(self):
        from core.mikrotik_connect import _active_pppoe_session_is_blocked

        def fake_print(sock, path, **kwargs):
            if path == "/ppp/active":
                return [{"name": "0701127243", "address": "10.20.0.11"}]
            if path == "/ip/firewall/address-list":
                return [{"list": "ispcentric-blocked", "address": "10.20.0.11"}]
            return []

        with patch("core.mikrotik_connect._print", side_effect=fake_print):
            self.assertTrue(
                _active_pppoe_session_is_blocked(object(), "0701127243")
            )


class PortalBaseUrlReachabilityTests(SimpleTestCase):
    """A portal URL pushed to the router must point at an address we answer on."""

    def test_private_ip_this_server_does_not_own_is_reported(self):
        from core.hotspot_portal import unreachable_base_url_reason

        with patch(
            "core.hotspot_portal.local_ipv4_addresses",
            return_value={"192.168.88.254"},
        ):
            reason = unreachable_base_url_reason("http://10.10.0.168:8000")
        self.assertIn("10.10.0.168", reason)
        self.assertIn("no such address", reason)

    def test_private_ip_bound_to_this_server_is_accepted(self):
        from core.hotspot_portal import unreachable_base_url_reason

        with patch(
            "core.hotspot_portal.local_ipv4_addresses",
            return_value={"192.168.88.254"},
        ):
            self.assertEqual(
                unreachable_base_url_reason("http://192.168.88.254:8000"), ""
            )

    def test_hostnames_and_public_ips_are_left_alone(self):
        from core.hotspot_portal import unreachable_base_url_reason

        with patch("core.hotspot_portal.local_ipv4_addresses", return_value=set()):
            self.assertEqual(unreachable_base_url_reason("http://isp.richcom.co.ke"), "")
            self.assertEqual(unreachable_base_url_reason("http://41.90.1.2"), "")
            self.assertEqual(unreachable_base_url_reason("http://127.0.0.1:8000"), "")

    @override_settings(PUBLIC_BASE_URL="http://10.10.0.168:8000", HOSTED=False, DEBUG=True)
    def test_stale_local_public_base_url_is_replaced_with_lan_ip(self):
        from core.hotspot_portal import hotspot_portal_urls, public_base_url

        with patch(
            "core.hotspot_portal.local_ipv4_addresses",
            return_value={"192.168.1.135", "10.9.0.3"},
        ), patch(
            "core.hotspot_portal._default_route_ipv4",
            return_value="192.168.1.135",
        ):
            base = public_base_url()
            urls = hotspot_portal_urls("606060")
        self.assertEqual(base, "http://192.168.1.135:8000")
        self.assertEqual(urls["base_url"], "http://192.168.1.135:8000")
        self.assertTrue(urls["pay_url"].startswith("http://192.168.1.135:8000/hotspot/"))
        self.assertTrue(urls["base_auto_selected"])
        self.assertIn("10.10.0.168", urls["base_unreachable_reason"])

    @override_settings(PUBLIC_BASE_URL="auto", HOSTED=False, DEBUG=True)
    def test_auto_sentinel_picks_lan_ip_not_wireguard(self):
        from core.hotspot_portal import public_base_url

        with patch(
            "core.hotspot_portal.local_ipv4_addresses",
            return_value={"10.9.0.3", "192.168.1.135"},
        ), patch(
            "core.hotspot_portal._default_route_ipv4",
            return_value="10.9.0.3",
        ), override_settings(WIREGUARD_SUBNET="10.9.0.0/24"):
            # Default route may be the WG interface; still prefer a non-tunnel LAN IP.
            base = public_base_url()
        self.assertEqual(base, "http://192.168.1.135:8000")

    @override_settings(
        PUBLIC_BASE_URL="http://192.168.88.254:8000",
        HOSTED=True,
        ALLOWED_HOSTS=["isp.richcom.co.ke", "*"],
        DEBUG=False,
    )
    def test_hosted_ignores_stale_private_public_base_url(self):
        from core.hotspot_portal import public_base_url

        with patch(
            "core.hotspot_portal.local_ipv4_addresses",
            return_value={"10.0.0.5"},
        ):
            base = public_base_url()
        self.assertEqual(base, "http://isp.richcom.co.ke")

    @override_settings(
        PUBLIC_BASE_URL="http://isp.richcom.co.ke",
        HOSTED=True,
        DEBUG=False,
    )
    def test_hosted_keeps_public_hostname(self):
        from core.hotspot_portal import hotspot_portal_urls, public_base_url

        self.assertEqual(public_base_url(), "http://isp.richcom.co.ke")
        urls = hotspot_portal_urls("606060")
        self.assertEqual(
            urls["pay_url"],
            "http://isp.richcom.co.ke/hotspot/606060/pay/",
        )
        self.assertFalse(urls["base_auto_selected"])

    @override_settings(PUBLIC_BASE_URL="http://192.168.1.135:8000", HOSTED=False, DEBUG=True)
    def test_usable_local_public_base_url_is_kept(self):
        from core.hotspot_portal import public_base_url

        with patch(
            "core.hotspot_portal.local_ipv4_addresses",
            return_value={"192.168.1.135"},
        ):
            self.assertEqual(public_base_url(), "http://192.168.1.135:8000")


class PppoePayPortalUrlTests(SimpleTestCase):
    """PPPoE renew redirects must be absolute — never path-only on 192.168 CPE IPs."""

    @override_settings(
        PUBLIC_BASE_URL="http://isp.richcom.co.ke",
        HOSTED=True,
        DEBUG=False,
    )
    def test_pppoe_pay_url_uses_public_base_not_relative_path(self):
        from core.mikrotik_connect import _pppoe_pay_portal_url

        org = type("Org", (), {"join_code": "121212", "pk": 1})()
        url = _pppoe_pay_portal_url(org)
        self.assertTrue(url.startswith("http://isp.richcom.co.ke/pppoe/121212/pay/"))
        self.assertFalse(url.startswith("/pppoe/"))

    @override_settings(PUBLIC_BASE_URL="auto", HOSTED=False, DEBUG=True)
    def test_auto_public_base_builds_absolute_lan_pay_url(self):
        from core.mikrotik_connect import _pppoe_pay_portal_url

        org = type("Org", (), {"join_code": "343434", "pk": 2})()
        with patch(
            "core.hotspot_portal.local_ipv4_addresses",
            return_value={"192.168.1.135", "10.9.0.3"},
        ), patch(
            "core.hotspot_portal._default_route_ipv4",
            return_value="192.168.1.135",
        ), override_settings(WIREGUARD_SUBNET="10.9.0.0/24"):
            url = _pppoe_pay_portal_url(org)
        self.assertTrue(
            url.startswith("http://192.168.1.135:8000/pppoe/343434/pay/"),
            msg=url,
        )

    @override_settings(
        PUBLIC_BASE_URL="http://192.168.88.254:8000",
        HOSTED=True,
        ALLOWED_HOSTS=["isp.richcom.co.ke", "*"],
        DEBUG=False,
    )
    def test_hosted_ignores_stale_private_base_for_pppoe_pay(self):
        from core.mikrotik_connect import _billing_portal_base_url, _pppoe_pay_portal_url

        self.assertEqual(_billing_portal_base_url(), "http://isp.richcom.co.ke")
        org = type("Org", (), {"join_code": "565656", "pk": 3})()
        url = _pppoe_pay_portal_url(org)
        self.assertTrue(url.startswith("http://isp.richcom.co.ke/pppoe/565656/pay/"))
        self.assertNotIn("192.168.", url)

    def test_captive_html_location_is_absolute(self):
        from core.mikrotik_connect import _captive_pay_redirect_html

        html = _captive_pay_redirect_html(
            "http://isp.richcom.co.ke/pppoe/121212/pay/?t=token"
        )
        self.assertIn(
            '$(if http-header == "Location")http://isp.richcom.co.ke/pppoe/121212/pay/?t=token&mac=',
            html,
        )
        self.assertNotIn('Location")/pppoe/', html)

    def test_cpe_portal_access_allows_billing_before_wan_drop(self):
        from unittest.mock import MagicMock

        from core.mikrotik_connect import (
            RENEW_HOTSPOT_TAG,
            _ensure_cpe_portal_access,
        )

        sock = MagicMock()
        added: list[tuple[str, dict]] = []

        def fake_add(s, path, **props):
            added.append((path, props))
            return {"_reply": "!done", "ret": f"*{len(added)}"}

        with (
            patch("core.mikrotik_connect._print", return_value=[]),
            patch("core.mikrotik_connect._remove_tagged_rows", return_value=0),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch(
                "core.mikrotik_connect._portal_target_ipv4",
                return_value="41.90.1.2",
            ),
            patch(
                "core.mikrotik_connect._billing_portal_base_url",
                return_value="http://isp.richcom.co.ke",
            ),
        ):
            notes = _ensure_cpe_portal_access(
                sock, "http://isp.richcom.co.ke/pppoe/121212/pay/"
            )

        garden = [p for path, p in added if path == "/ip/hotspot/walled-garden"]
        allow = [
            p
            for path, p in added
            if path == "/ip/firewall/filter" and p.get("action") == "accept"
        ]
        self.assertTrue(garden)
        self.assertEqual(garden[0].get("dst-host"), "isp.richcom.co.ke")
        self.assertTrue(allow)
        self.assertEqual(allow[0].get("dst-address"), "41.90.1.2")
        self.assertEqual(allow[0].get("comment"), f"{RENEW_HOTSPOT_TAG}-allow")
        self.assertTrue(any("walled garden" in n for n in notes))
        self.assertTrue(any("forward allow" in n for n in notes))

    def test_fetch_hotspot_pages_refuses_relative_without_base(self):
        from unittest.mock import MagicMock

        from core.mikrotik_connect import _fetch_hotspot_pages

        sock = MagicMock()
        with (
            patch("core.mikrotik_connect._billing_portal_base_url", return_value=""),
            patch("core.mikrotik_connect._write_hotspot_html_file") as write_html,
        ):
            notes = _fetch_hotspot_pages(sock, "/pppoe/121212/pay/")
        write_html.assert_not_called()
        self.assertTrue(any("relative" in n.lower() or "192.168" in n for n in notes))


class CompulsoryHotspotFallbackTests(SimpleTestCase):
    def test_pppoe_enforcement_pushes_hotspot_fallback_when_compulsory(self):
        from core.mikrotik_connect import apply_pppoe_enforcement_on_router

        org = type(
            "Org",
            (),
            {
                "join_code": "505050",
                "hotspot_enabled": False,
                "hotspot_redirect_url": "",
                "hotspot_use_welcome_page": True,
                "save": lambda self, **kwargs: None,
            },
        )()
        router = type(
            "Router",
            (),
            {
                "pk": 7,
                "name": "NAS-1",
                "host": "192.168.88.1",
                "username": "admin",
                "password": "x",
                "lan_bridge": "bridge",
                "wan_interface": "ether1",
                "vpn_address": "",
                "organization": org,
                "save": lambda self, **kwargs: None,
            },
        )()

        with (
            patch(
                "core.mikrotik_connect._router_api_host_candidates",
                return_value=["192.168.88.1"],
            ),
            patch(
                "core.mikrotik_connect.check_mikrotik_reachable",
                return_value={"online": True, "via": "api"},
            ),
            patch("core.mikrotik_connect._api_session") as api_session,
            patch(
                "core.mikrotik_connect._ensure_pppoe_stack",
                return_value=("ispcentric-pppoe", ["pppoe ready"]),
            ),
            patch(
                "core.mikrotik_connect._sync_organization_pppoe_secrets_on_socket",
                return_value=1,
            ),
            patch(
                "core.mikrotik_connect.apply_hotspot_on_router",
                return_value={"ok": True, "notes": ["hotspot ready"], "users_synced": 0},
            ) as hotspot_push,
            patch(
                "core.mikrotik_connect._hotspot_portal_urls_for_org",
                return_value={
                    "login_url": "http://billing/login",
                    "alogin_url": "http://billing/alogin",
                    "pay_url": "http://billing/pay",
                    "welcome_url": "http://billing/welcome",
                },
            ),
        ):
            api_session.return_value.__enter__.return_value = object()
            api_session.return_value.__exit__.return_value = False
            result = apply_pppoe_enforcement_on_router(router, compulsory=True)

        self.assertTrue(result["ok"])
        self.assertTrue(result["hotspot_fallback"])
        hotspot_push.assert_called_once()
        self.assertTrue(org.hotspot_enabled)


@override_settings(
    WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
    WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
    WIREGUARD_SUBNET="10.9.0.0/24",
)
class TunnelStatusTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        from django.core.cache import cache

        from accounts.models import Organization
        from core.models import WireGuardReservation

        self.owner = User.objects.create_user("tunnel-owner", password="x")
        self.org = Organization.objects.create(
            name="Tunnel ISP",
            owner=self.owner,
            join_code="445566",
        )
        self.reservation = WireGuardReservation.objects.create(
            label="Kariobangi",
            address="10.9.0.4",
            public_key=SERVER_PUBLIC_KEY,
            private_key=SERVER_PUBLIC_KEY,
        )
        cache.delete(f"mikrotik_tunnel_local_devices:{self.org.pk}")
        self.client.force_login(self.owner)

    def _token(self):
        from django.core import signing

        return signing.dumps(
            {"address": self.reservation.address, "user_id": self.owner.pk},
            salt="mikrotik-tunnel-status",
            compress=True,
        )

    def test_local_server_uses_discovery_instead_of_the_tunnel_route(self):
        with (
            patch("core.wireguard.server_on_tunnel", return_value=False),
            patch("core.views.discover_mikrotik_devices", return_value=[]),
            patch("core.views.check_mikrotik_reachable") as probe,
        ):
            response = self.client.get(
                "/app/mikrotik/tunnel-status/", {"token": self._token()}
            )

        data = response.json()
        probe.assert_not_called()
        self.assertTrue(data["ok"])
        self.assertTrue(data["no_tunnel_route"])
        self.assertTrue(data["local_mode"])
        self.assertFalse(data["ready"])
        self.assertIn("Local mode", data["message"])
        self.assertIn("no MikroTik", data["message"])
        self.assertIn("checks", data)
        self.assertTrue(any(item["key"] == "lan" for item in data["checks"]))
        self.assertTrue(any(item["status"] == "waiting" for item in data["checks"]))

    def test_local_server_reports_discovered_lan_api_ready(self):
        device = {
            "host": "192.168.88.1",
            "name": "Kariobangi",
            "identity": "Kariobangi",
            "onboarded": False,
        }
        with (
            patch("core.wireguard.server_on_tunnel", return_value=False),
            patch("core.views.discover_mikrotik_devices", return_value=[device]),
            patch(
                "core.views.check_mikrotik_reachable",
                return_value={"online": True, "via": "api"},
            ) as probe,
        ):
            response = self.client.get(
                "/app/mikrotik/tunnel-status/", {"token": self._token()}
            )

        data = response.json()
        probe.assert_called_once_with("192.168.88.1", timeout=0.8)
        self.assertTrue(data["local_mode"])
        self.assertTrue(data["ready"])
        self.assertTrue(data["api_enabled"])
        self.assertEqual(data["lan_address"], "192.168.88.1")
        self.assertEqual(
            [item["status"] for item in data["checks"] if item["key"] == "api"],
            ["ok"],
        )

    def test_local_server_flags_subnet_mismatch_when_api_unreachable(self):
        device = {
            "host": "192.168.88.1",
            "name": "Kariobangi",
            "identity": "Kariobangi",
            "onboarded": False,
        }
        with (
            patch("core.wireguard.server_on_tunnel", return_value=False),
            patch("core.views.discover_mikrotik_devices", return_value=[device]),
            patch(
                "core.views.check_mikrotik_reachable",
                return_value={"online": False, "via": ""},
            ),
            patch(
                "core.hotspot_portal.local_ipv4_addresses",
                return_value={"192.168.1.66"},
            ),
        ):
            response = self.client.get(
                "/app/mikrotik/tunnel-status/", {"token": self._token()}
            )

        data = response.json()
        self.assertTrue(data["local_mode"])
        self.assertFalse(data["ready"])
        self.assertTrue(data["subnet_mismatch"])
        self.assertEqual(data["local_ip"], "192.168.1.66")
        self.assertIn("different subnet", data["message"])
        self.assertIn("192.168.1.66", data["message"])

    def test_a_server_on_the_tunnel_reports_api_ready(self):
        with (
            patch("core.wireguard.server_on_tunnel", return_value=True),
            patch(
                "core.views.check_mikrotik_reachable",
                return_value={"online": True, "via": "api"},
            ),
        ):
            response = self.client.get(
                "/app/mikrotik/tunnel-status/", {"token": self._token()}
            )

        data = response.json()
        self.assertTrue(data["ready"])
        self.assertFalse(data["no_tunnel_route"])
        self.assertTrue(data["api_enabled"])
        self.assertIn("checks", data)
        self.assertTrue(
            any(item["key"] == "tunnel" and item["status"] == "ok" for item in data["checks"])
        )
        self.assertTrue(
            any(item["key"] == "api" and item["status"] == "ok" for item in data["checks"])
        )

    def test_tunnel_server_address_is_not_bindable_on_a_plain_host(self):
        # The dev machine holds no 10.9.0.1, so the helper must not claim a route.
        self.assertFalse(wireguard.server_on_tunnel())

    @override_settings(
        WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
        WIREGUARD_SUBNET="10.9.0.0/24",
    )
    def test_tunnel_verification_checks_cover_vps_mode(self):
        checks = wireguard.tunnel_verification_checks(
            local_mode=False,
            address="10.9.0.4",
            tunnel_reachable=False,
            api_enabled=False,
        )
        keys = [item["key"] for item in checks]
        self.assertEqual(
            keys,
            ["tunnel", "vps_peer", "billing_ping", "api", "firewall"],
        )
        self.assertEqual(checks[1]["status"], "fail")
        self.assertIn("[Peer]", checks[1]["message"])

        missing = wireguard.tunnel_verification_checks(
            local_mode=False,
            address="10.9.0.4",
            tunnel_reachable=False,
            api_enabled=False,
            peer_state="missing",
        )
        self.assertEqual(missing[1]["status"], "fail")
        self.assertIn("sync-server", missing[1]["message"])

        no_hs = wireguard.tunnel_verification_checks(
            local_mode=False,
            address="10.9.0.4",
            tunnel_reachable=False,
            api_enabled=False,
            peer_state="no_handshake",
        )
        self.assertEqual(no_hs[1]["status"], "fail")
        self.assertIn("handshake", no_hs[1]["message"].lower())

        waiting = wireguard.tunnel_verification_checks(
            local_mode=False,
            address="10.9.0.4",
            tunnel_reachable=False,
            api_enabled=False,
            peer_state="waiting_router",
        )
        self.assertEqual(waiting[1]["status"], "ok")

        ready = wireguard.tunnel_verification_checks(
            local_mode=False,
            address="10.9.0.4",
            tunnel_reachable=True,
            api_enabled=True,
        )
        self.assertTrue(all(item["status"] == "ok" for item in ready))

    def test_peer_sync_report_marks_hosted_skip_as_required(self):
        with override_settings(HOSTED=True):
            report = wireguard.peer_sync_report(
                {
                    "ok": False,
                    "skipped": True,
                    "reason": "sync_command_unset",
                    "error": "WIREGUARD_SYNC_COMMAND is empty",
                }
            )
        self.assertTrue(report["peer_sync_required"])
        self.assertFalse(report["peer_synced"])
        self.assertIn("WIREGUARD_SYNC_COMMAND", report["peer_sync_hint"])

    def test_peer_sync_report_local_skip_is_not_required(self):
        with override_settings(HOSTED=False):
            report = wireguard.peer_sync_report(
                {"ok": False, "skipped": True, "reason": "sync_command_unset"}
            )
        self.assertFalse(report["peer_sync_required"])
        self.assertTrue(report["peer_sync_skipped"])

    def test_inspect_server_peer_parses_wg_dump(self):
        dump = (
            "private\tpublic\t51820\toff\n"
            f"{SERVER_PUBLIC_KEY}\t(none)\t(none)\t10.9.0.8/32\t0\t0\t0\toff\n"
        )
        with (
            override_settings(
                WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
                WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
            ),
            patch("core.wireguard.shutil.which", return_value="wg"),
            patch("core.wireguard.subprocess.run") as run,
        ):
            run.return_value.returncode = 0
            run.return_value.stdout = dump
            run.return_value.stderr = ""
            info = wireguard.inspect_server_peer(SERVER_PUBLIC_KEY)
        self.assertTrue(info["checked"])
        self.assertTrue(info["present"])
        self.assertIsNone(info["handshake_age_sec"])

    def test_ensure_reservation_peer_reports_missing(self):
        class _Res:
            label = "Site"
            address = "10.9.0.8"
            public_key = SERVER_PUBLIC_KEY

        with (
            patch(
                "core.wireguard.apply_server_peer",
                return_value={"ok": False, "skipped": False, "error": "denied"},
            ),
            patch(
                "core.wireguard.inspect_server_peer",
                return_value={
                    "checked": True,
                    "present": False,
                    "handshake_age_sec": None,
                    "error": "",
                },
            ),
        ):
            result = wireguard.ensure_reservation_peer(_Res())
        self.assertEqual(result["code"], "peer_missing")
        self.assertIn("sync-server", result["message"])

    def test_apply_server_peer_reports_sync_command_unset(self):
        with (
            override_settings(
                WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
                WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
                WIREGUARD_SYNC_COMMAND="",
            ),
            patch("core.wireguard.server_on_tunnel", return_value=False),
        ):
            result = wireguard.apply_server_peer(
                "Site A", "10.9.0.8", SERVER_PUBLIC_KEY
            )
        self.assertTrue(result["skipped"])
        self.assertEqual(result["reason"], "sync_command_unset")
        self.assertIn("WIREGUARD_SYNC_COMMAND", result["error"])


class MikroTikDeleteTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization
        from billing.models import Customer

        self.owner = User.objects.create_user("mikrotik-owner", password="x")
        self.org = Organization.objects.create(
            name="Delete ISP",
            owner=self.owner,
            join_code="998877",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Yard Router",
            model=MikroTikRouter.ModelChoice.HEX,
            host="192.168.88.1",
            username="admin",
            password="secret",
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Linked Client",
            phone="254700000099",
            account_number="DEL-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="linked1",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            router=self.router,
        )

    def test_owner_can_delete_router_and_clients_stay_unassigned(self):
        self.client.force_login(self.owner)
        response = self.client.post(
            f"/app/mikrotik/{self.router.pk}/delete/",
            follow=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/app/mikrotik/")
        self.assertFalse(MikroTikRouter.objects.filter(pk=self.router.pk).exists())
        self.customer.refresh_from_db()
        self.assertIsNone(self.customer.router_id)

    def test_get_delete_redirects_to_list_without_removing(self):
        self.client.force_login(self.owner)
        response = self.client.get(f"/app/mikrotik/{self.router.pk}/delete/")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/app/mikrotik/")
        self.assertTrue(MikroTikRouter.objects.filter(pk=self.router.pk).exists())


class ClientsSurfingStatusTests(TestCase):
    def setUp(self):
        from datetime import timedelta

        from django.contrib.auth.models import User
        from django.core.cache import cache
        from django.utils import timezone

        from accounts.models import Organization
        from billing.models import Customer

        cache.clear()
        self.owner = User.objects.create_user("surfing-owner", password="x")
        self.org = Organization.objects.create(
            name="Live ISP",
            owner=self.owner,
            join_code="887766",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Live NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="192.168.88.1",
            username="admin",
            password="secret",
        )
        now = timezone.now()
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Unassigned Online Client",
            phone="254700000088",
            account_number="LIVE-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="LiveUser",
            pppoe_password="secret",
            status=Customer.Status.ACTIVE,
            package_start=now - timedelta(hours=1),
            package_end=now + timedelta(hours=1),
            router=None,
        )
        self.client.force_login(self.owner)

    @patch("core.views.fetch_active_pppoe_usernames")
    def test_dialed_session_on_blocked_profile_is_not_reported_as_surfing(
        self, fetch_active
    ):
        fetch_active.return_value = {
            "ok": True,
            "usernames": ["liveuser"],
            "blocked": ["liveuser"],
            "error": "",
        }

        response = self.client.get(
            "/app/clients/surfing/",
            {"service": "pppoe", "refresh": "1"},
        )

        data = response.json()
        self.assertEqual(data["surfing_count"], 0)
        self.assertFalse(data["clients"][0]["surfing"])
        self.assertEqual(data["clients"][0]["state"], "not_surfing")
        self.assertEqual(data["clients"][0]["label"], "Not surfing")
        self.assertIn("blocked on the router", data["clients"][0]["reason"])

    @patch("core.views.fetch_active_pppoe_usernames")
    def test_dialed_but_expired_package_is_not_surfing(self, fetch_active):
        """Past midnight cut-off: dialed session must not count as surfing."""
        from datetime import timedelta

        from django.utils import timezone

        fetch_active.return_value = {
            "ok": True,
            "usernames": ["liveuser"],
            "blocked": [],
            "error": "",
        }
        self.customer.package_start = timezone.now() - timedelta(days=3)
        self.customer.package_end = timezone.now() - timedelta(days=1)
        self.customer.save(update_fields=["package_start", "package_end"])

        response = self.client.get(
            "/app/clients/surfing/",
            {"service": "pppoe", "refresh": "1"},
        )

        data = response.json()
        self.assertEqual(data["surfing_count"], 0)
        client = data["clients"][0]
        self.assertFalse(client["surfing"])
        self.assertTrue(client["session_online"])
        self.assertFalse(client["internet_allowed"])
        self.assertEqual(client["state"], "expired")
        self.assertEqual(client["label"], "Expired")
        self.assertIn("subscription ended", client["reason"].lower())

    @patch("core.views.fetch_active_pppoe_usernames")
    def test_unreachable_router_shows_disconnected(self, fetch_active):
        fetch_active.return_value = {
            "ok": False,
            "usernames": [],
            "blocked": [],
            "error": "Connection timed out.",
        }
        self.customer.router = self.router
        self.customer.save(update_fields=["router"])

        response = self.client.get(
            "/app/clients/surfing/",
            {"service": "pppoe", "refresh": "1"},
        )

        data = response.json()
        client = data["clients"][0]
        self.assertFalse(client["surfing"])
        self.assertEqual(client["state"], "disconnected")
        self.assertEqual(client["label"], "Disconnected")
        self.assertFalse(client["router_reachable"])
        self.assertIn("timed out", client["reason"].lower())

    @patch("core.views.fetch_active_pppoe_usernames")
    def test_undialed_client_shows_disconnected(self, fetch_active):
        """Router reachable but no PPPoE session → Internet column = Disconnected."""
        fetch_active.return_value = {
            "ok": True,
            "usernames": [],
            "blocked": [],
            "error": "",
        }
        self.customer.router = self.router
        self.customer.save(update_fields=["router"])

        response = self.client.get(
            "/app/clients/surfing/",
            {"service": "pppoe", "refresh": "1"},
        )

        data = response.json()
        client = data["clients"][0]
        self.assertFalse(client["surfing"])
        self.assertFalse(client["session_online"])
        self.assertEqual(client["state"], "disconnected")
        self.assertEqual(client["label"], "Disconnected")
        self.assertTrue(client["router_reachable"])

    @patch("core.views.fetch_active_pppoe_usernames")
    def test_expired_undialed_client_shows_expired(self, fetch_active):
        """Ended package with no session still shows Expired (not Disconnected)."""
        from datetime import timedelta

        from django.utils import timezone

        fetch_active.return_value = {
            "ok": True,
            "usernames": [],
            "blocked": [],
            "error": "",
        }
        self.customer.router = self.router
        self.customer.package_start = timezone.now() - timedelta(days=3)
        self.customer.package_end = timezone.now() - timedelta(days=1)
        self.customer.save(update_fields=["router", "package_start", "package_end"])

        response = self.client.get(
            "/app/clients/surfing/",
            {"service": "pppoe", "refresh": "1"},
        )

        data = response.json()
        client = data["clients"][0]
        self.assertFalse(client["surfing"])
        self.assertFalse(client["session_online"])
        self.assertEqual(client["state"], "expired")
        self.assertEqual(client["label"], "Expired")

    @patch("core.views.fetch_active_pppoe_usernames")
    def test_unassigned_client_matches_live_session_on_any_org_router(self, fetch_active):
        fetch_active.return_value = {
            "ok": True,
            "usernames": ["liveuser"],
            "blocked": [],
            "error": "",
        }

        response = self.client.get(
            "/app/clients/surfing/",
            {"service": "pppoe", "refresh": "1"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["surfing_count"], 1)
        self.assertTrue(data["clients"][0]["surfing"])
        self.assertTrue(data["clients"][0]["internet_allowed"])
        self.assertEqual(data["clients"][0]["reason"], "Online — internet OK")
        self.assertEqual(data["clients"][0]["full_name"], "Unassigned Online Client")
        self.assertTrue(data["clients"][0]["url"])
        fetch_active.assert_called_once_with(
            self.router.host,
            self.router.username,
            self.router.password,
            timeout=4.0,
        )

    def test_pppoe_portal_is_pppoe_only(self):
        from django.test import RequestFactory

        from core.views import _pppoe_portal_context

        self.org.hotspot_enabled = True
        self.org.save(update_fields=["hotspot_enabled"])
        request = RequestFactory().get(
            f"/pppoe/{self.org.join_code}/pay/",
            REMOTE_ADDR="10.20.0.2",
        )

        context = _pppoe_portal_context(
            self.org,
            request,
            customer=self.customer,
        )

        self.assertTrue(context["hotspot_option_available"])
        self.assertFalse(context["dual_access_tabs"])
        self.assertEqual(context["portal_mode"], "pppoe")
        self.assertEqual(context["hotspot_plans"], [])
        self.assertFalse(context["show_inline_hotspot"])
        self.assertIn("/hotspot/", context["hotspot_payment_start_url"])
        self.assertIn(f"/hotspot/{self.org.join_code}/pay/", context["hotspot_pay_url"])
        self.assertEqual(context["account_number"], self.customer.account_number)
        self.assertEqual(context["pppoe_phone_value"], "0700000088")
        self.assertEqual(context["pppoe_selected_plan_id"], self.customer.plan_id)
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.service_type, "pppoe")

    def test_pppoe_portal_offers_hotspot_handoff_when_enabled(self):
        from django.test import RequestFactory

        from accounts.models import Organization
        from billing.models import BillingPlan
        from core.views import _pppoe_portal_context

        self.org.hotspot_enabled = True
        self.org.daraja_enabled = True
        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.mpesa_payment_type = Organization.MpesaPaymentType.PAYBILL
        self.org.mpesa_number = "123456"
        self.org.daraja_consumer_key = "key"
        self.org.daraja_consumer_secret = "secret"
        self.org.daraja_passkey = "pass"
        self.org.daraja_callback_url = "https://example.com/callback"
        self.org.save()
        BillingPlan.objects.create(
            organization=self.org,
            name="Home Monthly",
            price="2000.00",
            download_speed_mbps=20,
            upload_speed_mbps=10,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        request = RequestFactory().get(f"/pppoe/{self.org.join_code}/pay/")
        context = _pppoe_portal_context(self.org, request, customer=self.customer)
        self.assertTrue(context["hotspot_option_available"])
        self.assertIn(f"/hotspot/{self.org.join_code}/pay/", context["hotspot_pay_url"])
        self.assertEqual(context["portal_mode"], "pppoe")
        self.assertFalse(context["dual_access_tabs"])

        response = self.client.get(f"/pppoe/{self.org.join_code}/pay/")
        self.assertContains(response, "Pay for Hotspot instead")
        self.assertContains(response, f"/hotspot/{self.org.join_code}/pay/")
        self.assertContains(response, 'id="panel-pppoe"')
        self.assertNotContains(response, 'id="choose-hotspot"')

    def test_pppoe_pay_page_starts_on_pppoe_tab_even_without_customer(self):
        """Unidentified /pppoe/…/pay visitors must still open Home / PPPoE first."""
        from django.test import RequestFactory

        from accounts.models import Organization
        from billing.models import BillingPlan
        from core.views import _pppoe_portal_context

        self.org.hotspot_enabled = True
        self.org.daraja_enabled = True
        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.mpesa_payment_type = Organization.MpesaPaymentType.PAYBILL
        self.org.mpesa_number = "123456"
        self.org.daraja_consumer_key = "key"
        self.org.daraja_consumer_secret = "secret"
        self.org.daraja_passkey = "pass"
        self.org.daraja_callback_url = "https://example.com/callback"
        self.org.save()
        BillingPlan.objects.create(
            organization=self.org,
            name="Hotspot Hour",
            price="50.00",
            download_speed_mbps=5,
            upload_speed_mbps=2,
            service_type=BillingPlan.ServiceType.HOTSPOT,
        )
        BillingPlan.objects.create(
            organization=self.org,
            name="Home Monthly",
            price="2000.00",
            download_speed_mbps=20,
            upload_speed_mbps=10,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        request = RequestFactory().get(f"/pppoe/{self.org.join_code}/pay/")
        context = _pppoe_portal_context(self.org, request, customer=None)
        self.assertEqual(context["portal_mode"], "pppoe")
        self.assertTrue(context["pppoe_option_available"])
        self.assertTrue(context["hotspot_option_available"])
        self.assertFalse(context["dual_access_tabs"])
        self.assertTrue(context["show_inline_hotspot"])
        self.assertTrue(context["pppoe_plans"])
        self.assertTrue(context["hotspot_plans"])

        response = self.client.get(f"/pppoe/{self.org.join_code}/pay/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["portal_mode"], "pppoe")
        self.assertTrue(response.context["show_inline_hotspot"])
        html = response.content.decode()
        self.assertIn('id="panel-pppoe"', html)
        self.assertIn('id="panel-hotspot"', html)
        self.assertIn("Hotspot on this device", html)
        self.assertNotIn('id="choose-hotspot"', html)
        self.assertNotIn("Pay for Hotspot instead", html)
        pppoe_pos = html.index('id="panel-pppoe"')
        hotspot_pos = html.index('id="panel-hotspot"')
        self.assertLess(pppoe_pos, hotspot_pos)

    def test_hotspot_portal_is_hotspot_only(self):
        from django.test import RequestFactory

        from accounts.models import Organization
        from billing.models import BillingPlan, Customer
        from core.views import _hotspot_portal_context

        self.org.pppoe_compulsory = True
        self.org.hotspot_enabled = True
        self.org.daraja_enabled = True
        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.mpesa_payment_type = Organization.MpesaPaymentType.PAYBILL
        self.org.mpesa_number = "123456"
        self.org.daraja_consumer_key = "key"
        self.org.daraja_consumer_secret = "secret"
        self.org.daraja_passkey = "pass"
        self.org.daraja_callback_url = "https://example.com/callback"
        self.org.save()
        hotspot_plan = BillingPlan.objects.create(
            organization=self.org,
            name="Day Pass",
            price="100.00",
            download_speed_mbps=10,
            upload_speed_mbps=5,
            service_type=BillingPlan.ServiceType.HOTSPOT,
        )
        BillingPlan.objects.create(
            organization=self.org,
            name="Home Monthly",
            price="2000.00",
            download_speed_mbps=20,
            upload_speed_mbps=10,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        hotspot_customer = Customer.objects.create(
            organization=self.org,
            full_name="Hotspot Device",
            phone="254700000099",
            account_number="HOT-CHOICE",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:11",
            status=Customer.Status.ACTIVE,
            plan=hotspot_plan,
        )
        request = RequestFactory().get(
            f"/hotspot/{self.org.join_code}/pay/",
            {"mac": "AABBCCDDEE11"},
        )

        context = _hotspot_portal_context(self.org, request=request)
        response = self.client.get(f"/hotspot/{self.org.join_code}/pay/?mac=AABBCCDDEE11")

        self.assertFalse(context["pppoe_option_available"])
        self.assertFalse(context["dual_access_tabs"])
        self.assertEqual(context["portal_mode"], "hotspot")
        self.assertEqual(context["hotspot_phone_value"], "0700000099")
        self.assertEqual(context["hotspot_selected_plan_id"], hotspot_plan.pk)
        self.assertFalse(context["pppoe_payment_start_url"])
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="panel-hotspot"')
        self.assertContains(response, 'data-pay-panel="hotspot"')
        self.assertNotContains(response, 'id="panel-pppoe"')
        self.assertNotContains(response, "Home / PPPoE")
        self.assertContains(response, 'value="0700000099"')
        self.assertContains(response, "Choose a package")
        hotspot_customer.refresh_from_db()
        self.assertEqual(hotspot_customer.service_type, "hotspot")

    def test_pppoe_pay_autofills_from_account_query(self):
        from accounts.models import Organization
        from billing.models import BillingPlan

        self.org.daraja_enabled = True
        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.mpesa_payment_type = Organization.MpesaPaymentType.PAYBILL
        self.org.mpesa_number = "123456"
        self.org.daraja_consumer_key = "key"
        self.org.daraja_consumer_secret = "secret"
        self.org.daraja_passkey = "pass"
        self.org.daraja_callback_url = "https://example.com/callback"
        self.org.hotspot_enabled = False
        self.org.save()
        plan = BillingPlan.objects.create(
            organization=self.org,
            name="Home Monthly",
            price="1500.00",
            download_speed_mbps=10,
            upload_speed_mbps=5,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        self.customer.plan = plan
        self.customer.save(update_fields=["plan"])

        response = self.client.get(
            f"/pppoe/{self.org.join_code}/pay/",
            {"account": self.customer.account_number},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["portal_mode"], "pppoe")
        self.assertEqual(
            response.context["account_number"], self.customer.account_number
        )
        self.assertEqual(response.context["pppoe_phone_value"], "0700000088")
        self.assertEqual(response.context["pppoe_selected_plan_id"], plan.pk)
        self.assertFalse(response.context["require_account_lookup"])
        self.assertContains(response, self.customer.account_number)
        self.assertContains(response, 'value="0700000088"')
        self.assertContains(response, "(previous)")
        self.assertContains(response, "Previous package selected")

    def test_pppoe_pay_defaults_to_previous_package_first_in_list(self):
        """Previous plan is pre-selected and listed first; other plans remain choosable."""
        from accounts.models import Organization
        from billing.models import BillingPlan

        self.org.daraja_enabled = True
        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.mpesa_payment_type = Organization.MpesaPaymentType.PAYBILL
        self.org.mpesa_number = "123456"
        self.org.daraja_consumer_key = "key"
        self.org.daraja_consumer_secret = "secret"
        self.org.daraja_passkey = "pass"
        self.org.daraja_callback_url = "https://example.com/callback"
        self.org.save()
        cheap = BillingPlan.objects.create(
            organization=self.org,
            name="Starter",
            price="500.00",
            download_speed_mbps=5,
            upload_speed_mbps=2,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        previous = BillingPlan.objects.create(
            organization=self.org,
            name="Home Monthly",
            price="2500.00",
            download_speed_mbps=20,
            upload_speed_mbps=10,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        self.customer.plan = previous
        self.customer.save(update_fields=["plan"])

        response = self.client.get(
            f"/pppoe/{self.org.join_code}/pay/",
            {"account": self.customer.account_number},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["pppoe_selected_plan_id"], previous.pk)
        plans = list(response.context["pppoe_plans"])
        self.assertEqual(plans[0].pk, previous.pk)
        self.assertTrue(any(p.pk == cheap.pk for p in plans))
        html = response.content.decode()
        selected = f'value="{previous.pk}"'
        pos = html.find(selected)
        self.assertGreater(pos, 0)
        self.assertIn("checked", html[pos : pos + 160])

    def test_pppoe_pay_autofills_account_from_signed_token(self):
        from django.core import signing
        from django.test import RequestFactory

        from core.views import _find_pppoe_customer_from_token, _pppoe_portal_context

        token = signing.dumps(
            {
                "cid": self.customer.pk,
                "org": self.org.pk,
                "mode": "pppoe",
            },
            salt="pppoe-payment",
            compress=True,
        )
        matched = _find_pppoe_customer_from_token(self.org, token)
        self.assertEqual(matched.pk, self.customer.pk)

        request = RequestFactory().get(
            f"/pppoe/{self.org.join_code}/pay/",
            {"t": token},
            REMOTE_ADDR="192.168.88.50",
        )
        context = _pppoe_portal_context(
            self.org, request, customer=matched, identify_error=""
        )
        self.assertEqual(context["account_number"], self.customer.account_number)
        self.assertEqual(context["customer_name"], self.customer.full_name)
        self.assertTrue(context["customer_token"])
        self.assertFalse(context["require_account_lookup"])

        response = self.client.get(
            f"/pppoe/{self.org.join_code}/pay/",
            {"t": token},
            REMOTE_ADDR="192.168.88.50",
        )
        self.assertEqual(response.status_code, 200)
        # Token path must resolve even when the phone is not on 10.20.0.x.
        self.assertEqual(response.context["account_number"], self.customer.account_number)
        self.assertFalse(response.context["require_account_lookup"])

    def test_captive_pay_redirect_html_keeps_signed_token_and_adds_mac(self):
        from core.mikrotik_connect import _captive_pay_redirect_html

        html = _captive_pay_redirect_html(
            "http://billing.example:8000/pppoe/123456/pay/?t=signed.token.value"
        )
        self.assertIn("t=signed.token.value", html)
        self.assertIn("mac=$(mac)", html)
        self.assertNotIn("?t=signed.token.value/?", html)
        # mac must lead the appended query so other fields cannot erase it.
        self.assertIn("t=signed.token.value&mac=$(mac)", html)

    def test_pppoe_pay_ignores_mac_query_on_pppoe_only_page(self):
        """PPPoE pay stays PPPoE-only; MAC belongs on /hotspot/…/pay/."""
        from django.core import signing

        from accounts.models import Organization
        from billing.models import BillingPlan

        self.org.hotspot_enabled = True
        self.org.daraja_enabled = True
        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.mpesa_payment_type = Organization.MpesaPaymentType.PAYBILL
        self.org.mpesa_number = "123456"
        self.org.daraja_consumer_key = "key"
        self.org.daraja_consumer_secret = "secret"
        self.org.daraja_passkey = "pass"
        self.org.daraja_callback_url = "https://example.com/callback"
        self.org.save()
        BillingPlan.objects.create(
            organization=self.org,
            name="Hotspot Hour",
            price="50.00",
            download_speed_mbps=10,
            upload_speed_mbps=5,
            service_type=BillingPlan.ServiceType.HOTSPOT,
        )
        BillingPlan.objects.create(
            organization=self.org,
            name="Home Monthly",
            price="2000.00",
            download_speed_mbps=20,
            upload_speed_mbps=10,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        token = signing.dumps(
            {
                "cid": self.customer.pk,
                "org": self.org.pk,
                "mode": "pppoe",
            },
            salt="pppoe-payment",
            compress=True,
        )
        response = self.client.get(
            f"/pppoe/{self.org.join_code}/pay/",
            {"t": token, "mac": "AA:BB:CC:DD:EE:FF"},
            REMOTE_ADDR="192.168.88.50",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["portal_mode"], "pppoe")
        self.assertEqual(response.context["account_number"], self.customer.account_number)
        self.assertEqual(response.context["hotspot_mac"], "")
        self.assertFalse(response.context["dual_access_tabs"])
        self.assertContains(response, 'id="panel-pppoe"')
        self.assertNotContains(response, 'id="panel-hotspot"')
        self.assertNotContains(response, 'value="AA:BB:CC:DD:EE:FF"')
        self.assertNotContains(response, "Home / PPPoE")
        self.assertNotContains(response, 'id="choose-hotspot"')

    def test_remembered_pppoe_ip_autofills_without_active_session_lookup(self):
        from django.core.cache import cache
        from unittest.mock import patch

        from core.mikrotik_connect import (
            find_pppoe_customer_for_ip,
            remember_pppoe_customer_session_ip,
        )

        cache.clear()
        remember_pppoe_customer_session_ip(self.customer, "10.20.0.77")
        with patch(
            "core.mikrotik_connect._api_session",
            side_effect=AssertionError("API should not be required when IP is cached"),
        ):
            matched = find_pppoe_customer_for_ip(self.org, "10.20.0.77")
        self.assertEqual(matched.pk, self.customer.pk)

        response = self.client.get(
            f"/pppoe/{self.org.join_code}/pay/",
            REMOTE_ADDR="10.20.0.77",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["account_number"], self.customer.account_number)
        self.assertFalse(response.context["require_account_lookup"])

    def test_pppoe_pay_autofills_from_account_hint_cookie(self):
        from accounts.models import Organization
        from billing.models import BillingPlan

        self.org.daraja_enabled = True
        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.mpesa_payment_type = Organization.MpesaPaymentType.PAYBILL
        self.org.mpesa_number = "123456"
        self.org.daraja_consumer_key = "key"
        self.org.daraja_consumer_secret = "secret"
        self.org.daraja_passkey = "pass"
        self.org.daraja_callback_url = "https://example.com/callback"
        self.org.save()
        BillingPlan.objects.create(
            organization=self.org,
            name="Home Monthly",
            price="1500.00",
            download_speed_mbps=10,
            upload_speed_mbps=5,
            service_type=BillingPlan.ServiceType.PPPOE,
        )
        self.client.cookies["pppoe_acct"] = self.customer.account_number
        response = self.client.get(f"/pppoe/{self.org.join_code}/pay/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["account_number"], self.customer.account_number)
        self.assertContains(response, f'value="{self.customer.account_number}"')
        self.assertContains(response, "Matched to this connection")

    def test_pppoe_pay_autofills_when_username_typed_as_account(self):
        from core.views import _find_pppoe_customer_for_pay

        self.customer.pppoe_username = "liveuser"
        self.customer.save(update_fields=["pppoe_username"])
        matched = _find_pppoe_customer_for_pay(
            self.org, account_number="liveuser"
        )
        self.assertIsNotNone(matched)
        self.assertEqual(matched.pk, self.customer.pk)

    def test_pppoe_pay_portal_url_includes_account_for_autofill(self):
        from core.mikrotik_connect import _pppoe_pay_portal_url

        with self.settings(PUBLIC_BASE_URL="http://billing.example:8000"):
            url = _pppoe_pay_portal_url(self.org, customer=self.customer)
        self.assertIn("t=", url)
        self.assertIn(f"account={self.customer.account_number}", url)

    def test_remembered_hotspot_ip_mac_autofills_pay_page(self):
        from django.core.cache import cache
        from unittest.mock import patch

        from accounts.models import Organization
        from billing.models import BillingPlan
        from core.mikrotik_connect import remember_hotspot_mac_for_ip

        cache.clear()
        self.org.hotspot_enabled = True
        self.org.daraja_enabled = True
        self.org.daraja_environment = Organization.DarajaEnvironment.PRODUCTION
        self.org.mpesa_payment_type = Organization.MpesaPaymentType.PAYBILL
        self.org.mpesa_number = "123456"
        self.org.daraja_consumer_key = "key"
        self.org.daraja_consumer_secret = "secret"
        self.org.daraja_passkey = "pass"
        self.org.daraja_callback_url = "https://example.com/callback"
        self.org.save()
        BillingPlan.objects.create(
            organization=self.org,
            name="Hotspot Hour",
            price="50.00",
            download_speed_mbps=10,
            upload_speed_mbps=5,
            service_type=BillingPlan.ServiceType.HOTSPOT,
        )
        remember_hotspot_mac_for_ip(self.org, "10.50.50.44", "11:22:33:44:55:66")
        with patch(
            "core.mikrotik_connect._api_session",
            side_effect=AssertionError("API should not be required when IP MAC is cached"),
        ):
            response = self.client.get(
                f"/hotspot/{self.org.join_code}/pay/",
                REMOTE_ADDR="10.50.50.44",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["hotspot_mac"], "11:22:33:44:55:66")
        self.assertContains(response, 'name="mac" value="11:22:33:44:55:66"')
        self.assertEqual(response.cookies.get("hs_mac").value, "11:22:33:44:55:66")

    def test_hotspot_page_hides_pppoe_choice_when_pppoe_is_off(self):
        self.org.pppoe_compulsory = False
        self.org.hotspot_enabled = True
        self.org.save(update_fields=["pppoe_compulsory", "hotspot_enabled"])

        response = self.client.get(f"/hotspot/{self.org.join_code}/pay/")

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Home / PPPoE")
        self.assertNotContains(response, 'id="choose-pppoe"')


class PppoeOnlyOneSessionTests(SimpleTestCase):
    """PPPoE credentials must dial on only one device at a time."""

    def test_default_profile_sets_only_one_yes(self):
        from core.mikrotik_connect import PPPOE_PROFILE_NAME, _ensure_pppoe_stack

        adds: list[tuple] = []
        aaa_cmds: list[list] = []

        def fake_print(sock, path, **kwargs):
            return []

        def fake_add(sock, path, **props):
            adds.append((path, dict(props)))
            return {"_reply": "!done", "ret": f"*{len(adds)}"}

        def fake_command(sock, words, **kwargs):
            if words and words[0] == "/ppp/aaa/set":
                aaa_cmds.append(list(words))
            return [], {"_reply": "!done"}

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch("core.mikrotik_connect._set", return_value={"_reply": "!done"}),
            patch("core.mikrotik_connect._remove", return_value={"_reply": "!done"}),
            patch("core.mikrotik_connect._command", side_effect=fake_command),
            patch("core.mikrotik_connect._add_or_set_attempts", return_value=({"_reply": "!done"}, "*1")),
            patch("core.mikrotik_connect._ensure_pppoe_nat"),
            patch("core.mikrotik_connect._ensure_pppoe_expired_redirect", return_value=[]),
            patch("core.mikrotik_connect._add_filter_rule", return_value={"_reply": "!done"}),
            patch("core.mikrotik_connect._resolve_lan_interface", return_value="bridge"),
            patch("core.mikrotik_connect._ensure_interface_list"),
            patch("core.mikrotik_connect._ensure_list_member"),
        ):
            profile, notes = _ensure_pppoe_stack(
                object(), lan_interface="bridge", wan_interface="ether1"
            )

        self.assertEqual(profile, PPPOE_PROFILE_NAME)
        profile_adds = [props for path, props in adds if path == "/ppp/profile"]
        self.assertTrue(profile_adds)
        for props in profile_adds:
            self.assertEqual(
                props.get("only-one"),
                "yes",
                msg=f"profile {props.get('name')} must reject a second simultaneous dial",
            )
        self.assertTrue(aaa_cmds)
        self.assertIn("=use-one-session=yes", aaa_cmds[0])
        self.assertTrue(any("one session" in n.lower() for n in notes))

    def test_blocked_and_speed_profiles_set_only_one_yes(self):
        from core.mikrotik_connect import (
            PPPOE_BLOCKED_PROFILE_NAME,
            _ensure_pppoe_blocked_profile,
            _ensure_pppoe_rate_profile,
            _pppoe_speed_profile_name,
        )

        adds: list[tuple] = []
        state = {"/ppp/profile": []}

        def fake_print(sock, path, **kwargs):
            return list(state.get(path, []))

        def fake_add(sock, path, **props):
            adds.append((path, dict(props)))
            item_id = f"*{len(adds)}"
            row = {".id": item_id, **props}
            state.setdefault(path, []).append(row)
            return {"_reply": "!done", "ret": item_id}

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch("core.mikrotik_connect._set", return_value={"_reply": "!done"}),
            patch("core.mikrotik_connect._verify_profile_rate_limit"),
        ):
            _ensure_pppoe_blocked_profile(object())
            speed_name = _ensure_pppoe_rate_profile(
                object(), upload_mbps=5, download_mbps=10
            )

        self.assertEqual(speed_name, _pppoe_speed_profile_name(5, 10))
        by_name = {
            props["name"]: props for path, props in adds if path == "/ppp/profile"
        }
        self.assertEqual(by_name[PPPOE_BLOCKED_PROFILE_NAME]["only-one"], "yes")
        self.assertEqual(by_name[speed_name]["only-one"], "yes")

    def test_ppp_secret_writes_only_one_yes(self):
        from core.mikrotik_connect import _ensure_ppp_secret

        adds: list[tuple] = []
        state = {
            "/ppp/profile": [],
            "/ppp/secret": [],
            "/ppp/active": [],
            "/queue/simple": [],
        }

        def fake_print(sock, path, **kwargs):
            return list(state.get(path, []))

        def fake_add(sock, path, **props):
            adds.append((path, dict(props)))
            item_id = f"*{len(adds)}"
            state.setdefault(path, []).append({".id": item_id, **props})
            return {"_reply": "!done", "ret": item_id}

        def fake_set(sock, path, item_id, **props):
            for row in state.get(path, []):
                if row.get(".id") == item_id:
                    row.update(props)
                    break
            return {"_reply": "!done"}

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch("core.mikrotik_connect._disconnect_pppoe_sessions", return_value=0),
        ):
            action = _ensure_ppp_secret(
                object(),
                username="alice",
                password="secret",
            )

        self.assertEqual(action, "created")
        secret_adds = [props for path, props in adds if path == "/ppp/secret"]
        self.assertEqual(len(secret_adds), 1)
        self.assertEqual(secret_adds[0]["only-one"], "yes")

    def test_ppp_secret_falls_back_when_only_one_unsupported_on_secret(self):
        """Older RouterOS may reject only-one on /ppp/secret; profile still enforces."""
        from core.mikrotik_connect import _ensure_ppp_secret

        adds: list[dict] = []
        state = {"/ppp/secret": [], "/ppp/active": [], "/queue/simple": []}

        def fake_add(sock, path, **props):
            if path == "/ppp/secret" and "only-one" in props:
                return {"_reply": "!trap", "message": "unknown parameter"}
            adds.append(dict(props))
            item_id = f"*{len(adds)}"
            state.setdefault(path, []).append({".id": item_id, **props})
            return {"_reply": "!done", "ret": item_id}

        with (
            patch(
                "core.mikrotik_connect._print",
                side_effect=lambda sock, path, **kw: list(state.get(path, [])),
            ),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch("core.mikrotik_connect._set", return_value={"_reply": "!done"}),
            patch("core.mikrotik_connect._disconnect_pppoe_sessions", return_value=0),
        ):
            action = _ensure_ppp_secret(
                object(),
                username="bob",
                password="secret",
            )

        self.assertEqual(action, "created")
        self.assertEqual(len(adds), 1)
        self.assertNotIn("only-one", adds[0])
        self.assertEqual(adds[0]["name"], "bob")


class PackageSpeedLimitTests(SimpleTestCase):
    """Package Mbps must become real MikroTik rate-limits, not discarded strings."""

    def _plan(self, upload=5, download=10):
        return type(
            "Plan",
            (),
            {
                "upload_speed_mbps": upload,
                "download_speed_mbps": download,
                "speed_mbps": download,
            },
        )()

    def _customer(self, *, plan=None, allowed=True, disabled=False):
        return type(
            "Customer",
            (),
            {
                "plan": plan,
                "status": "active",
                "package_end": object() if allowed else None,
                "service_type": "pppoe",
                "organization": type("Org", (), {"pppoe_compulsory": True})(),
            },
        )()

    def test_rate_limit_string_is_upload_then_download(self):
        from core.mikrotik_connect import (
            _pppoe_rate_limit_for_customer,
            _pppoe_speed_profile_name,
            _ppp_secret_profile_for_customer,
        )

        customer = self._customer(plan=self._plan(upload=8, download=25))
        with patch(
            "core.mikrotik_connect._customer_internet_allowed",
            return_value=True,
        ):
            self.assertEqual(_pppoe_rate_limit_for_customer(customer), "8M/25M")
            self.assertEqual(
                _ppp_secret_profile_for_customer(customer, disabled=False),
                _pppoe_speed_profile_name(8, 25),
            )

    def test_blocked_clients_keep_blocked_profile_not_speed_profile(self):
        from core.mikrotik_connect import (
            PPPOE_BLOCKED_PROFILE_NAME,
            _ppp_secret_profile_for_customer,
        )

        customer = self._customer(plan=self._plan(), allowed=False)
        with patch(
            "core.mikrotik_connect._customer_internet_allowed",
            return_value=False,
        ):
            self.assertEqual(
                _ppp_secret_profile_for_customer(customer, disabled=False),
                PPPOE_BLOCKED_PROFILE_NAME,
            )

    def test_ensure_ppp_secret_creates_speed_profile_and_applies_rate_limit(self):
        from core.mikrotik_connect import (
            _ensure_ppp_secret,
            _pppoe_speed_profile_name,
        )

        profile_name = _pppoe_speed_profile_name(5, 10)
        sets: list[dict] = []
        adds: list[tuple] = []
        state = {
            "/ppp/profile": [],
            "/ppp/secret": [],
            "/ppp/active": [
                {"name": "alice", "address": "10.20.0.50"},
            ],
            "/queue/simple": [],
        }

        def fake_print(sock, path, **kwargs):
            return list(state.get(path, []))

        def fake_add(sock, path, **props):
            adds.append((path, dict(props)))
            item_id = f"*{len(adds)}"
            row = {".id": item_id, **props}
            state.setdefault(path, []).append(row)
            return {"_reply": "!done", "ret": item_id}

        def fake_set(sock, path, item_id, **props):
            sets.append({"path": path, "id": item_id, **props})
            for row in state.get(path, []):
                if row.get(".id") == item_id:
                    row.update(props)
                    break
            return {"_reply": "!done"}

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch("core.mikrotik_connect._remove", return_value={"_reply": "!done"}),
            patch("core.mikrotik_connect._disconnect_pppoe_sessions", return_value=1),
        ):
            action = _ensure_ppp_secret(
                object(),
                username="alice",
                password="secret",
                profile=profile_name,
                rate_limit="5M/10M",
            )

        self.assertEqual(action, "created")
        profile_adds = [props for path, props in adds if path == "/ppp/profile"]
        self.assertTrue(profile_adds)
        self.assertEqual(profile_adds[0]["name"], profile_name)
        self.assertEqual(profile_adds[0]["rate-limit"], "5M/10M")
        self.assertEqual(profile_adds[0]["only-one"], "yes")

        secret_adds = [props for path, props in adds if path == "/ppp/secret"]
        self.assertEqual(secret_adds[0]["profile"], profile_name)
        self.assertEqual(secret_adds[0]["only-one"], "yes")

        rate_sets = [
            item for item in sets if item.get("path") == "/ppp/secret" and "rate-limit" in item
        ]
        self.assertTrue(rate_sets)
        self.assertEqual(rate_sets[0]["rate-limit"], "5M/10M")

        queue_adds = [props for path, props in adds if path == "/queue/simple"]
        self.assertTrue(queue_adds)
        self.assertEqual(queue_adds[0]["max-limit"], "5M/10M")
        self.assertEqual(queue_adds[0]["target"], "10.20.0.50")

    def test_rate_limit_helpers_normalize_and_match(self):
        from core.mikrotik_connect import (
            _normalize_rate_limit_string,
            _parse_rate_limit_mbps,
            _rate_limits_match,
        )

        self.assertEqual(_parse_rate_limit_mbps("5M/10M"), (5, 10))
        self.assertEqual(_parse_rate_limit_mbps("5000k/10m"), (5, 10))
        self.assertEqual(_normalize_rate_limit_string("5m/10M"), "5M/10M")
        self.assertTrue(_rate_limits_match("5M/10M", "5m/10m"))
        self.assertFalse(_rate_limits_match("5M/10M", "8M/25M"))

    def test_ensure_pppoe_rate_profile_rejects_bare_profile(self):
        from core.mikrotik_connect import (
            _ensure_pppoe_rate_profile,
            _pppoe_speed_profile_name,
        )

        name = _pppoe_speed_profile_name(10, 20)
        adds: list[dict] = []

        def fake_add(sock, path, **props):
            adds.append(props)
            # Simulate RouterOS accepting only a bare profile (no rate-limit).
            if "rate-limit" in props:
                return {"_reply": "!trap", "message": "unknown parameter"}
            return {"_reply": "!done", "ret": "*1"}

        with (
            patch("core.mikrotik_connect._print", return_value=[]),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch("core.mikrotik_connect._set", return_value={"_reply": "!trap"}),
        ):
            with self.assertRaises(ConnectionError):
                _ensure_pppoe_rate_profile(
                    object(), upload_mbps=10, download_mbps=20
                )

        self.assertTrue(any("rate-limit" in props for props in adds))

    def test_ensure_pppoe_rate_profile_verifies_written_rate(self):
        from core.mikrotik_connect import (
            _ensure_pppoe_rate_profile,
            _pppoe_speed_profile_name,
        )

        name = _pppoe_speed_profile_name(10, 20)
        state = {"/ppp/profile": []}

        def fake_print(sock, path, **kwargs):
            return list(state.get(path, []))

        def fake_add(sock, path, **props):
            row = {".id": "*9", **props}
            state.setdefault(path, []).append(row)
            return {"_reply": "!done", "ret": "*9"}

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch("core.mikrotik_connect._set", return_value={"_reply": "!trap"}),
        ):
            result = _ensure_pppoe_rate_profile(
                object(), upload_mbps=10, download_mbps=20
            )

        self.assertEqual(result, name)
        self.assertEqual(state["/ppp/profile"][0]["rate-limit"], "10M/20M")

    def test_ensure_hotspot_rate_profile_does_not_fallback_to_default(self):
        from core.mikrotik_connect import (
            ISP_HOTSPOT_USER_PROFILE,
            _ensure_hotspot_rate_profile,
            _hotspot_speed_profile_name,
        )

        org = type(
            "Org",
            (),
            {
                "hotspot_idle_timeout_minutes": 15,
                "hotspot_voucher_validity_hours": 24,
            },
        )()
        with (
            patch("core.mikrotik_connect._print", return_value=[]),
            patch(
                "core.mikrotik_connect._add_or_set_attempts",
                return_value=({"_reply": "!trap", "message": "fail"}, ""),
            ),
        ):
            with self.assertRaises(ConnectionError):
                _ensure_hotspot_rate_profile(
                    object(),
                    organization=org,
                    upload_mbps=3,
                    download_mbps=12,
                )

    def test_ensure_pppoe_rate_profile_updates_existing(self):
        from core.mikrotik_connect import (
            _ensure_pppoe_rate_profile,
            _pppoe_speed_profile_name,
        )

        name = _pppoe_speed_profile_name(10, 20)
        state = {
            "/ppp/profile": [
                {".id": "*3", "name": name, "rate-limit": "5M/10M"},
            ]
        }
        sets: list[dict] = []

        def fake_set(sock, path, item_id, **props):
            sets.append(props)
            for row in state.get(path, []):
                if row.get(".id") == item_id:
                    row.update(props)
                    break
            return {"_reply": "!done"}

        with (
            patch(
                "core.mikrotik_connect._print",
                side_effect=lambda sock, path, **kw: list(state.get(path, [])),
            ),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch("core.mikrotik_connect._add", return_value={"_reply": "!trap"}),
        ):
            result = _ensure_pppoe_rate_profile(
                object(), upload_mbps=10, download_mbps=20
            )

        self.assertEqual(result, name)
        self.assertEqual(sets[0]["rate-limit"], "10M/20M")
        self.assertEqual(sets[0]["only-one"], "yes")

    def test_hotspot_uses_plan_speeds_not_only_org_defaults(self):
        from core.mikrotik_connect import (
            _hotspot_rate_limit_for_customer,
            _hotspot_speed_profile_name,
            _ensure_hotspot_rate_profile,
        )

        plan = self._plan(upload=3, download=12)
        org = type(
            "Org",
            (),
            {
                "hotspot_default_upload_mbps": 5,
                "hotspot_default_download_mbps": 10,
                "hotspot_idle_timeout_minutes": 15,
                "hotspot_voucher_validity_hours": 24,
            },
        )()
        customer = type("Customer", (), {"plan": plan, "organization": org})()
        self.assertEqual(_hotspot_rate_limit_for_customer(customer, org), "3M/12M")

        adds: list[dict] = []
        state = {"/ip/hotspot/user/profile": []}

        def fake_add_or_set(sock, path, item_id, attempts):
            adds.append(attempts[0])
            row = {".id": "*1", **attempts[0]}
            state.setdefault(path, []).append(row)
            return {"_reply": "!done"}, "*1"

        with (
            patch(
                "core.mikrotik_connect._print",
                side_effect=lambda sock, path, **kw: list(state.get(path, [])),
            ),
            patch(
                "core.mikrotik_connect._add_or_set_attempts",
                side_effect=fake_add_or_set,
            ),
        ):
            profile = _ensure_hotspot_rate_profile(
                object(),
                organization=org,
                upload_mbps=3,
                download_mbps=12,
            )

        self.assertEqual(profile, _hotspot_speed_profile_name(3, 12))
        self.assertEqual(adds[0]["rate-limit"], "3M/12M")

    def test_bulk_sync_assigns_speed_profile_for_paid_plan(self):
        from core.mikrotik_connect import (
            PPPOE_BLOCKED_PROFILE_NAME,
            _pppoe_speed_profile_name,
            _sync_organization_pppoe_secrets_on_socket,
        )

        plan = self._plan(upload=5, download=10)
        paid = type(
            "Customer",
            (),
            {
                "pppoe_username": "paid",
                "pppoe_password": "pw",
                "account_number": "A1",
                "status": "active",
                "package_end": timezone_aware_future(),
                "plan": plan,
                "organization": type("Org", (), {"pppoe_compulsory": True})(),
                "service_type": "pppoe",
                "router_id": 1,
            },
        )()
        unpaid = type(
            "Customer",
            (),
            {
                "pppoe_username": "unpaid",
                "pppoe_password": "pw",
                "account_number": "A2",
                "status": "active",
                "package_end": None,
                "plan": plan,
                "organization": type("Org", (), {"pppoe_compulsory": True})(),
                "service_type": "pppoe",
                "router_id": 1,
            },
        )()

        captured = []

        def fake_ensure(sock, **kwargs):
            captured.append(kwargs)
            return "updated"

        router = type("Router", (), {"pk": 1})()
        with (
            patch(
                "core.mikrotik_connect._pppoe_customers_for_router",
                return_value=[paid, unpaid],
            ),
            patch(
                "core.mikrotik_connect._ensure_ppp_secret",
                side_effect=fake_ensure,
            ),
            patch(
                "core.mikrotik_connect._current_ppp_secret_profile",
                return_value="",
            ),
            patch("core.mikrotik_connect._disconnect_pppoe_sessions", return_value=0),
            patch(
                "core.mikrotik_connect._customer_internet_allowed",
                side_effect=lambda c: c.pppoe_username == "paid",
            ),
            patch(
                "core.mikrotik_connect._customer_pppoe_secret_disabled",
                return_value=False,
            ),
            patch(
                "core.mikrotik_connect._block_orphan_pppoe_secrets_on_socket",
                return_value=[],
            ),
        ):
            synced = _sync_organization_pppoe_secrets_on_socket(object(), router)

        self.assertEqual(synced, 2)
        by_user = {item["username"]: item for item in captured}
        self.assertEqual(
            by_user["paid"]["profile"],
            _pppoe_speed_profile_name(5, 10),
        )
        self.assertEqual(by_user["paid"]["rate_limit"], "5M/10M")
        self.assertEqual(by_user["unpaid"]["profile"], PPPOE_BLOCKED_PROFILE_NAME)


class ExpiredCaptivePayTests(SimpleTestCase):
    def test_https_public_url_dstnats_to_http_80(self):
        from core.mikrotik_connect import _portal_http_port

        self.assertEqual(_portal_http_port("https://billing.example.com"), "80")
        self.assertEqual(_portal_http_port("http://192.168.88.254:8000"), "8000")
        self.assertEqual(_portal_http_port("http://billing.example.com"), "80")

    def test_unchanged_blocked_secret_does_not_kick(self):
        from core.mikrotik_connect import (
            PPPOE_BLOCKED_PROFILE_NAME,
            _ensure_ppp_secret,
        )

        state = {
            "/ppp/secret": [
                {
                    ".id": "*1",
                    "name": "alice",
                    "profile": PPPOE_BLOCKED_PROFILE_NAME,
                    "disabled": "false",
                    "password": "secret",
                    "service": "any",
                    "comment": "ispcentric-pppoe",
                }
            ],
            "/ppp/profile": [],
            "/ppp/active": [],
            "/queue/simple": [],
        }
        disconnects = []

        def fake_print(sock, path, **kwargs):
            return list(state.get(path, []))

        def fake_set(sock, path, item_id, **props):
            for row in state.get(path, []):
                if row.get(".id") == item_id:
                    row.update(props)
            return {"_reply": "!done"}

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch("core.mikrotik_connect._add", return_value={"_reply": "!done"}),
            patch(
                "core.mikrotik_connect._disconnect_pppoe_sessions",
                side_effect=lambda sock, username: disconnects.append(username) or 0,
            ),
        ):
            _ensure_ppp_secret(
                object(),
                username="alice",
                password="secret",
                profile=PPPOE_BLOCKED_PROFILE_NAME,
                rate_limit="",
            )

        self.assertEqual(disconnects, [])

    def test_masked_password_print_does_not_kick_stable_secret(self):
        """Masked **** password prints must not tear down dial on every sweep."""
        from core.mikrotik_connect import (
            PPPOE_PROFILE_NAME,
            _ensure_ppp_secret,
            _pppoe_password_is_readable,
        )

        self.assertFalse(_pppoe_password_is_readable("****"))
        self.assertFalse(_pppoe_password_is_readable(""))
        self.assertTrue(_pppoe_password_is_readable("secret"))

        state = {
            "/ppp/secret": [
                {
                    ".id": "*1",
                    "name": "alice",
                    "profile": PPPOE_PROFILE_NAME,
                    "disabled": "false",
                    "password": "****",
                    "service": "any",
                    "comment": "ispcentric-pppoe",
                }
            ],
            "/ppp/profile": [],
            "/ppp/active": [],
            "/queue/simple": [],
        }
        disconnects = []

        def fake_set(sock, path, item_id, **props):
            for row in state.get(path, []):
                if row.get(".id") == item_id:
                    # Keep password masked like RouterOS that hides secrets.
                    if "password" in props:
                        row["password"] = "****"
                    else:
                        row.update(props)
            return {"_reply": "!done"}

        with (
            patch(
                "core.mikrotik_connect._print",
                side_effect=lambda sock, path, **kw: list(state.get(path, [])),
            ),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch("core.mikrotik_connect._add", return_value={"_reply": "!done"}),
            patch(
                "core.mikrotik_connect._disconnect_pppoe_sessions",
                side_effect=lambda sock, username: disconnects.append(username) or 0,
            ),
        ):
            _ensure_ppp_secret(
                object(),
                username="alice",
                password="secret",
                profile=PPPOE_PROFILE_NAME,
                rate_limit="",
            )

        self.assertEqual(disconnects, [])

    def test_profile_flip_to_blocked_kicks(self):
        from core.mikrotik_connect import (
            PPPOE_BLOCKED_PROFILE_NAME,
            _ensure_ppp_secret,
            _pppoe_speed_profile_name,
        )

        speed = _pppoe_speed_profile_name(5, 10)
        state = {
            "/ppp/secret": [
                {
                    ".id": "*1",
                    "name": "alice",
                    "profile": speed,
                    "disabled": "false",
                    "password": "secret",
                    "service": "any",
                    "comment": "ispcentric-pppoe",
                }
            ],
            "/ppp/profile": [],
            "/ppp/active": [],
            "/queue/simple": [],
        }
        disconnects = []

        def fake_set(sock, path, item_id, **props):
            for row in state.get(path, []):
                if row.get(".id") == item_id:
                    row.update(props)
            return {"_reply": "!done"}

        with (
            patch(
                "core.mikrotik_connect._print",
                side_effect=lambda sock, path, **kw: list(state.get(path, [])),
            ),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch("core.mikrotik_connect._add", return_value={"_reply": "!done"}),
            patch(
                "core.mikrotik_connect._disconnect_pppoe_sessions",
                side_effect=lambda sock, username: disconnects.append(username) or 1,
            ),
        ):
            _ensure_ppp_secret(
                object(),
                username="alice",
                password="secret",
                profile=PPPOE_BLOCKED_PROFILE_NAME,
                rate_limit="",
            )

        self.assertEqual(disconnects, ["alice"])

    def test_blocked_secret_with_unblocked_active_session_is_kicked(self):
        """
        If the first kick failed, the secret stays on ispcentric-blocked while
        the live session still has a paid address-list. Later provision must
        kick again so surfing stops immediately.
        """
        from types import SimpleNamespace
        from unittest.mock import MagicMock, patch

        from core.mikrotik_connect import (
            PPPOE_BLOCKED_PROFILE_NAME,
            provision_customer_pppoe,
        )

        customer = SimpleNamespace(
            pk=42,
            router_id=1,
            router=SimpleNamespace(
                pk=1,
                api_host="10.0.0.1",
                username="admin",
                password="x",
                host="10.0.0.1",
                name="NAS",
            ),
            organization=SimpleNamespace(pk=1, join_code="111111"),
            organization_id=1,
            pppoe_username="alice",
            pppoe_password="secret",
            plan=None,
            account_number="PPP-42",
            save=MagicMock(),
        )
        disconnects = []

        class FakeSock:
            pass

        class FakeSession:
            def __enter__(self):
                return FakeSock()

            def __exit__(self, *args):
                return False

        with (
            patch(
                "core.mikrotik_connect._customer_internet_allowed",
                return_value=False,
            ),
            patch(
                "core.mikrotik_connect._customer_pppoe_secret_disabled",
                return_value=False,
            ),
            patch(
                "core.mikrotik_connect._ppp_secret_profile_for_customer",
                return_value=PPPOE_BLOCKED_PROFILE_NAME,
            ),
            patch(
                "core.mikrotik_connect._pppoe_rate_limit_for_customer",
                return_value="",
            ),
            patch(
                "core.mikrotik_connect._router_api_host_candidates",
                return_value=["10.0.0.1"],
            ),
            patch(
                "core.mikrotik_connect.socket.create_connection",
                return_value=MagicMock(
                    __enter__=lambda *a, **k: MagicMock(),
                    __exit__=lambda *a, **k: False,
                ),
            ),
            patch("core.mikrotik_connect._api_session", return_value=FakeSession()),
            patch(
                "core.mikrotik_connect._current_ppp_secret_profile",
                return_value=PPPOE_BLOCKED_PROFILE_NAME,
            ),
            patch(
                "core.mikrotik_connect._active_pppoe_session_is_blocked",
                return_value=False,
            ),
            patch(
                "core.mikrotik_connect._pppoe_has_active_session",
                return_value=True,
            ),
            patch(
                "core.mikrotik_connect._ensure_pppoe_expired_access",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._ensure_pppoe_blocked_profile",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._ensure_ppp_secret",
                return_value="updated",
            ),
            patch(
                "core.mikrotik_connect._disconnect_pppoe_sessions",
                side_effect=lambda sock, username: disconnects.append(username) or 1,
            ),
            patch(
                "core.mikrotik_connect._billing_portal_base_url",
                return_value="http://billing.example",
            ),
            patch(
                "core.mikrotik_connect.cpe_renew_clear_is_pending",
                return_value=False,
            ),
        ):
            result = provision_customer_pppoe(customer, ensure_stack=False)

        self.assertTrue(result.get("ok"))
        self.assertEqual(disconnects, ["alice"])

    def test_expired_access_repair_loop_reinstalls_missing_redirect(self):
        """When dst-nat vanishes, correction loop must put it back."""
        from core.mikrotik_connect import (
            PPPOE_BLOCKED_ADDRESS_LIST,
            PPP_SECRET_TAG,
            _ensure_pppoe_expired_access,
        )

        nat_rows: list[dict] = []
        filter_rows: list[dict] = []
        adds: list[tuple] = []

        def fake_print(sock, path, **kwargs):
            if path == "/ip/firewall/nat":
                return list(nat_rows)
            if path == "/ip/firewall/filter":
                return list(filter_rows)
            return []

        def fake_add(sock, path, **props):
            adds.append((path, dict(props)))
            item = {".id": f"*{len(adds)}", **props}
            if path == "/ip/firewall/nat":
                # First HTTP redirect attempt "fails" to stick until attempt 2.
                if (
                    props.get("comment", "").endswith("expired redirect")
                    and len([a for a in adds if "expired redirect" in a[1].get("comment", "")])
                    == 1
                ):
                    return {"_reply": "!done", "ret": item[".id"]}
                nat_rows.append(item)
            elif path == "/ip/firewall/filter":
                filter_rows.append(item)
            return {"_reply": "!done", "ret": item[".id"]}

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch("core.mikrotik_connect._remove", return_value={"_reply": "!done"}),
            patch(
                "core.mikrotik_connect._add_filter_rule",
                side_effect=lambda sock, rule, place_before="": fake_add(
                    sock, "/ip/firewall/filter", **rule
                ),
            ),
            patch(
                "core.mikrotik_connect._billing_portal_base_url",
                return_value="http://billing.example:8000",
            ),
            patch(
                "core.mikrotik_connect._portal_target_ipv4",
                return_value="203.0.113.10",
            ),
            patch("core.mikrotik_connect._first_forward_drop_id", return_value=""),
        ):
            notes = _ensure_pppoe_expired_access(object())

        redirect_adds = [
            props
            for path, props in adds
            if path == "/ip/firewall/nat"
            and "expired redirect" in props.get("comment", "")
        ]
        self.assertGreaterEqual(len(redirect_adds), 2)
        self.assertEqual(redirect_adds[0]["to-addresses"], "203.0.113.10")
        self.assertEqual(
            redirect_adds[0]["src-address-list"], PPPOE_BLOCKED_ADDRESS_LIST
        )
        self.assertTrue(
            any("repaired on attempt" in n or "expired PPPoE HTTP" in n for n in notes)
            or any(PPP_SECRET_TAG in n for n in notes)
        )
        self.assertTrue(
            any(
                row.get("comment", "").endswith("expired redirect")
                for row in nat_rows
            )
        )

    def test_expired_redirect_skips_rewrite_when_rules_already_correct(self):
        """Idempotent install must not wipe+recreate good rules (WireGuard timeouts)."""
        from core.mikrotik_connect import (
            PPP_SECRET_TAG,
            PPPOE_BLOCKED_ADDRESS_LIST,
            _ensure_pppoe_expired_redirect,
        )

        nat_rows = [
            {
                ".id": "*d1",
                "chain": "dstnat",
                "action": "redirect",
                "protocol": "udp",
                "dst-port": "53",
                "to-ports": "53",
                "src-address-list": PPPOE_BLOCKED_ADDRESS_LIST,
                "comment": f"{PPP_SECRET_TAG} expired dns",
            },
            {
                ".id": "*d2",
                "chain": "dstnat",
                "action": "redirect",
                "protocol": "tcp",
                "dst-port": "53",
                "to-ports": "53",
                "src-address-list": PPPOE_BLOCKED_ADDRESS_LIST,
                "comment": f"{PPP_SECRET_TAG} expired dns",
            },
            {
                ".id": "*h1",
                "chain": "dstnat",
                "action": "dst-nat",
                "protocol": "tcp",
                "dst-port": "80",
                "to-ports": "8000",
                "to-addresses": "203.0.113.10",
                "src-address-list": PPPOE_BLOCKED_ADDRESS_LIST,
                "comment": f"{PPP_SECRET_TAG} expired redirect",
            },
        ]
        adds: list[tuple] = []
        removes: list[str] = []

        with (
            patch(
                "core.mikrotik_connect._print",
                side_effect=lambda sock, path, **kw: list(nat_rows),
            ),
            patch(
                "core.mikrotik_connect._add",
                side_effect=lambda sock, path, **props: (
                    adds.append((path, props)) or {"_reply": "!done", "ret": "*x"}
                ),
            ),
            patch(
                "core.mikrotik_connect._remove",
                side_effect=lambda sock, path, item_id: (
                    removes.append(item_id) or {"_reply": "!done"}
                ),
            ),
        ):
            notes = _ensure_pppoe_expired_redirect(
                object(), "203.0.113.10", "http://billing.example:8000"
            )

        self.assertEqual(adds, [])
        self.assertEqual(removes, [])
        self.assertTrue(any("already present" in n for n in notes))
        self.assertTrue(any("->" in n for n in notes))
        self.assertFalse(any("\u2192" in n for n in notes))

    def test_repair_expired_redirect_retries_after_timeout(self):
        from types import SimpleNamespace

        from core.mikrotik_connect import repair_router_expired_captive_redirect

        router = SimpleNamespace(
            api_host="10.9.0.8",
            host="10.9.0.8",
            username="admin",
            password="x",
        )
        sessions = {"n": 0}

        class _FakeSession:
            def __enter__(self):
                sessions["n"] += 1
                if sessions["n"] == 1:
                    raise TimeoutError("timed out")
                return object()

            def __exit__(self, *args):
                return False

        with (
            patch(
                "core.mikrotik_connect._api_session",
                side_effect=lambda *a, **k: _FakeSession(),
            ),
            patch(
                "core.mikrotik_connect._ensure_pppoe_expired_access",
                return_value=["expired PPPoE HTTP -> 203.0.113.10:80"],
            ),
            patch(
                "core.mikrotik_connect._ensure_pppoe_blocked_profile",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._billing_portal_base_url",
                return_value="http://billing.example",
            ),
        ):
            result = repair_router_expired_captive_redirect(router, timeout=1.0)

        self.assertTrue(result["ok"])
        self.assertEqual(result["attempt"], 2)
        self.assertIn("session attempt 2", result["message"])
        self.assertEqual(sessions["n"], 2)

    def test_sweep_log_text_strips_unicode_arrows(self):
        from core.mikrotik_connect import sweep_log_text

        self.assertEqual(
            sweep_log_text("expired PPPoE HTTP \u2192 10.0.0.1:80"),
            "expired PPPoE HTTP -> 10.0.0.1:80",
        )
        self.assertEqual(
            sweep_log_text("CPE is offline \u2014 renew Wi\u2011Fi"),
            "CPE is offline - renew Wi-Fi",
        )

    def test_captive_html_is_mobile_ready(self):
        from core.mikrotik_connect import _captive_pay_redirect_html

        html = _captive_pay_redirect_html(
            "http://billing.example/pppoe/999999/pay/?t=tok"
        )
        self.assertIn('name="viewport"', html)
        self.assertIn("window.location.replace", html)
        self.assertIn("window.top.location.replace", html)
        self.assertIn("$(if http-status == 302)", html)
        self.assertIn(
            '$(if http-header == "Location")http://billing.example/pppoe/999999/pay/?t=tok&mac=',
            html,
        )

    def test_enable_cpe_renew_publishes_dhcp_option_114(self):
        from unittest.mock import MagicMock

        from core.mikrotik_connect import _enable_cpe_renew_hotspot

        sock = MagicMock()
        dhcp_calls: list[str] = []
        order: list[str] = []
        profile_sets: list[dict] = []

        def track_pages(*_a, **_k):
            order.append("pages")
            return ["installed hotspot/login.html"]

        def track_wan(*_a, **_k):
            order.append("wan")
            return ["client internet blocked on CPE (renew popup only)"]

        def track_set(sock, path, item_id, **props):
            if path == "/ip/hotspot/profile":
                profile_sets.append(props)
            return {"_reply": "!done"}

        def track_add(sock, path, **props):
            if path == "/ip/hotspot/profile":
                profile_sets.append(props)
            return {"_reply": "!done", "ret": "*1"}

        with (
            patch(
                "core.mikrotik_connect._cpe_lan_bridge_name",
                return_value="bridge",
            ),
            patch(
                "core.mikrotik_connect._cpe_lan_gateway_ip",
                return_value="192.168.88.1",
            ),
            patch("core.mikrotik_connect._ensure_tagged_ip_address"),
            patch("core.mikrotik_connect._ensure_tagged_pool"),
            patch("core.mikrotik_connect._print", return_value=[]),
            patch(
                "core.mikrotik_connect._add",
                side_effect=track_add,
            ),
            patch(
                "core.mikrotik_connect._set",
                side_effect=track_set,
            ),
            patch(
                "core.mikrotik_connect._clear_captive_dns_hijack",
                return_value=2,
            ),
            patch(
                "core.mikrotik_connect._clear_https_capture_redirect",
                return_value=False,
            ),
            patch(
                "core.mikrotik_connect._clear_hotspot_sessions",
                return_value=["cleared 3 Hotspot session(s) so the pay popup can open"],
            ),
            patch(
                "core.mikrotik_connect._ensure_cpe_portal_access",
                return_value=["walled garden for billing"],
            ),
            patch(
                "core.mikrotik_connect._ensure_cpe_wan_block",
                side_effect=track_wan,
            ),
            patch(
                "core.mikrotik_connect._fetch_hotspot_pages",
                side_effect=track_pages,
            ),
            patch(
                "core.mikrotik_connect._bounce_cpe_wifi_clients",
                return_value=["bounced 1"],
            ),
            patch(
                "core.mikrotik_connect._ensure_captive_portal_dhcp_option",
                side_effect=lambda sock, url, comment="": (
                    dhcp_calls.append(url) or [f"option 114 → {url}"]
                ),
            ),
            patch("core.mikrotik_connect._command", return_value=([], {})),
        ):
            notes = _enable_cpe_renew_hotspot(
                sock,
                portal_url="http://billing.example/pppoe/121212/pay/?t=abc",
            )

        self.assertEqual(
            dhcp_calls,
            ["http://billing.example/pppoe/121212/pay/?t=abc"],
        )
        self.assertTrue(any("option 114" in n for n in notes))
        self.assertTrue(any("cleared 2 captive DNS" in n for n in notes))
        self.assertTrue(any("pay popup can open" in n for n in notes))
        # Cookie auto-login would leave phones "connected, no internet".
        self.assertTrue(profile_sets)
        for props in profile_sets:
            login_by = props.get("login-by", "")
            self.assertNotIn("cookie", login_by)
            self.assertNotIn("https", login_by)
            self.assertIn("http-pap", login_by)
        # login.html must install before WAN drop so /tool/fetch still works.
        self.assertEqual(order, ["pages", "wan"])

    def test_clear_hotspot_sessions_removes_cookies_and_hosts(self):
        from unittest.mock import MagicMock

        from core.mikrotik_connect import _clear_hotspot_sessions

        removed: list[tuple[str, str]] = []

        def fake_print(sock, path, **kwargs):
            if path == "/ip/hotspot/cookie":
                return [{".id": "*c1"}]
            if path == "/ip/hotspot/active":
                return [{".id": "*a1"}]
            if path == "/ip/hotspot/host":
                return [{".id": "*h1"}, {".id": "*h2"}]
            return []

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch(
                "core.mikrotik_connect._remove",
                side_effect=lambda sock, path, item_id: (
                    removed.append((path, item_id)) or {"_reply": "!done"}
                ),
            ),
        ):
            notes = _clear_hotspot_sessions(MagicMock())

        self.assertEqual(
            removed,
            [
                ("/ip/hotspot/cookie", "*c1"),
                ("/ip/hotspot/active", "*a1"),
                ("/ip/hotspot/host", "*h1"),
                ("/ip/hotspot/host", "*h2"),
            ],
        )
        self.assertTrue(any("pay popup can open" in n for n in notes))

    def test_enable_cpe_renew_aborts_without_absolute_pay_url(self):
        from unittest.mock import MagicMock

        from core.mikrotik_connect import _enable_cpe_renew_hotspot

        sock = MagicMock()
        with patch(
            "core.mikrotik_connect._resolve_absolute_captive_url",
            return_value="",
        ):
            with self.assertRaises(ConnectionError) as ctx:
                _enable_cpe_renew_hotspot(sock, portal_url="/pppoe/121212/pay/")
        self.assertIn("absolute pay URL", str(ctx.exception))

    def test_enable_cpe_renew_aborts_when_login_html_missing(self):
        from unittest.mock import MagicMock

        from core.mikrotik_connect import _enable_cpe_renew_hotspot

        sock = MagicMock()
        with (
            patch(
                "core.mikrotik_connect._cpe_lan_bridge_name",
                return_value="bridge",
            ),
            patch(
                "core.mikrotik_connect._cpe_lan_gateway_ip",
                return_value="192.168.88.1",
            ),
            patch("core.mikrotik_connect._ensure_tagged_ip_address"),
            patch("core.mikrotik_connect._ensure_tagged_pool"),
            patch("core.mikrotik_connect._print", return_value=[]),
            patch(
                "core.mikrotik_connect._add",
                return_value={"_reply": "!done", "ret": "*1"},
            ),
            patch(
                "core.mikrotik_connect._set",
                return_value={"_reply": "!done"},
            ),
            patch(
                "core.mikrotik_connect._clear_captive_dns_hijack",
                return_value=0,
            ),
            patch(
                "core.mikrotik_connect._clear_https_capture_redirect",
                return_value=False,
            ),
            patch(
                "core.mikrotik_connect._clear_hotspot_sessions",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._ensure_cpe_portal_access",
                return_value=["walled garden"],
            ),
            patch(
                "core.mikrotik_connect._fetch_hotspot_pages",
                return_value=["could not write hotspot/login.html"],
            ),
            patch("core.mikrotik_connect._command", return_value=([], {})),
        ):
            with self.assertRaises(ConnectionError) as ctx:
                _enable_cpe_renew_hotspot(
                    sock,
                    portal_url="http://billing.example/pppoe/1/pay/",
                )
        self.assertIn("login.html", str(ctx.exception))

    def test_pppoe_pay_portal_url_accepts_query_and_prefers_http(self):
        from types import SimpleNamespace

        from core.mikrotik_connect import _pppoe_pay_portal_url

        org = SimpleNamespace(pk=1, join_code="999999")
        with self.settings(PUBLIC_BASE_URL="https://billing.example"):
            url = _pppoe_pay_portal_url(
                org,
                "https://billing.example/pppoe/999999/pay/?t=keep",
            )
        self.assertTrue(url.startswith("http://billing.example/pppoe/999999/pay/"))
        self.assertIn("t=keep", url)

    def test_pppoe_pay_portal_url_empty_without_base(self):
        from types import SimpleNamespace

        from core.mikrotik_connect import _pppoe_pay_portal_url

        org = SimpleNamespace(pk=1, join_code="999999")
        with patch(
            "core.mikrotik_connect._billing_portal_base_url",
            return_value="",
        ):
            self.assertEqual(_pppoe_pay_portal_url(org), "")


class IspHotspotInstantPayTests(SimpleTestCase):
    """Non-PPPoE ISP Hotspot: connect Wi‑Fi → /hotspot/…/pay/ immediately."""

    def test_prefer_http_captive_url(self):
        from core.mikrotik_connect import _prefer_http_captive_url

        self.assertEqual(
            _prefer_http_captive_url("https://billing.example/hotspot/1/pay/"),
            "http://billing.example/hotspot/1/pay/",
        )
        self.assertEqual(
            _prefer_http_captive_url("http://billing.example:8000/hotspot/1/pay/"),
            "http://billing.example:8000/hotspot/1/pay/",
        )

    def test_enable_isp_hotspot_publishes_option_114_after_login_html(self):
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        from core.mikrotik_connect import (
            ISP_HOTSPOT_POOL,
            _ensure_isp_hotspot_stack,
        )

        sock = MagicMock()
        org = SimpleNamespace(name="Hot ISP", join_code="505050")
        order: list[str] = []
        dhcp_calls: list[str] = []
        server_attempts_seen: list = []

        def track_pages(*_a, **_k):
            order.append("pages")
            return ["installed hotspot/login.html", "installed hotspot/rlogin.html"]

        def track_dhcp(sock, url, comment=""):
            order.append("dhcp")
            dhcp_calls.append(url)
            return [f"option 114 → {url}"]

        def track_bounce(*_a, **_k):
            order.append("bounce")
            return ["bounced 2 Wi‑Fi client(s) for Hotspot pay popup"]

        def fake_add_or_set(sock, path, item_id, attempts):
            if path == "/ip/hotspot":
                server_attempts_seen.extend(attempts)
            return {"_reply": "!done"}, "*1"

        with (
            patch(
                "core.mikrotik_connect._resolve_lan_interface",
                return_value="bridge",
            ),
            patch(
                "core.mikrotik_connect._lan_ipv4_for_interface",
                return_value="10.50.50.1",
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_wireless_on_lan",
                return_value=[],
            ),
            patch("core.mikrotik_connect._ensure_tagged_ip_address"),
            patch("core.mikrotik_connect._ensure_tagged_pool"),
            patch(
                "core.mikrotik_connect._ensure_isp_hotspot_user_profile",
                return_value=[],
            ),
            patch("core.mikrotik_connect._print", return_value=[]),
            patch(
                "core.mikrotik_connect._add_or_set_attempts",
                side_effect=fake_add_or_set,
            ),
            patch(
                "core.mikrotik_connect._clear_captive_dns_hijack",
                return_value=1,
            ),
            patch(
                "core.mikrotik_connect._clear_https_capture_redirect",
                return_value=False,
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_owns_http_port",
                return_value=["Hotspot owns :80"],
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_walled_garden",
                return_value=["walled garden"],
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_server_bypass",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._fetch_isp_hotspot_pages",
                side_effect=track_pages,
            ),
            patch(
                "core.mikrotik_connect._ensure_captive_portal_dhcp_option",
                side_effect=track_dhcp,
            ),
            patch(
                "core.mikrotik_connect._bounce_isp_hotspot_clients",
                side_effect=track_bounce,
            ),
        ):
            notes = _ensure_isp_hotspot_stack(
                sock,
                lan_interface="bridge",
                organization=org,
                pay_url="https://billing.example/hotspot/505050/pay/",
            )

        self.assertEqual(order, ["pages", "dhcp", "bounce"])
        self.assertEqual(
            dhcp_calls,
            ["http://billing.example/hotspot/505050/pay/"],
        )
        self.assertTrue(any("option 114" in n for n in notes))
        self.assertTrue(any("Hotspot pay popup" in n for n in notes))
        # Dedicated 10.50.50 setup must prefer the identifiable Hotspot pool.
        self.assertEqual(server_attempts_seen[0].get("address-pool"), ISP_HOTSPOT_POOL)

    def test_enable_isp_hotspot_prefers_dedicated_pool_when_lan_has_ipv4(self):
        """Existing LAN IPv4 must not skip 10.50.50 — otherwise is_hotspot_pool_ip fails."""
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        from core.mikrotik_connect import (
            ISP_HOTSPOT_POOL,
            _ensure_isp_hotspot_stack,
        )

        sock = MagicMock()
        org = SimpleNamespace(name="Hot ISP", join_code="505050")
        server_attempts_seen: list = []
        ensured_ips: list[str] = []
        ensured_pools: list[str] = []

        def fake_add_or_set(sock, path, item_id, attempts):
            if path == "/ip/hotspot":
                server_attempts_seen.extend(attempts)
            return {"_reply": "!done"}, "*1"

        def track_ip(*_a, **kwargs):
            ensured_ips.append(kwargs.get("address") or "")

        def track_pool(*_a, **kwargs):
            ensured_pools.append(kwargs.get("name") or "")

        with (
            patch(
                "core.mikrotik_connect._resolve_lan_interface",
                return_value="bridge",
            ),
            patch(
                "core.mikrotik_connect._lan_ipv4_for_interface",
                return_value="192.168.88.1",
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_wireless_on_lan",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._ensure_tagged_ip_address",
                side_effect=track_ip,
            ),
            patch(
                "core.mikrotik_connect._ensure_tagged_pool",
                side_effect=track_pool,
            ),
            patch(
                "core.mikrotik_connect._ensure_isp_hotspot_user_profile",
                return_value=[],
            ),
            patch("core.mikrotik_connect._print", return_value=[]),
            patch(
                "core.mikrotik_connect._add_or_set_attempts",
                side_effect=fake_add_or_set,
            ),
            patch(
                "core.mikrotik_connect._clear_captive_dns_hijack",
                return_value=0,
            ),
            patch(
                "core.mikrotik_connect._clear_https_capture_redirect",
                return_value=False,
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_owns_http_port",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_walled_garden",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_server_bypass",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._fetch_isp_hotspot_pages",
                return_value=["installed hotspot/login.html"],
            ),
            patch(
                "core.mikrotik_connect._ensure_captive_portal_dhcp_option",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._bounce_isp_hotspot_clients",
                return_value=[],
            ),
        ):
            notes = _ensure_isp_hotspot_stack(
                sock,
                lan_interface="bridge",
                organization=org,
                pay_url="http://billing.example/hotspot/505050/pay/",
            )

        self.assertTrue(any("10.50.50.1/24" in a for a in ensured_ips))
        self.assertIn(ISP_HOTSPOT_POOL, ensured_pools)
        self.assertEqual(server_attempts_seen[0].get("address-pool"), ISP_HOTSPOT_POOL)
        self.assertTrue(any("LAN keeps 192.168.88.1" in n for n in notes))

    def test_enable_isp_hotspot_aborts_without_absolute_pay_url(self):
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        from core.mikrotik_connect import _ensure_isp_hotspot_stack

        sock = MagicMock()
        org = SimpleNamespace(name="Hot ISP", join_code="505050")
        with patch(
            "core.mikrotik_connect._billing_portal_base_url",
            return_value="",
        ):
            with self.assertRaises(ConnectionError) as ctx:
                _ensure_isp_hotspot_stack(
                    sock,
                    lan_interface="bridge",
                    organization=org,
                    pay_url="/hotspot/505050/pay/",
                )
        self.assertIn("absolute pay URL", str(ctx.exception))

    def test_enable_isp_hotspot_aborts_when_login_html_missing(self):
        from unittest.mock import MagicMock
        from types import SimpleNamespace

        from core.mikrotik_connect import _ensure_isp_hotspot_stack

        sock = MagicMock()
        org = SimpleNamespace(name="Hot ISP", join_code="505050")
        with (
            patch(
                "core.mikrotik_connect._resolve_lan_interface",
                return_value="bridge",
            ),
            patch(
                "core.mikrotik_connect._lan_ipv4_for_interface",
                return_value="10.50.50.1",
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_wireless_on_lan",
                return_value=[],
            ),
            patch("core.mikrotik_connect._ensure_tagged_ip_address"),
            patch("core.mikrotik_connect._ensure_tagged_pool"),
            patch(
                "core.mikrotik_connect._ensure_isp_hotspot_user_profile",
                return_value=[],
            ),
            patch("core.mikrotik_connect._print", return_value=[]),
            patch(
                "core.mikrotik_connect._add_or_set_attempts",
                return_value=({"_reply": "!done"}, "*1"),
            ),
            patch(
                "core.mikrotik_connect._clear_captive_dns_hijack",
                return_value=0,
            ),
            patch(
                "core.mikrotik_connect._clear_https_capture_redirect",
                return_value=False,
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_owns_http_port",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_walled_garden",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._ensure_hotspot_server_bypass",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._fetch_isp_hotspot_pages",
                return_value=["could not write hotspot/login.html"],
            ),
        ):
            with self.assertRaises(ConnectionError) as ctx:
                _ensure_isp_hotspot_stack(
                    sock,
                    lan_interface="bridge",
                    organization=org,
                    pay_url="http://billing.example/hotspot/505050/pay/",
                )
        self.assertIn("login.html", str(ctx.exception))

    def test_fetch_isp_pages_writes_hotspot_pay_redirect(self):
        from unittest.mock import MagicMock

        from core.mikrotik_connect import _fetch_isp_hotspot_pages

        written: dict[str, str] = {}

        def fake_write(sock, dst, html):
            written[dst] = html
            return True

        with (
            patch(
                "core.mikrotik_connect._delete_hotspot_file",
                return_value=False,
            ),
            patch(
                "core.mikrotik_connect._write_hotspot_html_file",
                side_effect=fake_write,
            ),
        ):
            notes = _fetch_isp_hotspot_pages(
                MagicMock(),
                pay_url="https://billing.example/hotspot/505050/pay/",
                welcome_url="https://billing.example/hotspot/505050/welcome/",
            )

        self.assertTrue(any("installed hotspot/login.html" in n for n in notes))
        login = written["hotspot/login.html"]
        self.assertIn("http://billing.example/hotspot/505050/pay", login)
        self.assertIn("mac=$(mac)", login)
        self.assertIn("$(if http-status == 302)", login)
        self.assertIn(
            "http://billing.example/hotspot/505050/welcome/",
            written["hotspot/alogin.html"],
        )

    def test_apply_hotspot_rejects_missing_public_base(self):
        from types import SimpleNamespace

        from core.mikrotik_connect import apply_hotspot_on_router

        router = SimpleNamespace(
            pk=1,
            name="NAS",
            host="192.168.88.1",
            username="admin",
            password="x",
            organization=SimpleNamespace(pk=9, join_code="505050", name="ISP"),
            account_status="active",
            lan_bridge="bridge",
            wan_interface="ether1",
            vpn_address="",
            wifi_ssid="",
        )
        with (
            patch(
                "core.mikrotik_connect._hotspot_portal_urls_for_org",
                return_value={"pay_url": "/hotspot/505050/pay/"},
            ),
            patch(
                "core.mikrotik_connect._billing_portal_base_url",
                return_value="",
            ),
            patch(
                "core.mikrotik_connect._resolve_absolute_captive_url",
                return_value="",
            ),
        ):
            result = apply_hotspot_on_router(router, enabled=True)
        self.assertFalse(result["ok"])
        self.assertIn("absolute pay URL", result["error"])


class AccessFlowCorrectionLoopTests(TestCase):
    """
    End-to-end correction loops for PPPoE expire/restore and ISP Hotspot captive.

    These encode the invariants that keep phones off "connected, no internet"
    and on the correct pay page.
    """

    def setUp(self):
        from datetime import timedelta

        from django.contrib.auth.models import User
        from django.core.cache import cache
        from django.utils import timezone

        from accounts.models import Organization
        from billing.models import Customer

        cache.clear()
        self.owner = User.objects.create_user("loop-owner", password="x")
        self.org = Organization.objects.create(
            name="Loop ISP",
            owner=self.owner,
            join_code="606061",
            hotspot_enabled=True,
            pppoe_compulsory=True,
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Loop NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.0.0.1",
            username="admin",
            password="secret",
        )
        self.pppoe = Customer.objects.create(
            organization=self.org,
            full_name="Loop Dialer",
            phone="0711111111",
            account_number="LOOP-PPP-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="loop1",
            pppoe_password="pass",
            status=Customer.Status.ACTIVE,
            router=self.router,
            package_start=timezone.now() - timedelta(days=5),
            package_end=timezone.now() - timedelta(days=1),
        )
        self.hotspot = Customer.objects.create(
            organization=self.org,
            full_name="Loop Hotspot",
            phone="0722222222",
            account_number="LOOP-HS-1",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:11",
            status=Customer.Status.ACTIVE,
            router=self.router,
            package_start=timezone.now() - timedelta(hours=3),
            package_end=timezone.now() - timedelta(hours=1),
        )

    def test_pppoe_expiry_retries_portal_until_ok_then_blocks(self):
        from core.mikrotik_connect import (
            PPPOE_BLOCKED_PROFILE_NAME,
            sync_customer_subscription_access,
        )

        portal_calls = []
        order = []

        def portal_side_effect(customer, *, enabled, portal_url=""):
            portal_calls.append(enabled)
            order.append("portal")
            # Fail once, then succeed — correction loop must keep trying.
            if len(portal_calls) == 1:
                return {"ok": False, "skipped": False, "error": "login.html missing"}
            return {"ok": True, "enabled": enabled, "notes": ["login ready"]}

        def provision_side_effect(customer, **kwargs):
            order.append("provision")
            return {"ok": True, "profile": PPPOE_BLOCKED_PROFILE_NAME}

        with (
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
                side_effect=portal_side_effect,
            ),
            patch(
                "core.mikrotik_connect.provision_customer_pppoe",
                side_effect=provision_side_effect,
            ),
            patch(
                "core.mikrotik_connect._pppoe_pay_portal_url",
                return_value="http://billing.example/pppoe/606061/pay/?t=x",
            ),
        ):
            result = sync_customer_subscription_access(self.pppoe, provision=True)

        self.assertFalse(result["allowed"])
        self.assertTrue(result["ok"])
        self.assertTrue(result["portal"]["ok"])
        self.assertGreaterEqual(len(portal_calls), 2)
        self.assertEqual(order[0], "portal")
        self.assertIn("provision", order)
        self.assertLess(order.index("portal"), order.index("provision"))

    def test_pppoe_restore_clears_renew_before_provision(self):
        from datetime import timedelta

        from django.utils import timezone

        from core.mikrotik_connect import sync_customer_subscription_access

        self.pppoe.package_end = timezone.now() + timedelta(days=2)
        self.pppoe.save(update_fields=["package_end"])

        order = []

        def portal_side_effect(customer, *, enabled, portal_url="", timeout=8.0):
            order.append(("portal", enabled))
            return {"ok": True, "enabled": enabled}

        def provision_side_effect(customer, **kwargs):
            order.append(("provision",))
            return {"ok": True, "profile": "ispcentric"}

        with (
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
                side_effect=portal_side_effect,
            ),
            patch(
                "core.mikrotik_connect.provision_customer_pppoe",
                side_effect=provision_side_effect,
            ),
        ):
            result = sync_customer_subscription_access(self.pppoe, provision=True)

        self.assertTrue(result["allowed"])
        self.assertTrue(result["ok"])
        self.assertEqual(order[0], ("portal", False))
        self.assertEqual(order[1], ("provision",))

    def test_pppoe_restore_retries_cpe_clear_after_offline_skip(self):
        """Paid restore clears renew Hotspot on the post-provision attempt."""
        from datetime import timedelta

        from django.utils import timezone

        from core.mikrotik_connect import (
            cpe_renew_clear_is_pending,
            sync_customer_subscription_access,
        )

        self.pppoe.package_end = timezone.now() + timedelta(days=2)
        self.pppoe.save(update_fields=["package_end"])

        portal_calls = []

        def portal_side_effect(customer, *, enabled, portal_url="", timeout=8.0):
            portal_calls.append(enabled)
            # First attempt: CPE offline. Post-provision attempt: online.
            if len(portal_calls) < 2:
                return {
                    "ok": False,
                    "skipped": True,
                    "session_active": False,
                    "error": "Subscriber is not online on this router right now.",
                }
            return {"ok": True, "enabled": False, "notes": ["renew removed"]}

        with (
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
                side_effect=portal_side_effect,
            ),
            patch(
                "core.mikrotik_connect.provision_customer_pppoe",
                return_value={"ok": True, "profile": "ispcentric-pppoe-5u-10d"},
            ),
            patch("core.mikrotik_connect.time.sleep") as sleep_mock,
        ):
            result = sync_customer_subscription_access(self.pppoe, provision=True)

        self.assertTrue(result["allowed"])
        self.assertTrue(result["portal"]["ok"])
        self.assertTrue(result["ok"])
        self.assertFalse(result.get("cpe_renew_clear_pending"))
        self.assertFalse(cpe_renew_clear_is_pending(self.pppoe))
        self.assertEqual(len(portal_calls), 2)
        self.assertTrue(all(enabled is False for enabled in portal_calls))
        # Offline path must not burn settle sleeps before returning.
        sleep_mock.assert_not_called()

    def test_pppoe_restore_exits_fast_when_cpe_stays_offline(self):
        """Offline CPE must not delay NAS restore with settle loops."""
        from datetime import timedelta

        from django.utils import timezone

        from core.mikrotik_connect import (
            cpe_renew_clear_is_pending,
            sync_customer_subscription_access,
        )

        self.pppoe.package_end = timezone.now() + timedelta(days=2)
        self.pppoe.save(update_fields=["package_end"])

        with (
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
                return_value={
                    "ok": False,
                    "skipped": True,
                    "session_active": False,
                    "error": "CPE offline",
                },
            ) as portal_mock,
            patch(
                "core.mikrotik_connect.provision_customer_pppoe",
                return_value={"ok": True, "profile": "ispcentric"},
            ),
            patch("core.mikrotik_connect.time.sleep") as sleep_mock,
        ):
            result = sync_customer_subscription_access(self.pppoe, provision=True)

        self.assertTrue(result["allowed"])
        self.assertTrue(result.get("cpe_renew_clear_pending"))
        self.assertTrue(cpe_renew_clear_is_pending(self.pppoe))
        self.assertFalse(result["ok"])
        self.assertIn("pending clear", result["message"])
        # One pre-provision + one post-provision attempt only.
        self.assertEqual(portal_mock.call_count, 2)
        sleep_mock.assert_not_called()

    def test_cpe_renew_pool_ip_resolves_remembered_customer(self):
        from core.mikrotik_connect import (
            find_pppoe_customer_for_ip,
            remember_pppoe_customer_session_ip,
        )

        remember_pppoe_customer_session_ip(self.pppoe, "192.168.189.40")
        found = find_pppoe_customer_for_ip(self.org, "192.168.189.40")
        self.assertEqual(found.pk, self.pppoe.pk)

        # Unknown renew-pool IP must not guess via an org-wide marker
        # (that would conflict across customers).
        self.assertIsNone(find_pppoe_customer_for_ip(self.org, "192.168.189.55"))

    def test_sync_skips_cpe_retry_when_portal_was_offline(self):
        from io import StringIO

        from django.core.management import call_command

        with (
            patch(
                "billing.management.commands.sync_subscription_access.sync_customer_subscription_access",
                return_value={
                    "ok": True,
                    "allowed": False,
                    "portal": {"ok": False, "skipped": True, "error": "CPE offline"},
                    "provision": {"ok": True, "profile": "ispcentric-blocked"},
                },
            ),
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
            ) as cpe_retry,
            patch(
                "billing.management.commands.sync_subscription_access.repair_hotspot_captive_portal",
                return_value={"ok": True, "notes": []},
            ),
            patch(
                "billing.management.commands.sync_subscription_access.repair_router_expired_captive_redirect",
                return_value={"ok": True, "message": "ok"},
            ),
        ):
            call_command("sync_subscription_access", stdout=StringIO())

        cpe_retry.assert_not_called()

    def test_middleware_renew_pool_probe_includes_signed_token(self):
        from django.core.cache import cache
        from django.test import RequestFactory, override_settings

        from core.mikrotik_connect import remember_pppoe_customer_session_ip
        from ispcentric.middleware import HotspotCaptiveProbeMiddleware

        remember_pppoe_customer_session_ip(self.pppoe, "192.168.189.77")
        cache.delete("captive:redirect:v2:192.168.189.77:")

        factory = RequestFactory()
        request = factory.get(
            "/hotspot-detect.html",
            HTTP_HOST="captive.apple.com",
            REMOTE_ADDR="192.168.189.77",
        )

        def boom(req):
            self.fail("probe must redirect, not fall through")

        with (
            override_settings(PUBLIC_BASE_URL="http://billing.example"),
            patch(
                "core.mikrotik_connect.resolve_captive_organization",
                return_value=self.org,
            ),
            patch(
                "core.hotspot_portal.public_base_url",
                return_value="http://billing.example",
            ),
        ):
            response = HotspotCaptiveProbeMiddleware(boom)(request)

        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/pppoe/{self.org.join_code}/pay/", response.url)
        self.assertIn("t=", response.url)

    def test_nas_expired_access_repair_loop_adds_dns_and_redirect(self):
        from core.mikrotik_connect import (
            PPP_SECRET_TAG,
            PPPOE_BLOCKED_ADDRESS_LIST,
            _ensure_pppoe_expired_access,
        )

        nat_rows = []
        filter_rows = [
            {".id": "*drop", "chain": "forward", "action": "drop"},
            {".id": "*idrop", "chain": "input", "action": "drop"},
        ]
        adds = []
        attempt = {"n": 0}

        def fake_print(sock, path, **kwargs):
            if path == "/ip/firewall/nat":
                return list(nat_rows)
            if path == "/ip/firewall/filter":
                return list(filter_rows)
            return []

        def fake_add(sock, path, **props):
            adds.append((path, props))
            if path == "/ip/firewall/nat" and "expired redirect" in props.get(
                "comment", ""
            ):
                # Appear only after first failed check (simulate flaky write).
                attempt["n"] += 1
                if attempt["n"] >= 1:
                    nat_rows.append(
                        {
                            ".id": f"*r{attempt['n']}",
                            "chain": "dstnat",
                            "action": "dst-nat",
                            "to-addresses": "203.0.113.10",
                            "dst-port": "80",
                            "comment": f"{PPP_SECRET_TAG} expired redirect",
                        }
                    )
            if path == "/ip/firewall/filter":
                filter_rows.append({".id": f"*f{len(filter_rows)}", **props})
            return {"_reply": "!done", "ret": "*1"}

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch("core.mikrotik_connect._remove", return_value={"_reply": "!done"}),
            patch(
                "core.mikrotik_connect._add_filter_rule",
                side_effect=lambda sock, rule, place_before="": fake_add(
                    sock, "/ip/firewall/filter", **rule
                ),
            ),
            patch(
                "core.mikrotik_connect._billing_portal_base_url",
                return_value="http://billing.example:8000",
            ),
            patch(
                "core.mikrotik_connect._portal_target_ipv4",
                return_value="203.0.113.10",
            ),
            patch("core.mikrotik_connect._first_forward_drop_id", return_value="*drop"),
            patch(
                "core.mikrotik_connect._ensure_pppoe_fast_captive_reject",
                return_value=["reject https fast"],
            ),
        ):
            notes = _ensure_pppoe_expired_access(object())

        self.assertTrue(any("expired PPPoE HTTP" in n for n in notes))
        self.assertTrue(any("client DNS accept" in n for n in notes))
        self.assertTrue(
            any(
                path == "/ip/firewall/nat"
                and props.get("src-address-list") == PPPOE_BLOCKED_ADDRESS_LIST
                and props.get("dst-port") == "80"
                for path, props in adds
            )
        )

    def test_isp_hotspot_bounce_clears_cookies_keeps_authorized(self):
        from unittest.mock import MagicMock

        from core.mikrotik_connect import _bounce_isp_hotspot_clients

        removed = []

        def fake_print(sock, path, **kwargs):
            if path == "/ip/hotspot/cookie":
                return [{".id": "*c1"}]
            if path == "/ip/hotspot/active":
                return [
                    {".id": "*a1", "authorized": "true"},
                    {".id": "*a2", "authorized": "false"},
                ]
            if path == "/ip/hotspot/host":
                return [{".id": "*h1", "authorized": "no"}]
            return []

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch(
                "core.mikrotik_connect._remove",
                side_effect=lambda sock, path, item_id: (
                    removed.append((path, item_id)) or {"_reply": "!done"}
                ),
            ),
            patch(
                "core.mikrotik_connect._bounce_wifi_clients",
                return_value=["bounced 1"],
            ),
        ):
            notes = _bounce_isp_hotspot_clients(MagicMock())

        self.assertIn(("/ip/hotspot/cookie", "*c1"), removed)
        self.assertIn(("/ip/hotspot/active", "*a2"), removed)
        self.assertIn(("/ip/hotspot/host", "*h1"), removed)
        self.assertNotIn(("/ip/hotspot/active", "*a1"), removed)
        self.assertTrue(any("cookie" in n for n in notes))

    def test_repair_hotspot_captive_retries_until_ok(self):
        from core.mikrotik_connect import repair_hotspot_captive_portal

        calls = {"n": 0}

        def fake_apply(router, **kwargs):
            calls["n"] += 1
            if calls["n"] < 2:
                return {"ok": False, "error": "login.html missing"}
            return {"ok": True, "notes": ["installed hotspot/login.html"]}

        with patch(
            "core.mikrotik_connect.apply_hotspot_on_router",
            side_effect=fake_apply,
        ):
            result = repair_hotspot_captive_portal(self.router, attempts=3)

        self.assertTrue(result["ok"])
        self.assertEqual(calls["n"], 2)
        self.assertTrue(
            any("repaired on attempt" in n for n in (result.get("notes") or []))
        )

    def test_sync_command_repairs_hotspot_and_expired_redirect(self):
        from io import StringIO

        from django.core.management import call_command

        with (
            patch(
                "billing.management.commands.sync_subscription_access.sync_customer_subscription_access",
                return_value={
                    "ok": False,
                    "allowed": False,
                    "portal": {
                        "ok": False,
                        "skipped": False,
                        "error": "login.html missing",
                    },
                    "provision": {"ok": True, "profile": "ispcentric-blocked"},
                },
            ),
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
                return_value={"ok": True, "enabled": True},
            ),
            patch(
                "billing.management.commands.sync_subscription_access.repair_hotspot_captive_portal",
                return_value={
                    "ok": True,
                    "notes": ["Hotspot captive repaired on attempt 2"],
                },
            ) as hs_repair,
            patch(
                "billing.management.commands.sync_subscription_access.repair_router_expired_captive_redirect",
                return_value={"ok": True, "message": "expired captive redirect ok"},
            ) as nas_repair,
        ):
            out = StringIO()
            call_command("sync_subscription_access", stdout=out)
            text = out.getvalue()

        self.assertTrue(hs_repair.called)
        self.assertTrue(nas_repair.called)
        self.assertIn("captive repaired", text)
        self.assertIn("expired-redirect", text)

    def test_captive_html_invariants_for_both_pay_modes(self):
        from core.mikrotik_connect import _captive_pay_redirect_html

        for url in (
            "http://billing.example/pppoe/606061/pay/?t=tok",
            "http://billing.example/hotspot/606061/pay/",
        ):
            html = _captive_pay_redirect_html(url)
            self.assertIn("$(if http-status == 302)", html)
            self.assertIn("mac=$(mac)", html)
            self.assertIn("window.location.replace", html)
            # Absolute pay target present (trailing slash may be stripped before ?mac=).
            self.assertIn(url.rstrip("/").split("?")[0], html)

    @override_settings(PUBLIC_BASE_URL="http://127.0.0.1:8000", HOSTED=False)
    def test_local_and_hosted_pay_urls_stay_absolute_http(self):
        from core.mikrotik_connect import (
            _normalize_hotspot_portal_urls,
            _pppoe_pay_portal_url,
            _prefer_http_captive_url,
        )

        with patch(
            "core.mikrotik_connect._billing_portal_base_url",
            return_value="http://127.0.0.1:8000",
        ):
            local_pppoe = _pppoe_pay_portal_url(self.org, customer=self.pppoe)
            local_hs = _normalize_hotspot_portal_urls(
                pay_url=f"/hotspot/{self.org.join_code}/pay/"
            )

        self.assertTrue(local_pppoe.startswith("http://127.0.0.1:8000/pppoe/"))
        self.assertIn("t=", local_pppoe)
        self.assertEqual(
            local_hs["pay_url"],
            f"http://127.0.0.1:8000/hotspot/{self.org.join_code}/pay/",
        )

        hosted = _prefer_http_captive_url(
            f"https://isp.example.co.ke/pppoe/{self.org.join_code}/pay/"
        )
        self.assertEqual(
            hosted,
            f"http://isp.example.co.ke/pppoe/{self.org.join_code}/pay/",
        )

    def test_verify_command_loops_until_surfing_restored(self):
        from datetime import timedelta
        from io import StringIO

        from django.core.management import call_command
        from django.utils import timezone

        self.pppoe.package_end = timezone.now() + timedelta(days=1)
        self.pppoe.save(update_fields=["package_end"])

        calls = {"n": 0}

        def fake_sync(customer, **kwargs):
            calls["n"] += 1
            if calls["n"] < 2:
                return {
                    "ok": False,
                    "allowed": True,
                    "cpe_renew_clear_pending": True,
                    "message": "pending clear",
                    "portal": {"ok": False, "skipped": True, "error": "offline"},
                    "provision": {
                        "ok": True,
                        "profile": "ispcentric",
                        "disabled": False,
                        "kicked": 0,
                        "notes": [],
                    },
                }
            return {
                "ok": True,
                "allowed": True,
                "cpe_renew_clear_pending": False,
                "message": "Internet allowed for subscription period.",
                "portal": {"ok": True, "enabled": False},
                "provision": {
                    "ok": True,
                    "profile": "ispcentric",
                    "disabled": False,
                    "kicked": 0,
                    "notes": ["nudged"],
                },
            }

        out = StringIO()
        with (
            patch(
                "core.mikrotik_connect.sync_customer_subscription_access",
                side_effect=fake_sync,
            ),
            patch(
                "core.mikrotik_connect.cpe_renew_clear_is_pending",
                side_effect=lambda c: calls["n"] < 2,
            ),
            patch("billing.access_verification.time.sleep"),
        ):
            call_command(
                "verify_subscription_access",
                customer=self.pppoe.pk,
                loops=3,
                settle=0.1,
                stdout=out,
            )
        text = out.getvalue()
        self.assertIn("PASS", text)
        self.assertGreaterEqual(calls["n"], 2)

    def test_verify_command_fails_when_cpe_never_comes_online(self):
        from datetime import timedelta
        from io import StringIO

        from django.core.management import call_command
        from django.core.management.base import CommandError
        from django.utils import timezone

        self.pppoe.package_end = timezone.now() + timedelta(days=1)
        self.pppoe.save(update_fields=["package_end"])

        with (
            patch(
                "core.mikrotik_connect.sync_customer_subscription_access",
                return_value={
                    "ok": False,
                    "allowed": True,
                    "cpe_renew_clear_pending": True,
                    "message": "pending clear",
                    "portal": {"ok": False, "skipped": False, "error": "CPE API error"},
                    "provision": {
                        "ok": True,
                        "profile": "ispcentric",
                        "disabled": False,
                        "notes": [],
                    },
                },
            ),
            patch(
                "core.mikrotik_connect.cpe_renew_clear_is_pending",
                return_value=True,
            ),
            patch("billing.access_verification.time.sleep"),
        ):
            with self.assertRaises(CommandError) as ctx:
                call_command(
                    "verify_subscription_access",
                    customer=self.pppoe.pk,
                    loops=2,
                    settle=0.01,
                    stdout=StringIO(),
                    stderr=StringIO(),
                )
        self.assertIn("renew popup pending", str(ctx.exception))


class DynamicAccessEnforcementLoopTests(TestCase):
    """
    NAS enforcement loops for dynamic mode: Hotspot MAC disabled until paid;
    PPPoE blocked profile outside subscription; restore after payment.
    """

    def setUp(self):
        from datetime import timedelta

        from django.contrib.auth.models import User
        from django.core.cache import cache
        from django.utils import timezone

        from accounts.models import Organization
        from billing.models import BillingPlan, Customer

        cache.clear()
        self.owner = User.objects.create_user("dyn-loop-owner", password="x")
        self.org = Organization.objects.create(
            name="Dynamic Loop ISP",
            owner=self.owner,
            join_code="707070",
            hotspot_enabled=True,
            pppoe_compulsory=True,
        )
        self.plan = BillingPlan.objects.create(
            organization=self.org,
            name="Hourly",
            price="50.00",
            duration=BillingPlan.Duration.HOURLY,
            download_speed_mbps=5,
            upload_speed_mbps=2,
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Dynamic NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.0.0.2",
            username="admin",
            password="secret",
        )
        now = timezone.now()
        self.pppoe = Customer.objects.create(
            organization=self.org,
            full_name="Dyn PPPoE",
            phone="0711222333",
            account_number="DYN-LOOP-PPP",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="dyn1",
            pppoe_password="pass",
            status=Customer.Status.ACTIVE,
            router=self.router,
            package_start=now - timedelta(days=5),
            package_end=now - timedelta(days=1),
        )
        self.hotspot = Customer.objects.create(
            organization=self.org,
            full_name="Dyn Hotspot",
            phone="0722333444",
            account_number="DYN-LOOP-HS",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:99",
            status=Customer.Status.ACTIVE,
            router=self.router,
            plan=self.plan,
        )

    def test_unpaid_hotspot_mac_stays_disabled_on_nas(self):
        from core.mikrotik_connect import _hotspot_customer_access_fields

        mac, disabled, limit_uptime, _comment = _hotspot_customer_access_fields(
            self.hotspot
        )
        self.assertEqual(mac, "AA:BB:CC:DD:EE:99")
        self.assertTrue(disabled)
        self.assertEqual(limit_uptime, "")

    def test_hotspot_authorize_loop_after_package_applied(self):
        from datetime import timedelta

        from django.utils import timezone

        from billing.services import apply_subscription_renewal
        from core.mikrotik_connect import (
            _hotspot_customer_access_fields,
            _mark_hotspot_stack_ready,
            authorize_hotspot_customer,
        )

        apply_subscription_renewal(self.hotspot, plan=self.plan)
        self.hotspot.refresh_from_db()
        _mark_hotspot_stack_ready(self.router.pk)

        with (
            patch("core.mikrotik_connect.socket.create_connection"),
            patch("core.mikrotik_connect._api_session"),
            patch(
                "core.mikrotik_connect._apply_hotspot_customer_on_socket",
                return_value={
                    "ok": True,
                    "profile": "ispcentric-hs-5u-10d",
                    "rate_limit": "5M/10M",
                },
            ) as apply_one,
        ):
            result = authorize_hotspot_customer(
                self.hotspot, router=self.router, reauthenticate=True
            )

        self.assertTrue(result.get("ok"))
        apply_one.assert_called_once()
        _mac, disabled, limit_uptime, _ = _hotspot_customer_access_fields(self.hotspot)
        self.assertFalse(disabled)
        self.assertTrue(limit_uptime.endswith("s"))

    def test_pppoe_expired_then_paid_restore_loop(self):
        from datetime import timedelta

        from django.utils import timezone

        from core.mikrotik_connect import (
            PPPOE_BLOCKED_PROFILE_NAME,
            sync_customer_subscription_access,
        )

        order = []

        def portal_side_effect(customer, *, enabled, portal_url="", timeout=8.0):
            order.append(("portal", enabled))
            return {"ok": True, "enabled": enabled}

        def provision_side_effect(customer, **kwargs):
            order.append(("provision", kwargs.get("force_disabled", False)))
            profile = (
                PPPOE_BLOCKED_PROFILE_NAME
                if customer.package_end < timezone.now()
                else "ispcentric-5u-10d"
            )
            return {"ok": True, "profile": profile}

        with (
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
                side_effect=portal_side_effect,
            ),
            patch(
                "core.mikrotik_connect.provision_customer_pppoe",
                side_effect=provision_side_effect,
            ),
            patch(
                "core.mikrotik_connect._pppoe_pay_portal_url",
                return_value="http://billing.example/pppoe/707070/pay/?t=x",
            ),
        ):
            blocked = sync_customer_subscription_access(self.pppoe, provision=True)
            self.pppoe.package_end = timezone.now() + timedelta(days=2)
            self.pppoe.save(update_fields=["package_end"])
            restored = sync_customer_subscription_access(self.pppoe, provision=True)

        self.assertFalse(blocked["allowed"])
        self.assertEqual(order[0], ("portal", True))
        self.assertTrue(restored["allowed"])
        self.assertEqual(order[2], ("portal", False))

    def test_quick_paid_restore_skips_post_kick_cpe_retries(self):
        from datetime import timedelta

        from django.utils import timezone

        from core.mikrotik_connect import sync_customer_subscription_access

        order = []

        def portal_side_effect(customer, *, enabled, portal_url="", timeout=8.0):
            order.append(("portal", enabled))
            return {"ok": False, "skipped": True}

        def provision_side_effect(customer, **kwargs):
            order.append(("provision", kwargs.get("force_disabled", False)))
            return {"ok": True, "profile": "ispcentric-5u-10d"}

        self.pppoe.package_end = timezone.now() + timedelta(days=2)
        self.pppoe.save(update_fields=["package_end"])

        with (
            patch(
                "core.mikrotik_connect.apply_cpe_renew_portal",
                side_effect=portal_side_effect,
            ),
            patch(
                "core.mikrotik_connect.provision_customer_pppoe",
                side_effect=provision_side_effect,
            ),
            patch(
                "core.mikrotik_connect._pppoe_pay_portal_url",
                return_value="http://billing.example/pppoe/707070/pay/?t=x",
            ),
            patch(
                "core.mikrotik_connect._clear_cpe_renew_with_retries"
            ) as post_kick,
        ):
            result = sync_customer_subscription_access(
                self.pppoe, provision=True, quick=True
            )

        self.assertTrue(result["allowed"])
        self.assertTrue(result["ok"])
        self.assertEqual(order, [("provision", False)])
        post_kick.assert_not_called()

    def test_verify_dynamic_access_command_passes_dry_run(self):
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command(
            "verify_dynamic_access",
            customer=self.hotspot.pk,
            loops=2,
            dry_run=True,
            stdout=out,
        )
        text = out.getvalue()
        self.assertIn("PASS", text)
        self.assertIn("billing_allows=False", text)

    def test_verify_dynamic_access_command_loops_until_nas_matches(self):
        from datetime import timedelta
        from io import StringIO

        from django.core.management import call_command
        from django.utils import timezone

        from billing.services import apply_subscription_renewal

        apply_subscription_renewal(self.hotspot, plan=self.plan)
        self.hotspot.refresh_from_db()

        calls = {"n": 0}

        def fake_sync(customer, **kwargs):
            calls["n"] += 1
            if calls["n"] < 2:
                return {
                    "ok": False,
                    "allowed": True,
                    "provision": {"ok": False},
                    "message": "retry",
                }
            return {
                "ok": True,
                "allowed": True,
                "provision": {"ok": True},
                "message": "authorized",
            }

        out = StringIO()
        with (
            patch(
                "core.mikrotik_connect.sync_customer_subscription_access",
                side_effect=fake_sync,
            ),
            patch("billing.access_verification.time.sleep"),
        ):
            call_command(
                "verify_dynamic_access",
                customer=self.hotspot.pk,
                loops=3,
                settle=0.01,
                stdout=out,
            )
        self.assertIn("PASS", out.getvalue())
        self.assertGreaterEqual(calls["n"], 2)


class PppoeHotspotAccountLoopCommandTests(TestCase):
    """Integration tests for verify_access_accounts on both service types."""

    def setUp(self):
        from datetime import timedelta

        from django.contrib.auth.models import User
        from django.utils import timezone

        from accounts.models import Organization
        from billing.models import BillingPlan, Customer
        from core.models import MikroTikRouter

        self.owner = User.objects.create_user("cmd-loop-owner", password="x")
        self.org = Organization.objects.create(
            name="Cmd Loop ISP",
            owner=self.owner,
            join_code="808080",
            pppoe_compulsory=True,
            hotspot_enabled=True,
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Cmd NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.0.0.3",
            username="admin",
            password="secret",
        )
        now = timezone.now()
        self.pppoe = Customer.objects.create(
            organization=self.org,
            full_name="Cmd PPPoE",
            phone="0711000000",
            account_number="CMD-PPP",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="cmdppp",
            pppoe_password="pass",
            status=Customer.Status.ACTIVE,
            router=self.router,
            package_start=now - timedelta(days=5),
            package_end=now - timedelta(days=1),
        )
        self.hotspot = Customer.objects.create(
            organization=self.org,
            full_name="Cmd Hotspot",
            phone="0722000000",
            account_number="CMD-HS",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:CC",
            status=Customer.Status.ACTIVE,
            router=self.router,
        )

    def test_verify_access_accounts_pppoe_service_only(self):
        from io import StringIO

        from django.core.management import call_command

        with patch(
            "core.mikrotik_connect.sync_customer_subscription_access",
            return_value={
                "ok": True,
                "allowed": False,
                "provision": {"ok": True, "profile": "ispcentric-blocked"},
                "portal": {"ok": True},
            },
        ):
            out = StringIO()
            call_command(
                "verify_access_accounts",
                organization=self.org.pk,
                service="pppoe",
                loops=1,
                stdout=out,
            )
        self.assertIn("PASS", out.getvalue())
        self.assertIn("CMD-PPP", out.getvalue())

    def test_verify_access_accounts_hotspot_service_only(self):
        from io import StringIO

        from django.core.management import call_command

        with patch(
            "core.mikrotik_connect.sync_customer_subscription_access",
            return_value={
                "ok": True,
                "allowed": False,
                "provision": {"ok": True},
            },
        ):
            out = StringIO()
            call_command(
                "verify_access_accounts",
                organization=self.org.pk,
                service="hotspot",
                loops=1,
                stdout=out,
            )
        self.assertIn("PASS", out.getvalue())
        self.assertIn("CMD-HS", out.getvalue())


class RouterConnectivityLoopTests(TestCase):
    """Unit tests for NAS/CPE connectivity correction loops."""

    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization
        from billing.models import Customer
        from core.models import MikroTikRouter

        self.owner = User.objects.create_user("conn-loop-owner", password="x")
        self.org = Organization.objects.create(
            name="Conn Loop ISP",
            owner=self.owner,
            join_code="606060",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Conn NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="192.168.88.1",
            username="admin",
            password="secret",
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="Conn PPPoE",
            phone="254700000099",
            account_number="CONN-PPP",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="connuser",
            pppoe_password="pass",
            status=Customer.Status.ACTIVE,
            router=self.router,
        )

    def test_evaluate_nas_connectivity_success(self):
        from core.connectivity_verification import evaluate_nas_connectivity

        with (
            patch(
                "core.mikrotik_connect.check_mikrotik_reachable",
                return_value={"online": True, "via": "api"},
            ),
            patch(
                "core.mikrotik_connect.test_mikrotik_api_login",
                return_value={"ok": True, "identity": "MikroTik"},
            ),
        ):
            result = evaluate_nas_connectivity(self.router)
        self.assertTrue(result["ok"])
        self.assertTrue(result["api_ok"])

    def test_evaluate_nas_tunnel_hint_when_unreachable(self):
        from core.connectivity_verification import evaluate_nas_connectivity

        self.router.host = "10.9.0.12"
        self.router.vpn_address = "10.9.0.12"
        with patch(
            "core.mikrotik_connect.check_mikrotik_reachable",
            return_value={"online": False, "error": "timed out"},
        ):
            result = evaluate_nas_connectivity(self.router)
        self.assertFalse(result["ok"])
        self.assertIn("WireGuard", result["hint"])

    def test_run_nas_loop_retries_until_api_ok(self):
        from core.connectivity_verification import run_nas_connectivity_loop

        calls = {"n": 0}

        def fake_eval(router, **kwargs):
            calls["n"] += 1
            if calls["n"] < 2:
                return {
                    "ok": False,
                    "reachable": True,
                    "api_ok": False,
                    "error": "auth failed",
                    "details": {"host": router.host},
                }
            return {
                "ok": True,
                "reachable": True,
                "api_ok": True,
                "details": {"host": router.host},
            }

        with (
            patch(
                "core.connectivity_verification.evaluate_nas_connectivity",
                side_effect=fake_eval,
            ),
            patch("core.connectivity_verification.time.sleep"),
        ):
            outcome = run_nas_connectivity_loop(self.router, loops=3, settle=0)
        self.assertTrue(outcome.passed)
        self.assertEqual(len(outcome.attempts), 2)

    def test_evaluate_cpe_offline_is_skipped_not_failed(self):
        from core.connectivity_verification import evaluate_cpe_connectivity

        with (
            patch(
                "core.connectivity_verification.evaluate_nas_connectivity",
                return_value={"ok": True, "api_ok": True, "details": {}},
            ),
            patch(
                "core.mikrotik_connect.resolve_customer_cpe_session",
                return_value={
                    "ok": True,
                    "session_active": False,
                    "address": "",
                    "hint": "CPE offline",
                },
            ),
        ):
            result = evaluate_cpe_connectivity(self.customer)
        self.assertTrue(result["ok"])
        self.assertTrue(result["skipped"])
        self.assertFalse(result["session_active"])

    def test_evaluate_cpe_shallow_session_is_not_management_ok(self):
        from core.connectivity_verification import evaluate_cpe_connectivity

        with (
            patch(
                "core.connectivity_verification.evaluate_nas_connectivity",
                return_value={"ok": True, "api_ok": True, "details": {}},
            ),
            patch(
                "core.mikrotik_connect.resolve_customer_cpe_session",
                return_value={
                    "ok": True,
                    "session_active": True,
                    "address": "10.20.0.50",
                    "caller_id": "AA:BB",
                },
            ),
        ):
            result = evaluate_cpe_connectivity(self.customer, deep=False)
        self.assertTrue(result["ok"])
        self.assertTrue(result["session_active"])
        self.assertTrue(result["session_only"])
        self.assertFalse(result["cpe_ok"])
        self.assertFalse(result["management_ok"])

    def test_layered_cpe_classifies_wan_mgmt_blocked(self):
        from core.connectivity_verification import evaluate_layered_cpe_access

        with (
            patch(
                "core.connectivity_verification.evaluate_nas_connectivity",
                return_value={"ok": True, "api_ok": True, "details": {}},
            ),
            patch(
                "core.mikrotik_connect.probe_customer_cpe_web",
                return_value={
                    "ok": False,
                    "session_active": True,
                    "cpe_host": "10.20.0.50",
                    "port": None,
                    "ping_ok": True,
                    "error": "ports closed",
                    "hint": "",
                    "steps": ["found client IP 10.20.0.50", "ping ok"],
                },
            ),
        ):
            result = evaluate_layered_cpe_access(self.customer, try_api=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["failure_class"], "wan_mgmt_blocked")
        self.assertTrue(result["details"]["layers"]["ping_ok"])
        self.assertFalse(result["details"]["layers"]["web_ok"])

    def test_layered_cpe_loop_passes_when_web_ok(self):
        from core.connectivity_verification import run_layered_cpe_access_loop

        with (
            patch(
                "core.connectivity_verification.evaluate_layered_cpe_access",
                return_value={
                    "ok": True,
                    "skipped": False,
                    "failure_class": "ok",
                    "failing_layer": "",
                    "error": "",
                    "hint": "",
                    "details": {
                        "cpe_host": "10.20.0.50",
                        "web_port": 80,
                        "layers": {
                            "nas_ok": True,
                            "session_active": True,
                            "ping_ok": True,
                            "web_ok": True,
                            "api_ok": True,
                        },
                    },
                },
            ),
            patch("core.connectivity_verification.time.sleep"),
        ):
            outcome = run_layered_cpe_access_loop(self.customer, loops=2, settle=0)
        self.assertTrue(outcome.passed)
        self.assertEqual(outcome.layer_pass_rates.get("web_ok"), 100.0)

    def test_verify_router_connectivity_command_dry_run(self):
        from io import StringIO

        from django.core.management import call_command

        with (
            patch(
                "core.mikrotik_connect.check_mikrotik_reachable",
                return_value={"online": True, "via": "api"},
            ),
            patch(
                "core.mikrotik_connect.test_mikrotik_api_login",
                return_value={"ok": True, "identity": "MikroTik"},
            ),
        ):
            out = StringIO()
            call_command(
                "verify_router_connectivity",
                router=self.router.pk,
                dry_run=True,
                stdout=out,
            )
        self.assertIn("PASS", out.getvalue())
        self.assertIn("Conn NAS", out.getvalue())


class LayeredRouterHealthLoopTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization

        self.owner = User.objects.create_user("layer-owner", password="x")
        self.org = Organization.objects.create(
            name="Layer ISP",
            owner=self.owner,
            join_code="112233",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="MIK TEST",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.9.0.50",
            vpn_address="10.9.0.50",
            username="admin",
            password="secret",
        )

    def test_layered_maps_ping_only_to_limited(self):
        from core.connectivity_verification import evaluate_layered_health

        with (
            patch("core.mikrotik_connect._icmp_ping", return_value=True),
            patch(
                "core.connectivity_verification._tcp_open",
                return_value=(False, "8728: timed out"),
            ),
        ):
            result = evaluate_layered_health(self.router, timeout=0.5)
        self.assertEqual(result["status"], "limited")
        self.assertEqual(result["score"], 55)
        self.assertEqual(result["failing_layer"], "tcp_8728")
        self.assertTrue(result["details"]["layers"]["ping"])
        self.assertFalse(result["details"]["layers"]["tcp_8728"])

    def test_layered_maps_api_open_bad_login_to_auth_failed(self):
        from core.connectivity_verification import evaluate_layered_health

        def fake_tcp(host, port, timeout):
            return (port == 8728, "" if port == 8728 else f"{port}: closed")

        with (
            patch("core.mikrotik_connect._icmp_ping", return_value=True),
            patch(
                "core.connectivity_verification._tcp_open",
                side_effect=fake_tcp,
            ),
            patch(
                "core.mikrotik_connect.test_mikrotik_api_login",
                return_value={"ok": False, "error": "invalid user name or password"},
            ),
        ):
            result = evaluate_layered_health(self.router, timeout=0.5)
        self.assertEqual(result["status"], "auth_failed")
        self.assertEqual(result["score"], 25)
        self.assertEqual(result["failing_layer"], "api_auth")
        self.assertTrue(result["details"]["layers"]["tcp_8728"])
        self.assertFalse(result["details"]["layers"]["api_auth"])

    def test_layered_maps_api_timeout_to_reachable_not_auth_failed(self):
        """Port 8728 open then login timeout must not say wrong password."""
        from core.connectivity_verification import evaluate_layered_health

        def fake_tcp(host, port, timeout):
            return (port == 8728, "" if port == 8728 else f"{port}: closed")

        with (
            patch("core.mikrotik_connect._icmp_ping", return_value=True),
            patch(
                "core.connectivity_verification._tcp_open",
                side_effect=fake_tcp,
            ),
            patch(
                "core.mikrotik_connect.test_mikrotik_api_login",
                return_value={
                    "ok": False,
                    "error": "Connection timed out. Is the router reachable on API port 8728?",
                },
            ),
        ):
            result = evaluate_layered_health(self.router, timeout=0.5)
        self.assertEqual(result["status"], "reachable")
        self.assertEqual(result["score"], 70)
        self.assertEqual(result["failing_layer"], "api_auth")
        self.assertNotIn("password", (result.get("reason") or "").lower())
        self.assertIn("timed out", (result.get("error") or "").lower())

    def test_status_after_api_probe_classifies_timeouts(self):
        from core.mikrotik_status_samples import (
            is_credential_login_failure,
            status_after_api_probe,
            status_reason,
        )

        self.assertTrue(is_credential_login_failure("invalid user name or password"))
        self.assertFalse(
            is_credential_login_failure(
                "Connection timed out. Is the router reachable on API port 8728?"
            )
        )
        self.assertFalse(is_credential_login_failure(""))
        status, auth_ok, error = status_after_api_probe(
            {"ok": False, "error": "Could not reach 10.9.0.50:8728."},
            via="api",
        )
        self.assertEqual(status, "reachable")
        self.assertFalse(auth_ok)
        self.assertIn("8728", error)
        empty_status, _, _ = status_after_api_probe({"ok": False, "error": ""}, via="api")
        self.assertEqual(empty_status, "reachable")
        reason = status_reason("auth_failed")
        self.assertIn("username/password", reason.lower())
        limited = status_reason("limited")
        self.assertIn("8728", limited)
        self.assertIn("api", limited.lower())

    def test_outage_sample_requires_two_consecutive_failures(self):
        from django.core.cache import cache

        from core.mikrotik_status_samples import (
            _last_status_cache_key,
            record_mikrotik_status_samples,
        )
        from core.models import MikroTikStatusSample

        cache.clear()
        org_id = self.org.pk
        rid = self.router.pk
        cache.set(_last_status_cache_key(org_id, rid), "connected", 3600)
        row = {
            "id": rid,
            "status": "limited",
            "online": False,
            "error": "API :8728 closed",
        }
        first = record_mikrotik_status_samples(self.org, [row])
        self.assertEqual(first, 0)
        self.assertEqual(MikroTikStatusSample.objects.filter(router=self.router).count(), 0)
        second = record_mikrotik_status_samples(self.org, [row])
        self.assertEqual(second, 1)
        sample = MikroTikStatusSample.objects.get(router=self.router)
        self.assertEqual(sample.status, "limited")
        self.assertEqual(sample.score, 55)
        self.assertIn("8728", sample.error)

    def test_ping_probe_confirms_api_before_limited(self):
        from core.mikrotik_connect import check_mikrotik_reachable

        def fake_connection(addr, timeout=None):
            # Parallel probes use the short timeout; confirm uses a longer one.
            if timeout is not None and float(timeout) > 0.5:
                return __import__("socket").socket()
            raise TimeoutError("timed out")

        with (
            patch("core.mikrotik_connect.socket.create_connection", side_effect=fake_connection),
            patch("core.mikrotik_connect._icmp_ping", return_value=True),
        ):
            result = check_mikrotik_reachable("10.9.0.50", timeout=0.1)
        self.assertTrue(result.get("online"))
        self.assertEqual(result.get("via"), "api")
        self.assertTrue(result.get("confirmed"))

    def test_layered_loop_detects_flaky_status(self):
        from core.connectivity_verification import run_layered_health_loop

        calls = {"n": 0}

        def fake_eval(router, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return {
                    "ok": False,
                    "status": "disconnected",
                    "score": 0,
                    "failing_layer": "ping",
                    "error": "unreachable",
                    "hint": "",
                    "reason": "offline",
                    "details": {
                        "layers": {
                            "ping": False,
                            "tcp_8728": False,
                            "tcp_8291": False,
                            "tcp_80": False,
                            "tcp_8080": False,
                            "api_auth": None,
                        }
                    },
                }
            return {
                "ok": True,
                "status": "connected",
                "score": 100,
                "failing_layer": "",
                "error": "",
                "hint": "",
                "reason": "ok",
                "details": {
                    "layers": {
                        "ping": True,
                        "tcp_8728": True,
                        "tcp_8291": True,
                        "tcp_80": True,
                        "tcp_8080": False,
                        "api_auth": True,
                    }
                },
            }

        with (
            patch(
                "core.connectivity_verification.evaluate_layered_health",
                side_effect=fake_eval,
            ),
            patch("core.connectivity_verification.time.sleep"),
        ):
            outcome = run_layered_health_loop(self.router, loops=3, settle=0)
        self.assertTrue(outcome.passed)
        self.assertTrue(outcome.flaky)
        self.assertEqual(outcome.dominant_failure, "disconnected")
        self.assertEqual(outcome.status_counts.get("connected"), 2)
        self.assertEqual(outcome.layer_pass_rates.get("tcp_8728"), round(2 / 3 * 100, 1))

    def test_diagnose_router_health_command_dry_run(self):
        from io import StringIO

        from django.core.management import call_command

        with (
            patch("core.mikrotik_connect._icmp_ping", return_value=True),
            patch(
                "core.connectivity_verification._tcp_open",
                side_effect=lambda host, port, timeout: (port == 8728, ""),
            ),
            patch(
                "core.mikrotik_connect.test_mikrotik_api_login",
                return_value={"ok": True, "identity": "MIK TEST"},
            ),
        ):
            out = StringIO()
            call_command(
                "diagnose_router_health",
                router=self.router.pk,
                dry_run=True,
                stdout=out,
            )
        self.assertIn("PASS", out.getvalue())
        self.assertIn("MIK TEST", out.getvalue())


class MikroTikStatusOfflineTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        from django.core.cache import cache

        from accounts.models import Organization

        self.owner = User.objects.create_user("status-owner", password="x")
        self.org = Organization.objects.create(
            name="Status ISP",
            owner=self.owner,
            join_code="778899",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Edge",
            model=MikroTikRouter.ModelChoice.HEX,
            host="192.168.88.1",
            username="admin",
            password="secret",
        )
        cache.clear()
        self.client.force_login(self.owner)

    def test_cached_status_is_not_written_as_health_samples(self):
        from django.core.cache import cache

        from core.models import MikroTikStatusSample

        cache.set(
            f"mikrotik_status:{self.org.pk}",
            [
                {
                    "id": self.router.pk,
                    "host": self.router.host,
                    "name": self.router.name,
                    "online": True,
                    "status": "connected",
                    "error": "",
                }
            ],
            60,
        )
        with patch("core.views.check_mikrotik_reachable") as probe:
            response = self.client.get("/app/mikrotik/status/")
        probe.assert_not_called()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["routers"][0]["status"], "connected")
        self.assertEqual(MikroTikStatusSample.objects.count(), 0)

    def test_offline_probe_records_sample_and_clears_live_cache(self):
        from django.core.cache import cache

        from core.models import MikroTikStatusSample

        live_key = f"mikrotik_live:{self.org.pk}:{self.router.pk}"
        cache.set(
            live_key,
            {"ok": True, "online": True, "identity": "stale"},
            60,
        )
        with (
            patch(
                "core.views.check_mikrotik_reachable",
                return_value={"online": False, "via": "", "error": "timed out"},
            ),
            patch("core.views.test_mikrotik_api_login") as login,
        ):
            response = self.client.get("/app/mikrotik/status/?refresh=1")
        login.assert_not_called()
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["routers"][0]["status"], "disconnected")
        self.assertFalse(data["routers"][0]["online"])
        self.assertIsNone(cache.get(live_key))
        sample = MikroTikStatusSample.objects.get(router=self.router)
        self.assertEqual(sample.status, "disconnected")
        self.assertEqual(sample.score, 0)

    def test_live_endpoint_dials_api_host_not_lan_only(self):
        self.router.vpn_address = "10.9.0.12"
        self.router.save(update_fields=["vpn_address", "updated_at"])
        with patch(
            "core.views.fetch_mikrotik_live_snapshot",
            return_value={"ok": False, "online": False, "error": "down"},
        ) as snap:
            response = self.client.get(
                f"/app/mikrotik/{self.router.pk}/live/?refresh=1"
            )
        snap.assert_called_once()
        self.assertEqual(snap.call_args.args[0], "10.9.0.12")
        body = response.json()
        self.assertEqual(body["api_host"], "10.9.0.12")
        self.assertEqual(body["host"], "192.168.88.1")
        self.assertFalse(body["online"])

    def test_outage_sample_bypasses_healthy_gate(self):
        from django.core.cache import cache

        from core.mikrotik_status_samples import record_mikrotik_status_samples
        from core.models import MikroTikStatusSample

        cache.set(f"mikrotik_status_sample_gate:{self.org.pk}", 1, 55)
        written = record_mikrotik_status_samples(
            self.org,
            [
                {
                    "id": self.router.pk,
                    "status": "disconnected",
                    "online": False,
                }
            ],
        )
        self.assertEqual(written, 1)
        self.assertEqual(MikroTikStatusSample.objects.count(), 1)

    def test_status_transition_bypasses_healthy_gate(self):
        from django.core.cache import cache

        from core.mikrotik_status_samples import (
            _last_status_cache_key,
            record_mikrotik_status_samples,
        )
        from core.models import MikroTikStatusSample

        cache.clear()
        cache.set(_last_status_cache_key(self.org.pk, self.router.pk), "disconnected", 60)
        cache.set(f"mikrotik_status_sample_gate:{self.org.pk}", 1, 55)
        written = record_mikrotik_status_samples(
            self.org,
            [
                {
                    "id": self.router.pk,
                    "status": "connected",
                    "online": True,
                }
            ],
        )
        self.assertEqual(written, 1)
        sample = MikroTikStatusSample.objects.get(router=self.router)
        self.assertEqual(sample.status, "connected")
        self.assertEqual(sample.score, 100)

    def test_trend_does_not_forward_fill_long_silent_gaps(self):
        from datetime import timedelta

        from django.utils import timezone

        from core.mikrotik_status_samples import mikrotik_performance_trend
        from core.models import MikroTikStatusSample

        now = timezone.now()
        MikroTikStatusSample.objects.create(
            organization=self.org,
            router=self.router,
            sampled_at=now - timedelta(hours=20),
            status="connected",
            score=100,
            online=True,
        )
        trend = mikrotik_performance_trend(self.org, hours=24)
        kari = next(
            ds for ds in trend["datasets"] if ds.get("router_id") == self.router.pk
        )
        filled = [v for v in kari["data"] if v is not None]
        # One old sample must not paint the entire 24h window as Connected.
        self.assertLess(len(filled), len(kari["data"]) // 2)
        self.assertTrue(any(v is None for v in kari["data"]))

    def test_performance_drops_explain_status_change(self):
        from datetime import timedelta

        from django.utils import timezone

        from core.mikrotik_status_samples import mikrotik_performance_drops
        from core.models import MikroTikStatusSample

        now = timezone.now()
        MikroTikStatusSample.objects.create(
            organization=self.org,
            router=self.router,
            sampled_at=now - timedelta(hours=2),
            status="connected",
            score=100,
            online=True,
        )
        MikroTikStatusSample.objects.create(
            organization=self.org,
            router=self.router,
            sampled_at=now - timedelta(hours=1),
            status="disconnected",
            score=0,
            online=False,
        )
        payload = mikrotik_performance_drops(
            self.org,
            hours=24,
            live_routers=[
                {
                    "id": self.router.pk,
                    "status": "auth_failed",
                    "error": "Login failed",
                }
            ],
        )
        self.assertTrue(payload["ok"])
        self.assertGreaterEqual(payload["current_count"], 1)
        current = payload["events"][0]
        self.assertTrue(current["current"])
        self.assertEqual(current["status"], "auth_failed")
        self.assertIn("login failed", current["reason"].lower())

    def test_performance_drops_include_historical_reason(self):
        from datetime import timedelta

        from django.utils import timezone

        from core.mikrotik_status_samples import mikrotik_performance_drops
        from core.models import MikroTikStatusSample

        now = timezone.now()
        MikroTikStatusSample.objects.create(
            organization=self.org,
            router=self.router,
            sampled_at=now - timedelta(hours=3),
            status="connected",
            score=100,
            online=True,
        )
        MikroTikStatusSample.objects.create(
            organization=self.org,
            router=self.router,
            sampled_at=now - timedelta(hours=2),
            status="limited",
            score=55,
            online=False,
        )
        payload = mikrotik_performance_drops(self.org, hours=24, live_routers=[])
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["current_count"], 0)
        self.assertTrue(payload["events"])
        event = payload["events"][0]
        self.assertEqual(event["status"], "limited")
        self.assertIn("ping", event["reason"].lower())

