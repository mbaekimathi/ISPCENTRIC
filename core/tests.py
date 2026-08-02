from io import StringIO
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
        self.assertIn("ispcentric API: enabled and listening on port 8728", script)
        self.assertIn("name=api and disabled=no and port=8728", script)
        # Hotspot otherwise refuses 8728 for unpaid LAN clients.
        self.assertIn('comment="ispcentric-hotspot-bypass-192"', script)
        self.assertIn("type=bypassed address=192.168.0.0/16", script)
        self.assertIn(
            ':do { /ip hotspot ip-binding remove [find where comment~"ispcentric-"] } '
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
            'src-address=192.168.0.0/16 place-before=0 '
            'comment="ispcentric-vpn-api-lan-192"',
            script,
        )
        # Masquerade must not rewrite sources talking to the billing tunnel.
        self.assertIn('comment="ispcentric-vpn-no-nat"', script)
        self.assertIn("action=accept", script)
        self.assertIn("dst-address=10.9.0.0/24", script)
        # Prove reachability to the VPS tunnel address.
        self.assertIn("/ping 10.9.0.1 count=4", script)
        self.assertIn("ispcentric OK", script)
        self.assertIn("save name=ispcentric-tunnel", script)
        # Idempotent cleanup for re-runs.
        self.assertIn(
            '/ip firewall filter remove [find where comment~"ispcentric-vpn-"]',
            script,
        )
        # Avoid :local so paste works cleanly in New Terminal.
        self.assertNotIn(":local ", script)
        if_line = next(
            line
            for line in script.splitlines()
            if line.startswith(":if") and "ping" in line
        )
        self.assertIn(
            'do={:put "ispcentric OK: tunnel 10.9.0.3 reaches 10.9.0.1 - Connect in ISPCENTRIC '
            '(API 8728 must show enabled above)"} else={:put',
            if_line,
        )
        self.assertTrue(if_line.endswith('"}'))
        self.assertEqual(if_line.count("{"), if_line.count("}"))

    @override_settings(
        WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
        WIREGUARD_SUBNET="10.9.0.0/24",
    )
    def test_new_script_removes_every_old_tunnel_component_before_replacing_it(self):
        old_private_key, _ = wireguard.generate_keypair()
        latest_private_key, _ = wireguard.generate_keypair()

        old_script = wireguard.routeros_script("10.9.0.3", old_private_key)
        latest_script = wireguard.routeros_script("10.9.0.4", latest_private_key)

        self.assertIn(f'private-key="{old_private_key}"', old_script)
        self.assertNotIn(old_private_key, latest_script)
        self.assertIn(f'private-key="{latest_private_key}"', latest_script)
        self.assertIn("address=10.9.0.4/24", latest_script)

        lines = latest_script.splitlines()
        cleanup_lines = [
            '/ip firewall filter remove [find where comment~"ispcentric-vpn-"]',
            '/ip firewall nat remove [find where comment="ispcentric-vpn-no-nat"]',
            ':do { /ip hotspot ip-binding remove [find where comment~"ispcentric-"] } '
            "on-error={}",
            "/interface wireguard peers remove [find where interface=ispcentric-vpn]",
            "/ip address remove [find where interface=ispcentric-vpn]",
            "/interface wireguard remove [find where name=ispcentric-vpn]",
        ]
        add_interface = next(
            index
            for index, line in enumerate(lines)
            if line.startswith("/interface wireguard add ")
        )
        for cleanup in cleanup_lines:
            self.assertIn(cleanup, lines)
            self.assertLess(lines.index(cleanup), add_interface)

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
            patch(
                "core.mikrotik_connect.check_mikrotik_reachable",
                return_value={"online": True, "via": "api"},
            ),
            patch("core.mikrotik_connect._api_session"),
            patch(
                "core.mikrotik_connect._apply_hotspot_customer_on_socket",
                return_value=True,
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

    def test_warm_authorize_probes_reachability_once(self):
        from unittest.mock import patch

        from core.mikrotik_connect import (
            _mark_hotspot_stack_ready,
            authorize_hotspot_customer,
        )

        _mark_hotspot_stack_ready(self.router.pk)
        with (
            patch(
                "core.mikrotik_connect.check_mikrotik_reachable",
                return_value={"online": True, "via": "api"},
            ) as reachable,
            patch("core.mikrotik_connect._api_session"),
            patch(
                "core.mikrotik_connect._apply_hotspot_customer_on_socket",
                return_value=True,
            ),
        ):
            authorize_hotspot_customer(
                self.customer, router=self.router, reauthenticate=False
            )
        # Single saved host → exactly one reachability probe (no pre-scan).
        self.assertEqual(reachable.call_count, 1)

    def test_offline_router_authorize_is_skipped_not_failed(self):
        from unittest.mock import patch

        from core.mikrotik_connect import (
            _mark_hotspot_stack_ready,
            authorize_hotspot_customer,
        )

        _mark_hotspot_stack_ready(self.router.pk)
        with (
            patch(
                "core.mikrotik_connect.check_mikrotik_reachable",
                return_value={"online": False, "via": ""},
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
    )
    def test_gateway_ip_host_is_rewritten_and_redirected(self):
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
                "effective_daraja_credentials": lambda self: {"ready": True},
                "pk": 1,
            },
        )()
        request = RequestFactory().get("/hotspot/404040/pay/", {"mac": "AABBCCDDEEFF"})
        with patch(
            "billing.models.BillingPlan.objects.filter"
        ) as plans_filter:
            plans_filter.return_value.order_by.return_value.__getitem__.return_value = []
            ctx = _hotspot_portal_context(org, mikrotik_login=False, request=request)
        self.assertTrue(ctx["show_payment_form"])
        self.assertEqual(ctx["hotspot_mac"], "AA:BB:CC:DD:EE:FF")


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

    @override_settings(PUBLIC_BASE_URL="http://192.168.88.254:8000")
    def test_sweep_style_push_still_sends_portal_urls(self):
        from core.mikrotik_connect import apply_hotspot_on_router

        with (
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

    def _build_rules(self):
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
                object(), lan_interface="bridge", wan_interface="ether1"
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

    @override_settings(PUBLIC_BASE_URL="http://10.10.0.168:8000")
    def test_portal_urls_carry_the_reason_for_the_settings_page(self):
        from core.hotspot_portal import hotspot_portal_urls

        with patch(
            "core.hotspot_portal.local_ipv4_addresses",
            return_value={"192.168.88.254"},
        ):
            urls = hotspot_portal_urls("606060")
        self.assertFalse(urls["base_is_loopback"])
        self.assertIn("10.10.0.168", urls["base_unreachable_reason"])


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

    def test_tunnel_server_address_is_not_bindable_on_a_plain_host(self):
        # The dev machine holds no 10.9.0.1, so the helper must not claim a route.
        self.assertFalse(wireguard.server_on_tunnel())


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
        self.assertIn("blocked on the router", data["clients"][0]["reason"])

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
        self.assertEqual(data["clients"][0]["reason"], "Online")
        fetch_active.assert_called_once_with(
            self.router.host,
            self.router.username,
            self.router.password,
            timeout=4.0,
        )

    def test_pppoe_portal_offers_hotspot_handoff_without_converting_customer(self):
        from django.test import RequestFactory

        from core.views import _pppoe_portal_context

        self.org.hotspot_enabled = True
        self.org.save(update_fields=["hotspot_enabled"])
        self.router.wifi_ssid = "Live ISP Hotspot"
        self.router.save(update_fields=["wifi_ssid"])
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
        self.assertTrue(context["dual_access_tabs"])
        self.assertEqual(context["hotspot_ssids"], ["Live ISP Hotspot"])
        self.assertTrue(context["hotspot_payment_start_url"])
        self.assertEqual(context["account_number"], self.customer.account_number)
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.service_type, "pppoe")

    def test_hotspot_portal_offers_pppoe_handoff_without_converting_customer(self):
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
        BillingPlan.objects.create(
            organization=self.org,
            name="Day Pass",
            price="100.00",
            download_speed_mbps=10,
            upload_speed_mbps=5,
        )
        hotspot_customer = Customer.objects.create(
            organization=self.org,
            full_name="Hotspot Device",
            phone="254700000099",
            account_number="HOT-CHOICE",
            service_type=Customer.ServiceType.HOTSPOT,
            hotspot_mac="AA:BB:CC:DD:EE:11",
            status=Customer.Status.ACTIVE,
        )
        request = RequestFactory().get(
            f"/hotspot/{self.org.join_code}/pay/",
            {"mac": "AABBCCDDEE11"},
        )

        context = _hotspot_portal_context(self.org, request=request)
        response = self.client.get(f"/hotspot/{self.org.join_code}/pay/?mac=AABBCCDDEE11")

        self.assertTrue(context["pppoe_option_available"])
        self.assertTrue(context["dual_access_tabs"])
        self.assertTrue(context["pppoe_payment_start_url"])
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Renew PPPoE")
        self.assertContains(response, "Pay for Hotspot")
        self.assertContains(response, 'id="panel-hotspot"')
        self.assertContains(response, 'id="panel-pppoe"')
        self.assertNotContains(response, "Open PPPoE renew page")
        hotspot_customer.refresh_from_db()
        self.assertEqual(hotspot_customer.service_type, "hotspot")

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

    def test_pppoe_pay_accepts_mac_query_for_hotspot_tab(self):
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
        self.assertEqual(response.context["account_number"], self.customer.account_number)
        self.assertEqual(response.context["hotspot_mac"], "AA:BB:CC:DD:EE:FF")
        self.assertContains(response, "AA:BB:CC:DD:EE:FF")
        self.assertContains(response, 'name="mac" value="AA:BB:CC:DD:EE:FF"')

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
        self.assertNotContains(response, "Renew PPPoE")
        self.assertNotContains(response, "Pay for Hotspot")


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

        secret_adds = [props for path, props in adds if path == "/ppp/secret"]
        self.assertEqual(secret_adds[0]["profile"], profile_name)

        rate_sets = [
            item for item in sets if item.get("path") == "/ppp/secret" and "rate-limit" in item
        ]
        self.assertTrue(rate_sets)
        self.assertEqual(rate_sets[0]["rate-limit"], "5M/10M")

        queue_adds = [props for path, props in adds if path == "/queue/simple"]
        self.assertTrue(queue_adds)
        self.assertEqual(queue_adds[0]["max-limit"], "5M/10M")
        self.assertEqual(queue_adds[0]["target"], "10.20.0.50")

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

        with (
            patch(
                "core.mikrotik_connect._print",
                side_effect=lambda sock, path, **kw: list(state.get(path, [])),
            ),
            patch(
                "core.mikrotik_connect._set",
                side_effect=lambda sock, path, item_id, **props: (
                    sets.append(props) or {"_reply": "!done"}
                ),
            ),
            patch("core.mikrotik_connect._add", return_value={"_reply": "!trap"}),
        ):
            result = _ensure_pppoe_rate_profile(
                object(), upload_mbps=10, download_mbps=20
            )

        self.assertEqual(result, name)
        self.assertEqual(sets[0]["rate-limit"], "10M/20M")

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
        with (
            patch("core.mikrotik_connect._print", return_value=[]),
            patch(
                "core.mikrotik_connect._add_or_set_attempts",
                side_effect=lambda sock, path, item_id, attempts: (
                    adds.append(attempts[0]) or ({"_reply": "!done"}, "*1")
                ),
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
