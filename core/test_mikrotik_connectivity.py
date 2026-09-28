"""
Focused tests for VPS ↔ MikroTik connectivity (WireGuard, API pool, stabilization).

Complements the large core/tests.py suite with integration-style cases that
exercise real call ordering and recent env-driven behavior.
"""

from __future__ import annotations

import os
import socket
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings

from core import wireguard
from core.mikrotik_connect import (
    fetch_mikrotik_live_snapshot,
    resolve_nas_api_host,
)
from core.models import MikroTikRouter

SERVER_PUBLIC_KEY = "YT2T/XV2GM3rnkxNPd6b4SFEgQzCScWEfKgSn2J2gWI="


def _router(**kwargs):
    defaults = dict(
        pk=42,
        name="Site",
        host="192.168.88.1",
        vpn_address="",
        api_host="",
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class StabilizeFailuresRequiredTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def _required(self, router_id: int, *, tunnel: bool = False) -> int:
        from core.mikrotik_status_samples import _stabilize_failures_required

        return _stabilize_failures_required(router_id, tunnel=tunnel)

    @override_settings(HOSTED=False)
    def test_local_default_and_tunnel(self):
        self.assertEqual(self._required(1, tunnel=False), 2)
        self.assertEqual(self._required(1, tunnel=True), 3)

    @override_settings(HOSTED=True)
    def test_hosted_default_and_tunnel(self):
        self.assertEqual(self._required(1, tunnel=False), 3)
        self.assertEqual(self._required(1, tunnel=True), 4)

    @override_settings(HOSTED=True)
    def test_hosted_tunnel_env_override(self):
        with patch.dict(os.environ, {"MIKROTIK_STABILIZE_TUNNEL_FAILURES": "5"}):
            self.assertEqual(self._required(1, tunnel=True), 5)

    @override_settings(HOSTED=True)
    def test_hosted_non_tunnel_env_override(self):
        with patch.dict(os.environ, {"MIKROTIK_STABILIZE_FAILURES_HOSTED": "2"}):
            self.assertEqual(self._required(1, tunnel=False), 2)

    @override_settings(HOSTED=False)
    def test_post_onboard_grace_wins(self):
        from core.mikrotik_status_samples import mark_mikrotik_post_onboard_grace

        mark_mikrotik_post_onboard_grace(9, tunnel=True)
        self.assertEqual(self._required(9, tunnel=False), 4)

    @override_settings(HOSTED=False)
    def test_post_uplink_grace_wins(self):
        from core.mikrotik_status_samples import mark_mikrotik_post_uplink_grace

        mark_mikrotik_post_uplink_grace(9, mode="bond")
        self.assertEqual(self._required(9, tunnel=True), 5)


class WireGuardHandshakeWaitTests(SimpleTestCase):
    @override_settings(
        WIREGUARD_ENDPOINT="203.0.113.50:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
        WIREGUARD_SUBNET="10.9.0.0/24",
    )
    def test_handshake_wait_line_count(self):
        lines = wireguard._handshake_wait_lines("10.9.0.1", "10.9.0.21", attempts=8)
        ping_ifs = [
            line
            for line in lines
            if "/ping 10.9.0.1 count=2" in line and line.startswith(":if")
        ]
        self.assertEqual(len(ping_ifs), 8)
        self.assertTrue(any("8.8.8.8" in line for line in lines))


class EnsureReservationPeerTests(SimpleTestCase):
    class _Res:
        label = "Site"
        address = "10.9.0.8"
        public_key = SERVER_PUBLIC_KEY

    @override_settings(
        WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
    )
    def test_no_handshake_when_peer_present_without_handshake(self):
        with (
            patch(
                "core.wireguard.apply_server_peer",
                return_value={"ok": True},
            ),
            patch(
                "core.wireguard.inspect_server_peer",
                return_value={
                    "checked": True,
                    "present": True,
                    "handshake_age_sec": None,
                },
            ),
        ):
            result = wireguard.ensure_reservation_peer(self._Res())
        self.assertEqual(result["code"], "no_handshake")
        self.assertIn("no handshake", result["message"].lower())

    @override_settings(
        WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
    )
    def test_no_handshake_when_stale_age(self):
        with (
            patch("core.wireguard.apply_server_peer", return_value={"ok": True}),
            patch(
                "core.wireguard.inspect_server_peer",
                return_value={
                    "checked": True,
                    "present": True,
                    "handshake_age_sec": 999,
                },
            ),
            patch.dict(os.environ, {"WIREGUARD_HANDSHAKE_MAX_AGE_SEC": "180"}),
        ):
            result = wireguard.ensure_reservation_peer(self._Res())
        self.assertEqual(result["code"], "no_handshake")
        self.assertIn("999s", result["message"])

    @override_settings(
        WIREGUARD_ENDPOINT="isp.richcom.co.ke:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
    )
    def test_waiting_router_when_handshake_fresh(self):
        with (
            patch("core.wireguard.apply_server_peer", return_value={"ok": True}),
            patch(
                "core.wireguard.inspect_server_peer",
                return_value={
                    "checked": True,
                    "present": True,
                    "handshake_age_sec": 30,
                },
            ),
        ):
            result = wireguard.ensure_reservation_peer(self._Res())
        self.assertEqual(result["code"], "waiting_router")


class ResolveNasApiHostCacheTests(SimpleTestCase):
    @override_settings(HOSTED=True)
    def test_hosted_tunnel_success_uses_longer_cache_ttl(self):
        router = _router(pk=7, vpn_address="10.9.0.12", host="192.168.88.1")
        seen: dict[str, int] = {}

        def fake_connect(address, timeout=1.0):
            host, port = address
            if host == "10.9.0.12" and port == 8728:
                return socket.socket()
            raise TimeoutError("timed out")

        def fake_cache_set(key, value, timeout):
            seen["ttl"] = int(timeout)

        with (
            patch(
                "core.mikrotik_connect._router_api_host_candidates",
                return_value=["10.9.0.12", "192.168.88.1"],
            ),
            patch(
                "core.mikrotik_connect.socket.create_connection",
                side_effect=fake_connect,
            ),
            patch("django.core.cache.cache.get", return_value=None),
            patch("django.core.cache.cache.set", side_effect=fake_cache_set),
        ):
            host = resolve_nas_api_host(router, timeout=0.5)
        self.assertEqual(host, "10.9.0.12")
        self.assertEqual(seen.get("ttl"), 180)

    @override_settings(HOSTED=False)
    def test_local_success_uses_shorter_cache_ttl(self):
        router = _router(pk=8, vpn_address="10.9.0.13", host="192.168.1.104")
        seen: dict[str, int] = {}

        def fake_connect(address, timeout=1.0):
            host, port = address
            if host == "192.168.1.104" and port == 8728:
                return socket.socket()
            raise TimeoutError("timed out")

        with (
            patch(
                "core.mikrotik_connect._router_api_host_candidates",
                return_value=["10.9.0.13", "192.168.1.104"],
            ),
            patch(
                "core.mikrotik_connect.socket.create_connection",
                side_effect=fake_connect,
            ),
            patch("django.core.cache.cache.get", return_value=None),
            patch(
                "django.core.cache.cache.set",
                side_effect=lambda k, v, t: seen.update({"ttl": int(t)}),
            ),
        ):
            host = resolve_nas_api_host(router, timeout=0.5)
        self.assertEqual(host, "192.168.1.104")
        self.assertEqual(seen.get("ttl"), 90)


class ApiSessionReuseTests(SimpleTestCase):
    def test_live_snapshot_requests_pooled_session(self):
        with patch("core.mikrotik_connect._api_session") as session_cm:
            session_cm.return_value.__enter__ = lambda self: MagicMock()
            session_cm.return_value.__exit__ = lambda *args: None
            with patch(
                "core.mikrotik_connect._print",
                return_value=[],
            ):
                fetch_mikrotik_live_snapshot("10.9.0.2", "admin", "secret", timeout=3.0)
        session_cm.assert_called_once()
        self.assertTrue(session_cm.call_args.kwargs.get("reuse"))


class WireGuardBootSyncTests(SimpleTestCase):
    def test_sync_interval_respects_floor(self):
        from core.boot import _wireguard_sync_interval_sec

        with patch.dict(os.environ, {"WIREGUARD_SYNC_INTERVAL_SEC": "30"}):
            self.assertEqual(_wireguard_sync_interval_sec(), 120.0)
        with patch.dict(os.environ, {"WIREGUARD_SYNC_INTERVAL_SEC": "900"}):
            self.assertEqual(_wireguard_sync_interval_sec(), 900.0)

    def test_sync_loop_skipped_when_auto_sync_disabled(self):
        from core.boot import _start_wireguard_sync_loop

        with (
            patch.dict(os.environ, {"WIREGUARD_AUTO_SYNC": "false"}),
            patch("core.boot.threading.Thread") as thread_cls,
            override_settings(
                WIREGUARD_ENDPOINT="203.0.113.50:51820",
                WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
            ),
        ):
            _start_wireguard_sync_loop()
        thread_cls.assert_not_called()

    def test_sync_loop_starts_when_configured(self):
        from core.boot import _start_wireguard_sync_loop

        with (
            patch.dict(os.environ, {"WIREGUARD_AUTO_SYNC": "true"}, clear=False),
            patch("core.boot._tunnel_sync_enabled", return_value=True),
            patch("core.wireguard.configured", return_value=True),
            patch("core.boot.threading.Thread") as thread_cls,
        ):
            _start_wireguard_sync_loop()
        thread_cls.assert_called_once()
        self.assertEqual(thread_cls.call_args.kwargs.get("name"), "wireguard-sync")


class EvaluateNasConnectivityIntegrationTests(TestCase):
    """Exercise candidate ordering without mocking resolve_nas_api_host."""

    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization

        self.owner = User.objects.create_user("nas-int-owner", password="x")
        self.org = Organization.objects.create(
            name="NAS Int ISP",
            owner=self.owner,
            join_code="707070",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="192.168.88.1",
            vpn_address="10.9.0.44",
            username="admin",
            password="secret",
        )

    @override_settings(HOSTED=False)
    def test_reaches_lan_when_tunnel_tcp_fails(self):
        from core.connectivity_verification import evaluate_nas_connectivity

        def fake_connect(address, timeout=1.0):
            host, port = address
            if host == "192.168.88.1" and port == 8728:
                return socket.socket()
            raise TimeoutError("tunnel down")

        with (
            patch(
                "core.mikrotik_connect.socket.create_connection",
                side_effect=fake_connect,
            ),
            patch(
                "core.mikrotik_connect.check_mikrotik_reachable",
                side_effect=lambda host, **kw: {
                    "online": host == "192.168.88.1",
                    "via": "api" if host == "192.168.88.1" else "",
                    "error": "" if host == "192.168.88.1" else "timed out",
                },
            ),
            patch(
                "core.mikrotik_connect.test_mikrotik_api_login",
                return_value={"ok": True, "identity": "MikroTik"},
            ),
        ):
            result = evaluate_nas_connectivity(self.router, timeout=2.0)
        self.assertTrue(result["ok"])
        self.assertEqual(result["details"]["working_host"], "192.168.88.1")


class HostedStabilizationPipelineTests(TestCase):
    """stabilize_live_status_rows + probe plan (refresh=1 skips stabilize in the view)."""

    def setUp(self):
        from django.contrib.auth.models import User

        from accounts.models import Organization

        self.owner = User.objects.create_user("hosted-stab-owner", password="x")
        self.org = Organization.objects.create(
            name="Hosted Stab ISP",
            owner=self.owner,
            join_code="808080",
        )
        self.router = MikroTikRouter.objects.create(
            organization=self.org,
            name="Tunnel Edge",
            model=MikroTikRouter.ModelChoice.HEX,
            host="192.168.88.1",
            vpn_address="10.9.0.55",
            username="admin",
            password="secret",
        )
        cache.clear()

    @override_settings(HOSTED=True)
    def test_tunnel_map_holds_four_failures_before_disconnect(self):
        from core.mikrotik_status_samples import (
            _live_stable_cache_key,
            build_router_probe_plan,
            stabilize_live_status_rows,
        )

        connected = {
            "id": self.router.pk,
            "host": self.router.host,
            "name": self.router.name,
            "online": True,
            "status": "connected",
            "error": "",
        }
        cache.set(_live_stable_cache_key(self.org.pk, self.router.pk), connected, 90)

        _candidates, _hosts, tunnel_map, _off = build_router_probe_plan([self.router])
        self.assertTrue(tunnel_map.get(self.router.pk))

        fail_row = {
            "id": self.router.pk,
            "host": self.router.host,
            "name": self.router.name,
            "online": False,
            "status": "disconnected",
            "error": "timed out",
        }

        for _ in range(3):
            rows = stabilize_live_status_rows(
                self.org.pk,
                [fail_row],
                force=False,
                tunnel_by_router=tunnel_map,
            )
            self.assertEqual(rows[0]["status"], "connected")
            self.assertTrue(rows[0].get("stabilized"))

        rows = stabilize_live_status_rows(
            self.org.pk,
            [fail_row],
            force=False,
            tunnel_by_router=tunnel_map,
        )
        self.assertEqual(rows[0]["status"], "disconnected")


class RouterScriptCleanupTests(SimpleTestCase):
    @override_settings(
        WIREGUARD_ENDPOINT="203.0.113.50:51820",
        WIREGUARD_SERVER_PUBLIC_KEY=SERVER_PUBLIC_KEY,
        WIREGUARD_SUBNET="10.9.0.0/24",
    )
    def test_cleanup_removes_watchdog_scheduler(self):
        private_key, _ = wireguard.generate_keypair()
        script = wireguard.routeros_script("10.9.0.21", private_key, factory_reset=False)
        self.assertIn('remove [find where name="ispcentric-tunnel-watch"]', script)
        self.assertIn("ispcentric-tunnel-watch", script)


class PppoeBatchSessionReuseTests(SimpleTestCase):
    def test_finish_uses_existing_socket_without_second_api_session(self):
        from core.mikrotik_connect import _pppoe_batch_finish_on_router

        kick_sock = MagicMock()
        write_state = {
            "notes": [],
            "errors": 0,
            "kick_usernames": ["alice"],
            "block_kick_usernames": [],
            "renew_portal_customers": [],
            "blocked_identity_customers": [],
        }
        router = SimpleNamespace(pk=1, name="NAS")
        with patch("core.mikrotik_connect._api_session") as mock_session:
            with patch(
                "core.mikrotik_connect._enable_cpe_renew_portals_for_batch_block",
                return_value=0,
            ):
                with patch(
                    "core.mikrotik_connect._pppoe_batch_run_kicks_on_socket",
                    return_value=(1, []),
                ) as mock_kicks:
                    with patch(
                        "core.mikrotik_connect._follow_up_pending_cpe_renew_clears",
                        return_value=0,
                    ):
                        with patch(
                            "core.mikrotik_connect._follow_up_pending_cpe_renew_enables",
                            return_value=0,
                        ):
                            result = _pppoe_batch_finish_on_router(
                                router,
                                [],
                                candidate="10.9.0.5",
                                api_user="u",
                                api_password="p",
                                allowed=0,
                                blocked=0,
                                write_state=write_state,
                                kick_sock=kick_sock,
                            )
        mock_session.assert_not_called()
        mock_kicks.assert_called_once()
        self.assertEqual(mock_kicks.call_args[0][0], kick_sock)
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("kicked"), 1)


class HotspotBatchSessionReuseTests(SimpleTestCase):
    def test_hotspot_batch_opens_pooled_api_session(self):
        from core.mikrotik_connect import sync_hotspot_subscription_batch_on_router

        router = SimpleNamespace(
            pk=7,
            host="192.168.88.1",
            username="api",
            password="secret",
            vpn_address="",
            api_host="",
        )
        customer = SimpleNamespace(pk=1)
        session_entered = []

        class FakeSession:
            def __enter__(self):
                session_entered.append(True)
                return MagicMock()

            def __exit__(self, *args):
                return False

        with patch(
            "core.mikrotik_connect._router_api_host_candidates",
            return_value=["192.168.88.1"],
        ):
            with patch(
                "core.mikrotik_connect.socket.create_connection",
            ):
                with patch(
                    "core.mikrotik_connect._api_session",
                    return_value=FakeSession(),
                ) as mock_api:
                    with patch(
                        "core.mikrotik_connect._remove_lan_wide_hotspot_bypasses",
                    ):
                        with patch(
                            "core.mikrotik_connect._print",
                            return_value=[],
                        ):
                            with patch(
                                "core.mikrotik_connect._apply_hotspot_customer_on_socket",
                                return_value={"ok": True},
                            ):
                                with patch(
                                    "core.mikrotik_connect._customer_internet_allowed",
                                    return_value=True,
                                ):
                                    with patch(
                                        "core.mikrotik_connect.clear_hotspot_authorize_pending",
                                    ):
                                        sync_hotspot_subscription_batch_on_router(
                                            router,
                                            [customer],
                                        )
        mock_api.assert_called_once()
        _, kwargs = mock_api.call_args
        self.assertTrue(kwargs.get("reuse"))
        self.assertTrue(session_entered)
