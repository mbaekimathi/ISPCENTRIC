"""Ports page: WAN detection, auto-assign, bond/failover for any ISP."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from core.mikrotik_connect import (
    UPLINK_TAG,
    _default_route_wan,
    _ensure_failover_uplink,
    _parse_ispcentric_mark_index,
    _pcc_slot_counts,
    _port_uplink_hints,
    _resolve_wan_to_physical,
    apply_mikrotik_single_wan,
    auto_rebalance_client_isps,
    plan_client_isp_distribution,
    detect_bandwidth_share_drift,
    _client_traffic_bps,
    clear_all_client_isp_pins,
    switch_client_to_isp_port,
    pin_client_to_isp_mark,
    switch_mikrotik_single_wan,
    apply_mikrotik_uplink_bond,
    apply_mikrotik_uplink_failover,
    assess_bond_members_readiness,
    assess_port_internet_readiness,
    assess_touch_ports_internet,
    assess_uplink_switch_risk,
    build_api_enable_terminal_script,
    build_mikrotik_recovery_script_sections,
    build_pppoe_open_surfing_script,
    build_single_wan_recovery_script,
    list_mikrotik_ports,
)
from core.models import MikroTikRouter
from core.views import (
    _allowed_roles_for_uplink_mode,
    _apply_single_wan_on_router,
    _balance_apply_readiness,
    _bond_apply_readiness,
    _auto_assign_bond_roles,
    _live_bond_candidate_ports,
    _build_router_client_analysis,
    _build_uplink_health_alerts,
    _build_uplink_prompt,
    _suppress_redundant_health_alerts,
    _build_wan_switch_risks,
    _failover_active_wan_port,
    _failover_ports_from_roles,
    _friendly_role_label,
    _live_isp_member_ports,
    _normalize_port_roles_for_uplink_mode,
    _perform_client_isp_switch,
    _pick_auto_wan,
    _port_role_choices_for_ui,
    _role_allowed_for_uplink_mode,
    _smart_balance_health,
    _wan_switch_confirmed,
    apply_detected_uplink,
    resolve_wan_speed_interfaces,
    suggest_port_roles,
)


def _port(
    name: str,
    *,
    running: bool = True,
    disabled: bool = False,
    bridged: bool = False,
    wireless: bool = False,
    uplink_kind: str = "",
    uplink_active: bool | None = None,
    uplink_iface: str | None = None,
    iface_type: str = "ether",
) -> dict:
    if uplink_active is None:
        uplink_active = bool(uplink_kind)
    if uplink_iface is None:
        if uplink_kind == "pppoe":
            uplink_iface = "pppoe-out1"
        elif uplink_kind == "dhcp" and bridged:
            # Behind-provider: DHCP lives on the bridge, attributed to a member.
            uplink_iface = "bridgeLocal"
        elif uplink_kind == "dhcp":
            uplink_iface = name
        else:
            uplink_iface = ""
    return {
        "name": name,
        "type": iface_type,
        "running": running,
        "disabled": disabled,
        "is_bridged": bridged,
        "bridge": "bridgeLocal" if bridged else "",
        "is_wireless": wireless,
        "uplink_kind": uplink_kind,
        "uplink_iface": uplink_iface,
        "uplink_active": uplink_active,
    }


class ResolveWanPhysicalTests(SimpleTestCase):
    def test_pppoe_maps_to_parent(self):
        self.assertEqual(
            _resolve_wan_to_physical(
                "pppoe-out1", {"pppoe-out1": "ether1"}
            ),
            "ether1",
        )

    def test_ether_unchanged(self):
        self.assertEqual(_resolve_wan_to_physical("ether1", {}), "ether1")


class DefaultRouteWanTests(SimpleTestCase):
    def test_maps_pppoe_default_route_to_ether(self):
        def fake_print(sock, path, **kwargs):
            if path == "/interface/pppoe-client":
                return [
                    {
                        "name": "pppoe-out1",
                        "interface": "ether1",
                        "disabled": "false",
                    }
                ]
            if path == "/ip/route":
                return [
                    {
                        "dst-address": "0.0.0.0/0",
                        "gateway": "pppoe-out1",
                        "immediate-gw": "pppoe-out1",
                        "active": "true",
                        "disabled": "false",
                        "distance": "1",
                    }
                ]
            return []

        with patch("core.mikrotik_connect._print", side_effect=fake_print):
            self.assertEqual(_default_route_wan(object()), "ether1")

    def test_dhcp_percent_gateway(self):
        def fake_print(sock, path, **kwargs):
            if path == "/interface/pppoe-client":
                return []
            if path == "/ip/route":
                return [
                    {
                        "dst-address": "0.0.0.0/0",
                        "gateway": "192.168.1.1",
                        "immediate-gw": "192.168.1.1%ether1",
                        "active": "true",
                        "disabled": "false",
                        "distance": "1",
                    }
                ]
            return []

        with patch("core.mikrotik_connect._print", side_effect=fake_print):
            self.assertEqual(_default_route_wan(object()), "ether1")

    def test_bridge_default_route_resolves_via_arp_and_host(self):
        def fake_print(sock, path, **kwargs):
            if path == "/interface/pppoe-client":
                return []
            if path == "/ip/route":
                return [
                    {
                        "dst-address": "0.0.0.0/0",
                        "gateway": "192.168.100.1",
                        "immediate-gw": "192.168.100.1%bridgeLocal",
                        "active": "true",
                        "disabled": "false",
                        "distance": "1",
                    }
                ]
            if path == "/ip/arp":
                return [
                    {
                        "address": "192.168.100.1",
                        "mac-address": "EC:1A:02:A9:9B:45",
                        "interface": "bridgeLocal",
                        "complete": "true",
                    }
                ]
            if path == "/interface/bridge/host":
                return [
                    {
                        "mac-address": "EC:1A:02:A9:9B:45",
                        "on-interface": "ether4",
                        "bridge": "bridgeLocal",
                        "local": "false",
                    },
                    {
                        "mac-address": "AA:BB:CC:DD:EE:FF",
                        "on-interface": "ether3",
                        "bridge": "bridgeLocal",
                        "local": "false",
                    },
                ]
            if path == "/ip/dhcp-client":
                return [
                    {
                        "interface": "bridgeLocal",
                        "disabled": "false",
                        "status": "bound",
                        "gateway": "192.168.100.1",
                    },
                    {
                        "interface": "ether1",
                        "disabled": "false",
                        "status": "",
                        "gateway": "",
                    },
                ]
            return []

        with patch("core.mikrotik_connect._print", side_effect=fake_print):
            self.assertEqual(_default_route_wan(object()), "ether4")
            hints = _port_uplink_hints(object())
        self.assertEqual(hints.get("ether4", {}).get("kind"), "dhcp")
        self.assertEqual(hints.get("ether4", {}).get("active"), "1")
        self.assertNotIn("ether1", hints)  # stale unbound client ignored as active WAN


class SuggestPortRolesTests(SimpleTestCase):
    def test_pppoe_suggested_wan_becomes_internet(self):
        ports = [
            _port("ether1", bridged=False, uplink_kind="pppoe"),
            _port("ether2", bridged=True, running=True),
            _port("ether3", bridged=True, running=False),
            _port("wlan1", bridged=True, wireless=True, iface_type="wlan"),
        ]
        roles = suggest_port_roles(ports, suggested_wan="ether1")
        self.assertEqual(roles["ether1"], MikroTikRouter.PortRole.WAN)
        self.assertEqual(roles["ether2"], MikroTikRouter.PortRole.LAN)
        self.assertEqual(roles["wlan1"], MikroTikRouter.PortRole.LAN)

    def test_second_pppoe_port_stays_unassigned_not_lan(self):
        ports = [
            _port("ether1", uplink_kind="pppoe"),
            _port("ether2", uplink_kind="pppoe", running=True),
            _port("ether3", bridged=True, running=True),
        ]
        roles = suggest_port_roles(ports, suggested_wan="ether1")
        self.assertEqual(roles["ether1"], MikroTikRouter.PortRole.WAN)
        self.assertEqual(roles["ether2"], MikroTikRouter.PortRole.NONE)
        self.assertEqual(roles["ether3"], MikroTikRouter.PortRole.LAN)

    def test_infer_topology_ether1_ether2_uplink_ether3_customer(self):
        from core.views import _infer_port_topology, _suggested_roles_for_uplink_mode

        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True, running=True),
            _port("ether2", bridged=True, running=True),
            _port("ether3", bridged=True, running=True),
            _port("ether4", bridged=True, running=False),
            _port("wlan1", bridged=True, wireless=True, running=False, iface_type="wlan"),
        ]
        topo = _infer_port_topology(ports, suggested_wan="ether1")
        self.assertEqual(topo["uplinks"], ["ether1", "ether2"])
        self.assertIn("ether3", topo["customers"])
        self.assertIn("ether4", topo["customers"])
        self.assertIn("wlan1", topo["customers"])

        roles = suggest_port_roles(ports, suggested_wan="ether1")
        self.assertEqual(roles["ether1"], MikroTikRouter.PortRole.WAN)
        self.assertEqual(roles["ether2"], MikroTikRouter.PortRole.NONE)
        self.assertEqual(roles["ether3"], MikroTikRouter.PortRole.LAN)

        multi = _suggested_roles_for_uplink_mode(
            MikroTikRouter.UplinkMode.SMART_BALANCE,
            ports,
            suggested_wan="ether1",
        )
        self.assertEqual(multi["ether1"], MikroTikRouter.PortRole.WAN)
        self.assertEqual(multi["ether2"], MikroTikRouter.PortRole.WAN_BACKUP)
        self.assertEqual(multi["ether3"], MikroTikRouter.PortRole.LAN)

    def test_uplink_candidates_exclude_customer_ports(self):
        from core.views import _list_uplink_candidates

        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True, running=True),
            _port("ether2", bridged=True, running=True),
            _port("ether3", bridged=True, running=True),
        ]
        names = [c["name"] for c in _list_uplink_candidates(ports, suggested_wan="ether1")]
        self.assertIn("ether1", names)
        self.assertIn("ether2", names)
        self.assertNotIn("ether3", names)

    def test_shared_isp_bridge_warn_is_informational(self):
        from core.views import _port_bridge_warn_payload

        row = _port("ether2", bridged=True, running=True)
        payload = _port_bridge_warn_payload(
            row,
            role=MikroTikRouter.PortRole.WAN_BACKUP,
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
        )
        self.assertTrue(payload["show"])
        self.assertEqual(payload["level"], "info")
        self.assertIn("Shared ISP", payload["message"])

    def test_customer_ports_hide_internet_status(self):
        from core.views import _port_shows_internet_status

        self.assertFalse(_port_shows_internet_status(MikroTikRouter.PortRole.LAN))
        self.assertTrue(_port_shows_internet_status(MikroTikRouter.PortRole.WAN_BACKUP))
        self.assertFalse(_port_shows_internet_status(MikroTikRouter.PortRole.BOND))

    def test_isp_ready_when_wan_share_shows_traffic(self):
        from core.views import _balance_apply_readiness, _port_isp_ready_for_uplink

        ports = [
            _port("ether1", running=True, uplink_kind="dhcp"),
            _port("ether2", running=True, uplink_kind="dhcp"),
        ]
        wan_share = {
            "ok": True,
            "total_bps": 12000,
            "shares": [
                {"name": "ether1", "pct": 58, "bps": 7000},
                {"name": "ether2", "pct": 42, "bps": 5000},
            ],
        }
        self.assertTrue(
            _port_isp_ready_for_uplink("ether1", ports, wan_share=wan_share)
        )
        ready, hint = _balance_apply_readiness(
            ["ether1"],
            ["ether2"],
            ports,
            wan_share=wan_share,
        )
        self.assertTrue(ready, hint)

    def test_wan_share_alone_does_not_ready_link_without_dhcp(self):
        from core.views import _port_isp_ready_for_uplink

        ports = [_port("ether2", running=True)]
        wan_share = {
            "ok": True,
            "total_bps": 5000,
            "shares": [{"name": "ether2", "pct": 100, "bps": 5000}],
        }
        self.assertFalse(
            _port_isp_ready_for_uplink("ether2", ports, wan_share=wan_share)
        )

    def test_isp_ready_when_uplink_live_dhcp_bound(self):
        from core.views import _port_isp_ready_for_uplink

        ports = [_port("ether2", running=True)]
        uplink_live = {
            "ok": True,
            "failover_clients": [
                {"interface": "ether2", "status": "bound", "kind": "dhcp"},
            ],
        }
        self.assertTrue(
            _port_isp_ready_for_uplink(
                "ether2", ports, uplink_live=uplink_live
            )
        )

    def test_setup_status_skips_isp_problems_when_multi_applied(self):
        from core.views import _build_uplink_setup_status

        ports = [
            _port("ether1", running=True),
            _port("ether2", running=True),
        ]
        status = _build_uplink_setup_status(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=ports,
            dual_wan_ready=False,
            bond_ready=False,
            balance_ready=False,
            balance_router_applied=True,
            smart_balance_applied=True,
            uplink_live={"ok": True, "mode": "smart_balance"},
            health_alerts=[],
        )
        self.assertTrue(status["applied"])
        self.assertTrue(status["ok"])
        self.assertNotIn("verified ISP", " ".join(status.get("problems") or []))

    def test_health_alert_skips_no_inet_when_traffic_flowing(self):
        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_live={"ok": True, "mode": "smart_balance"},
            wan_share={
                "ok": True,
                "total_bps": 9000,
                "shares": [
                    {"name": "ether1", "pct": 55, "bps": 5000},
                    {"name": "ether2", "pct": 45, "bps": 4000},
                ],
            },
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=[
                _port("ether1", running=True),
                _port("ether2", running=True),
            ],
            uplink_weights={},
            balance_router_applied=False,
            smart_balance_applied=False,
        )
        codes = [a["code"] for a in alerts]
        self.assertNotIn("balance_member_no_inet", codes)

    def test_sync_ports_internet_display_uses_wan_share(self):
        from core.views import _sync_ports_internet_display

        ports = [
            {
                "name": "ether1",
                "role": "wan",
                "running": True,
                "show_internet_status": True,
                "internet_verified": False,
                "internet_hint": "waiting",
                "internet_level": "warn",
            },
            {
                "name": "ether2",
                "role": "wan_backup",
                "running": True,
                "show_internet_status": True,
                "internet_verified": False,
                "internet_hint": "waiting",
                "internet_level": "warn",
            },
        ]
        wan_share = {
            "ok": True,
            "total_bps": 8000,
            "shares": [
                {"name": "ether1", "pct": 85, "bps": 7000},
                {"name": "ether2", "pct": 15, "bps": 1000},
            ],
        }
        _sync_ports_internet_display(ports, wan_share=wan_share)
        self.assertTrue(ports[0]["internet_verified"])
        self.assertTrue(ports[1]["internet_verified"])
        self.assertEqual(ports[0]["internet_hint"], "")

    def test_backup_prompt_hidden_when_roles_assigned(self):
        from core.views import _build_backup_uplink_prompt

        router = MikroTikRouter(
            name="test",
            host="192.168.88.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            wan_interface="ether1",
            port_roles={
                "ether1": MikroTikRouter.PortRole.WAN,
                "ether2": MikroTikRouter.PortRole.WAN_BACKUP,
            },
            uplink_ports=["ether1", "ether2"],
        )
        live = [
            _port("ether1", running=True, uplink_kind="dhcp", uplink_active=True),
            _port("ether2", running=True),
            {
                "name": "bond-wan",
                "type": "bond",
                "running": True,
                "uplink_kind": "dhcp",
                "uplink_active": True,
            },
        ]
        prompt = _build_backup_uplink_prompt(
            router, live_ports=live, management_iface_by_host={}
        )
        self.assertIsNone(prompt)

    def test_failover_badges_cleared_when_both_ports_share(self):
        from core.views import _sync_ports_failover_display

        ports = [
            {
                "name": "ether1",
                "role": "wan",
                "internet_verified": True,
            },
            {
                "name": "ether2",
                "role": "wan_backup",
                "internet_verified": True,
            },
        ]
        wan_share = {
            "ok": True,
            "total_bps": 8000,
            "shares": [
                {"name": "ether1", "pct": 49, "bps": 3900},
                {"name": "ether2", "pct": 51, "bps": 4100},
            ],
        }
        uplink_live = {
            "ok": True,
            "failover_clients": [
                {"interface": "ether2", "distance": "2", "status": "bound"},
                {"interface": "ether1", "distance": "1", "status": "bound"},
            ],
            "checked_routes": [
                {"active": True, "distance": "2", "disabled": False},
            ],
        }
        _sync_ports_failover_display(
            ports,
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            uplink_live=uplink_live,
            wan_share=wan_share,
        )
        self.assertTrue(ports[0]["sharing_traffic"])
        self.assertTrue(ports[1]["sharing_traffic"])
        self.assertFalse(ports[0]["failover_primary_stood_down"])
        self.assertFalse(ports[1]["failover_carrying"])

    def test_guard_touch_ports_allows_traffic_without_port_dhcp(self):
        from core.views import _guard_touch_ports_internet

        ports = [
            _port("ether1", running=True),
            _port("ether2", running=True, uplink_kind="dhcp", uplink_active=True),
        ]
        wan_share = {
            "ok": True,
            "total_bps": 8000,
            "shares": [
                {"name": "ether1", "pct": 49, "bps": 3900},
                {"name": "ether2", "pct": 51, "bps": 4100},
            ],
        }
        ok, err = _guard_touch_ports_internet(
            ["ether1", "ether2"],
            ports,
            wan_share=wan_share,
        )
        self.assertTrue(ok, err)
        self.assertEqual(err, "")

    def test_guard_touch_ports_allows_uplink_live_dhcp(self):
        from core.views import _guard_touch_ports_internet

        ports = [_port("ether1", running=True), _port("ether2", running=True)]
        uplink_live = {
            "ok": True,
            "failover_clients": [
                {"interface": "ether1", "status": "bound", "kind": "dhcp"},
                {"interface": "ether2", "status": "bound", "kind": "dhcp"},
            ],
        }
        ok, err = _guard_touch_ports_internet(
            ["ether1", "ether2"],
            ports,
            uplink_live=uplink_live,
        )
        self.assertTrue(ok, err)

    def test_probe_shared_isp_unbridges_and_adds_dhcp(self):
        from core.mikrotik_connect import probe_mikrotik_shared_isp_port

        unbridged: list[dict] = []
        dhcp_calls: list[dict] = []

        def fake_unbridge(sock, interfaces):
            unbridged.extend(
                {"interface": iface, "bridge": "bridgeLocal"} for iface in interfaces
            )
            return unbridged

        def fake_ensure(sock, interface, *, distance, add_default_route):
            dhcp_calls.append(
                {
                    "interface": interface,
                    "distance": distance,
                    "add_default_route": add_default_route,
                }
            )
            return {"_reply": "!done"}

        with (
            patch("core.mikrotik_connect._api_session") as session,
            patch("core.mikrotik_connect._iface_names", return_value={"ether2"}),
            patch("core.mikrotik_connect._print", return_value=[]),
            patch("core.mikrotik_connect._unbridge_interfaces", side_effect=fake_unbridge),
            patch(
                "core.mikrotik_connect._ensure_failover_dhcp_client",
                side_effect=fake_ensure,
            ),
        ):
            session.return_value.__enter__.return_value = object()
            result = probe_mikrotik_shared_isp_port(
                "192.168.88.1", "admin", "x", port_name="ether2"
            )
        self.assertTrue(result.get("ok"))
        self.assertTrue(result.get("probed"))
        self.assertEqual(unbridged[0]["interface"], "ether2")
        self.assertFalse(dhcp_calls[0]["add_default_route"])
        self.assertEqual(dhcp_calls[0]["distance"], 10)

    def test_pick_auto_wan_prefers_pppoe_hint_without_suggested(self):
        ports = [
            _port("ether2", bridged=True, running=True),
            _port("ether1", bridged=False, uplink_kind="pppoe"),
        ]
        self.assertEqual(
            _pick_auto_wan(ports, suggested_wan="", saved_wan=""),
            "ether1",
        )

    def test_bridge_behind_provider_assigns_gateway_member_as_wan(self):
        """Router-26 style: DHCP on bridge, ISP modem learned on ether4."""
        ports = [
            _port("ether1", running=False, uplink_kind="dhcp", uplink_active=False),
            _port("ether2", bridged=True, running=False),
            _port("ether3", bridged=True, running=True),
            _port(
                "ether4",
                bridged=True,
                running=True,
                uplink_kind="dhcp",
                uplink_active=True,
            ),
            _port("ether5", bridged=True, running=False),
            _port("wlan1", bridged=True, wireless=True, running=False, iface_type="wlan"),
        ]
        roles = suggest_port_roles(
            ports,
            suggested_wan="ether4",
            saved_wan="ether1",
        )
        self.assertEqual(roles["ether4"], MikroTikRouter.PortRole.WAN)
        self.assertEqual(roles["ether1"], MikroTikRouter.PortRole.UNUSED)
        self.assertEqual(roles["ether2"], MikroTikRouter.PortRole.LAN)
        self.assertEqual(roles["ether3"], MikroTikRouter.PortRole.LAN)
        self.assertEqual(roles["ether5"], MikroTikRouter.PortRole.LAN)
        self.assertEqual(roles["wlan1"], MikroTikRouter.PortRole.LAN)
        self.assertEqual(
            _pick_auto_wan(ports, suggested_wan="ether4", saved_wan="ether1"),
            "ether4",
        )

    def test_stale_saved_ether1_not_preferred_over_live_suggested(self):
        ports = [
            _port("ether1", running=False, uplink_kind="dhcp", uplink_active=False),
            _port("ether4", bridged=True, running=True, uplink_kind="dhcp", uplink_active=True),
        ]
        self.assertEqual(
            _pick_auto_wan(ports, suggested_wan="ether4", saved_wan="ether1"),
            "ether4",
        )

    def test_bridge_name_suggested_wan_is_ignored(self):
        ports = [
            _port("ether1", running=False),
            _port("ether3", bridged=True, running=True),
            _port("ether4", bridged=True, running=True, uplink_kind="dhcp", uplink_active=True),
        ]
        self.assertEqual(
            _pick_auto_wan(ports, suggested_wan="bridgeLocal", saved_wan="ether1"),
            "ether4",
        )

    def test_behind_provider_single_wan_push_is_soft_skipped(self):
        """Do not unbridge the ISP member — that drops customers / hangs API."""
        ports = [
            _port(
                "ether3",
                bridged=True,
                running=True,
                uplink_kind="dhcp",
                uplink_active=True,
            ),
        ]
        router = MagicMock()
        router.uplink_mode = MikroTikRouter.UplinkMode.SINGLE
        with patch("core.views.switch_mikrotik_single_wan") as switch:
            result = _apply_single_wan_on_router(
                router,
                "192.168.100.50",
                wan_interface="ether3",
                live_ports=ports,
            )
            switch.assert_not_called()
        self.assertTrue(result.get("ok"))
        self.assertTrue(result.get("skipped"))
        self.assertIn("bridge", (result.get("message") or "").lower())


class ListPortsEnrichmentTests(SimpleTestCase):
    def test_lists_uplink_kind_and_suggested_physical_wan(self):
        tables = {
            "/interface": [
                {
                    ".id": "*1",
                    "name": "ether1",
                    "type": "ether",
                    "running": "true",
                    "disabled": "false",
                    "comment": "",
                },
                {
                    ".id": "*2",
                    "name": "ether2",
                    "type": "ether",
                    "running": "true",
                    "disabled": "false",
                    "comment": "",
                },
            ],
            "/interface/bridge/port": [
                {"interface": "ether2", "bridge": "bridgeLocal"},
            ],
            "/interface/pppoe-client": [
                {
                    "name": "pppoe-out1",
                    "interface": "ether1",
                    "disabled": "false",
                }
            ],
            "/ip/dhcp-client": [],
            "/ip/route": [
                {
                    "dst-address": "0.0.0.0/0",
                    "gateway": "pppoe-out1",
                    "immediate-gw": "pppoe-out1",
                    "active": "true",
                    "disabled": "false",
                    "distance": "1",
                }
            ],
        }

        def fake_print(sock, path, **kwargs):
            return [dict(r) for r in tables.get(path, [])]

        @contextmanager
        def session(*args, **kwargs):
            yield MagicMock()

        with (
            patch("core.mikrotik_connect._api_session", session),
            patch("core.mikrotik_connect._print", side_effect=fake_print),
        ):
            result = list_mikrotik_ports("10.9.0.3", "admin", "x")

        self.assertTrue(result["ok"])
        self.assertEqual(result["suggested_wan"], "ether1")
        by_name = {p["name"]: p for p in result["ports"]}
        self.assertEqual(by_name["ether1"]["uplink_kind"], "pppoe")
        self.assertEqual(by_name["ether1"]["uplink_iface"], "pppoe-out1")
        self.assertTrue(by_name["ether2"]["is_bridged"])


class ListPortsApiRecoveryTests(SimpleTestCase):
    def test_timeout_includes_winbox_terminal_script(self):
        @contextmanager
        def session(*args, **kwargs):
            raise TimeoutError()
            yield  # pragma: no cover

        with patch("core.mikrotik_connect._api_session", session):
            result = list_mikrotik_ports("10.9.0.3", "admin", "x")

        self.assertFalse(result["ok"])
        self.assertIn("8728", result["error"])
        self.assertIn("8728", result["terminal_script"])
        self.assertIn("Winbox", result["terminal_script"])

    def test_build_api_enable_terminal_script_enables_service(self):
        script = build_api_enable_terminal_script()
        self.assertIn("disabled=no port=8728", script)
        self.assertIn("ispcentric-vpn-api-lan-192", script)
        self.assertIn("ispcentric-vpn-api", script)
        self.assertIn("ispcentric-vpn-api-net", script)
        self.assertIn("Reconnect", script)
        self.assertIn("ispcentric-vpn-hotspot-bypass", script)

    def test_build_pppoe_open_surfing_script_removes_compulsory_and_blocks(self):
        script = build_pppoe_open_surfing_script()
        self.assertIn("PPPoE compulsory", script)
        self.assertIn("ispcentric-blocked", script)
        self.assertIn("ispcentric-pppoe", script)
        self.assertIn("Open surfing enabled", script)

    def test_build_mikrotik_recovery_script_sections_single_wan(self):
        router = MikroTikRouter(
            name="r",
            host="203.0.113.8",
            username="admin",
            password="x",
            wan_interface="ether1",
            uplink_mode=MikroTikRouter.UplinkMode.SINGLE,
            port_roles={"ether1": MikroTikRouter.PortRole.WAN, "ether4": MikroTikRouter.PortRole.WAN_BACKUP},
        )
        sections = build_mikrotik_recovery_script_sections(router)
        keys = [s["key"] for s in sections]
        self.assertEqual(keys, ["management", "single_wan", "open_surfing"])
        single = next(s for s in sections if s["key"] == "single_wan")
        self.assertIn("ether1", single["script"])
        self.assertIn("ether4", single["script"])

    def test_build_mikrotik_recovery_script_sections_includes_uplink_undo(self):
        router = MikroTikRouter(
            name="r",
            host="203.0.113.8",
            username="admin",
            password="x",
            wan_interface="ether1",
            uplink_mode=MikroTikRouter.UplinkMode.BOND,
            bond_interface="bond-wan",
            uplink_ports=["ether1", "ether2"],
            uplink_unbridged=[{"interface": "ether2", "bridge": "bridgeLocal"}],
        )
        sections = build_mikrotik_recovery_script_sections(router)
        keys = [s["key"] for s in sections]
        self.assertIn("uplink", keys)
        uplink = next(s for s in sections if s["key"] == "uplink")
        self.assertIn("bond-wan", uplink["script"])
        self.assertIn("ether2", uplink["script"])


class FailoverUplinkTests(SimpleTestCase):
    def test_uses_pppoe_when_present(self):
        sets: list[tuple[str, dict]] = []

        def fake_print(sock, path, **kwargs):
            if path == "/interface/pppoe-client":
                return [
                    {
                        ".id": "*p",
                        "name": "pppoe-out1",
                        "interface": "ether1",
                        "disabled": "false",
                        "comment": "",
                    }
                ]
            return []

        def fake_set(sock, path, item_id, **props):
            sets.append((path, props))
            return {"_reply": "!done"}

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch("core.mikrotik_connect._add") as add,
        ):
            result = _ensure_failover_uplink(object(), "ether1", distance=1)

        self.assertEqual(result.get("_reply"), "!done")
        add.assert_not_called()
        self.assertTrue(
            any(
                path == "/interface/pppoe-client"
                and props.get("default-route-distance") == "1"
                for path, props in sets
            )
        )

    def test_falls_back_to_dhcp(self):
        adds: list[dict] = []

        def fake_print(sock, path, **kwargs):
            return []

        def fake_add(sock, path, **props):
            adds.append({"path": path, **props})
            return {"_reply": "!done"}

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
        ):
            result = _ensure_failover_uplink(object(), "ether2", distance=11)

        self.assertEqual(result.get("_reply"), "!done")
        self.assertEqual(adds[0]["path"], "/ip/dhcp-client")
        self.assertEqual(adds[0]["interface"], "ether2")
        self.assertEqual(adds[0]["default-route-distance"], "11")
        self.assertIn(UPLINK_TAG, adds[0].get("comment", ""))


class ApplyFailoverAndBondTests(SimpleTestCase):
    def _session(self):
        @contextmanager
        def _api(*args, **kwargs):
            yield MagicMock()

        return _api

    def test_failover_accepts_pppoe_primary(self):
        names = {"ether1", "ether2", "pppoe-out1", "bridgeLocal"}
        added_routes: list[dict] = []

        def fake_print(sock, path, **kwargs):
            if path == "/interface":
                return [{"name": n} for n in names]
            if path == "/interface/pppoe-client":
                return [
                    {
                        ".id": "*p",
                        "name": "pppoe-out1",
                        "interface": "ether1",
                        "disabled": "false",
                    }
                ]
            if path == "/interface/bridge/port":
                return []
            if path == "/interface/list":
                return [{"name": "WAN"}]
            if path == "/interface/list/member":
                return []
            if path == "/ip/route":
                return []
            if path == "/ip/dhcp-client":
                return [
                    {
                        ".id": "*d2",
                        "interface": "ether2",
                        "disabled": "false",
                        "gateway": "10.0.0.1",
                        "status": "bound",
                        "comment": "",
                    }
                ]
            return []

        def fake_add(sock, path, **props):
            if path == "/ip/route":
                added_routes.append(dict(props))
            return {"_reply": "!done"}

        with (
            patch("core.mikrotik_connect._api_session", self._session()),
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch(
                "core.mikrotik_connect._set",
                return_value={"_reply": "!done"},
            ),
            patch(
                "core.mikrotik_connect._add",
                side_effect=fake_add,
            ),
            patch(
                "core.mikrotik_connect._remove",
                return_value={"_reply": "!done"},
            ),
            patch(
                "core.mikrotik_connect._remove_comment_tagged",
                return_value=0,
            ),
            patch(
                "core.mikrotik_connect._ensure_uplink_no_backflow",
                return_value={"ok": True, "changed": True},
            ),
        ):
            result = apply_mikrotik_uplink_failover(
                "10.9.0.3",
                "admin",
                "x",
                primary_port="ether1",
                backup_ports=["ether2"],
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["primary"], "ether1")
        self.assertEqual(result["backups"], ["ether2"])
        self.assertGreaterEqual(len(result.get("checked_routes") or []), 1)
        self.assertTrue(
            any(r.get("check-gateway") == "ping" for r in added_routes),
            added_routes,
        )

    def test_bond_disables_member_dhcp(self):
        names = {"ether1", "ether2", "bridgeLocal"}
        disabled: list[str] = []
        bond_creates: list[dict] = []
        call_order: list[str] = []

        def fake_print(sock, path, **kwargs):
            if path == "/interface":
                return [{"name": n} for n in names]
            if path == "/interface/bonding":
                return []
            if path == "/interface/bridge/port":
                return [
                    {".id": "*b1", "interface": "ether1", "bridge": "bridgeLocal"},
                    {".id": "*b2", "interface": "ether2", "bridge": "bridgeLocal"},
                ]
            if path == "/ip/dhcp-client":
                return [
                    {".id": "*d1", "interface": "ether1", "disabled": "false"},
                    {".id": "*d2", "interface": "ether2", "disabled": "false"},
                ]
            if path == "/interface/list":
                return [{"name": "WAN"}]
            if path == "/interface/list/member":
                return []
            if path == "/interface/pppoe-client":
                return []
            return []

        def fake_set(sock, path, item_id, **props):
            if path == "/ip/dhcp-client" and props.get("disabled") == "yes":
                call_order.append("disable_member_dhcp")
                disabled.append(item_id)
            return {"_reply": "!done"}

        def fake_add(sock, path, **props):
            if path == "/interface/bonding":
                call_order.append("create_bond")
                bond_creates.append(dict(props))
            if path == "/ip/dhcp-client":
                call_order.append("bond_dhcp")
            return {"_reply": "!done"}

        with (
            patch("core.mikrotik_connect._api_session", self._session()),
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch(
                "core.mikrotik_connect._add",
                side_effect=fake_add,
            ),
            patch(
                "core.mikrotik_connect._remove",
                return_value={"_reply": "!done"},
            ),
            patch(
                "core.mikrotik_connect._remove_comment_tagged",
                return_value=0,
            ),
            patch(
                "core.mikrotik_connect._ensure_uplink_no_backflow",
                return_value={"ok": True, "changed": True},
            ),
            patch("core.mikrotik_connect.time.sleep", return_value=None),
            patch(
                "core.mikrotik_connect._wait_for_api_any",
                return_value="10.9.0.3",
            ),
        ):
            result = apply_mikrotik_uplink_bond(
                "10.9.0.3",
                "admin",
                "x",
                member_ports=["ether1", "ether2"],
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(sorted(result.get("disabled_member_dhcp") or []), ["ether1", "ether2"])
        self.assertEqual(sorted(disabled), ["*d1", "*d2"])
        self.assertTrue(bond_creates)
        self.assertEqual(bond_creates[0].get("link-monitoring"), "mii")
        self.assertIn("create_bond", call_order)
        self.assertIn("bond_dhcp", call_order)
        self.assertLess(call_order.index("create_bond"), call_order.index("bond_dhcp"))
        self.assertLess(call_order.index("bond_dhcp"), call_order.index("disable_member_dhcp"))

    def test_bond_moves_pppoe_to_bond(self):
        names = {"ether1", "ether2", "pppoe-out1", "bridgeLocal"}
        sets: list[tuple[str, dict]] = []

        def fake_print(sock, path, **kwargs):
            if path == "/interface":
                return [{"name": n} for n in names]
            if path == "/interface/bonding":
                return []
            if path == "/interface/bridge/port":
                return []
            if path == "/ip/dhcp-client":
                return []
            if path == "/interface/list":
                return [{"name": "WAN"}]
            if path == "/interface/list/member":
                return []
            if path == "/interface/pppoe-client":
                return [
                    {
                        ".id": "*p",
                        "name": "pppoe-out1",
                        "interface": "ether1",
                        "disabled": "false",
                    }
                ]
            return []

        def fake_set(sock, path, item_id, **props):
            sets.append((path, props))
            return {"_reply": "!done"}

        with (
            patch("core.mikrotik_connect._api_session", self._session()),
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch(
                "core.mikrotik_connect._add",
                return_value={"_reply": "!done"},
            ),
            patch(
                "core.mikrotik_connect._remove",
                return_value={"_reply": "!done"},
            ),
            patch(
                "core.mikrotik_connect._remove_comment_tagged",
                return_value=0,
            ),
            patch(
                "core.mikrotik_connect._ensure_uplink_no_backflow",
                return_value={"ok": True, "changed": True},
            ),
            patch("core.mikrotik_connect.time.sleep", return_value=None),
            patch(
                "core.mikrotik_connect._wait_for_api_any",
                return_value="10.9.0.3",
            ),
        ):
            result = apply_mikrotik_uplink_bond(
                "10.9.0.3",
                "admin",
                "x",
                member_ports=["ether1", "ether2"],
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result.get("moved_pppoe"), ["pppoe-out1"])
        self.assertEqual(result.get("uplink_kind"), "pppoe")
        self.assertTrue(
            any(
                path == "/interface/pppoe-client"
                and props.get("interface") == "bond-wan"
                for path, props in sets
            ),
            sets,
        )


class FailoverRoleOrderTests(SimpleTestCase):
    def test_failover_ports_preserve_role_insertion_order(self):
        router = MikroTikRouter(
            port_roles={
                "ether5": "lan",
                "ether3": "wan_backup",
                "ether1": "wan",
                "ether2": "wan_backup",
            }
        )
        primary, backups = _failover_ports_from_roles(router)
        self.assertEqual(primary, "ether1")
        self.assertEqual(backups, ["ether3", "ether2"])

    def test_failover_allows_multiple_backups(self):
        router = MikroTikRouter(
            port_roles={
                "ether1": "wan",
                "ether2": "wan_backup",
                "ether3": "wan_backup",
            }
        )
        primary, backups = _failover_ports_from_roles(router)
        self.assertEqual(primary, "ether1")
        self.assertEqual(backups, ["ether2", "ether3"])


class SingleWanSyncTests(SimpleTestCase):
    def test_adds_physical_and_pppoe_to_wan_list(self):
        added: list[dict] = []

        def fake_print(sock, path, **kwargs):
            if path == "/interface":
                return [
                    {"name": "ether1"},
                    {"name": "pppoe-out1"},
                    {"name": "bridgeLocal"},
                ]
            if path == "/interface/list":
                return [{"name": "WAN"}]
            if path == "/interface/list/member":
                return []
            if path == "/interface/pppoe-client":
                return [
                    {
                        "name": "pppoe-out1",
                        "interface": "ether1",
                        "disabled": "false",
                    }
                ]
            return []

        def fake_add(sock, path, **props):
            added.append({"path": path, **props})
            return {"_reply": "!done"}

        @contextmanager
        def session(*args, **kwargs):
            yield MagicMock()

        with (
            patch("core.mikrotik_connect._api_session", session),
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch(
                "core.mikrotik_connect._set",
                return_value={"_reply": "!done"},
            ),
        ):
            result = apply_mikrotik_single_wan(
                "10.9.0.3", "admin", "x", wan_interface="ether1"
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pppoe"], "pppoe-out1")
        members = [
            a["interface"]
            for a in added
            if a.get("path") == "/interface/list/member"
        ]
        self.assertIn("ether1", members)
        self.assertIn("pppoe-out1", members)


class AssessUplinkSwitchRiskTests(SimpleTestCase):
    def test_tunnel_management_is_safe(self):
        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", uplink_kind="dhcp", running=True),
        ]
        risk = assess_uplink_switch_risk(
            new_wan="ether2",
            old_wan="ether1",
            ports=ports,
            management_host="192.168.88.1",
            tunnel_address="10.9.0.5",
            uses_tunnel=True,
        )
        self.assertTrue(risk["safe"])
        self.assertFalse(risk["blocking"])

    def test_management_on_old_wan_requires_confirm(self):
        ports = [
            _port("ether1", uplink_kind="pppoe"),
            _port("ether2", uplink_kind="dhcp", running=True),
        ]
        risk = assess_uplink_switch_risk(
            new_wan="ether2",
            old_wan="ether1",
            ports=ports,
            management_host="203.0.113.8",
            management_iface_by_host={"203.0.113.8": "pppoe-out1"},
        )
        self.assertFalse(risk["blocking"])
        self.assertTrue(risk["needs_tunnel"])
        self.assertTrue(risk["confirmable"])
        self.assertFalse(risk["safe"])

    def test_bridged_new_wan_warns_without_blocking(self):
        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", bridged=True, uplink_kind="dhcp", running=True),
        ]
        risk = assess_uplink_switch_risk(
            new_wan="ether2",
            old_wan="ether1",
            ports=ports,
            management_host="192.168.10.1",
            management_iface_by_host={"192.168.10.1": "bridgeLocal"},
        )
        self.assertFalse(risk["blocking"])
        self.assertFalse(risk["safe"])
        self.assertTrue(any("bridge" in line.lower() for line in risk["risks"]))

    def test_unverified_tunnel_does_not_auto_safe(self):
        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", uplink_kind="dhcp", running=True),
        ]
        risk = assess_uplink_switch_risk(
            new_wan="ether2",
            old_wan="ether1",
            ports=ports,
            management_host="192.168.88.1",
            tunnel_address="10.9.0.5",
            uses_tunnel=True,
            tunnel_verified=False,
        )
        self.assertFalse(risk["safe"])
        self.assertFalse(risk["tunnel_verified"])


class PortInternetReadinessTests(SimpleTestCase):
    def test_dhcp_active_is_verified(self):
        row = assess_port_internet_readiness(
            _port("ether1", uplink_kind="dhcp", uplink_active=True, running=True)
        )
        self.assertTrue(row["verified"])
        self.assertEqual(row["level"], "ok")

    def test_dhcp_link_without_lease_warns(self):
        row = assess_port_internet_readiness(
            _port("ether2", uplink_kind="dhcp", uplink_active=False, running=True)
        )
        self.assertFalse(row["verified"])
        self.assertEqual(row["level"], "warn")

    def test_pppoe_down_blocks(self):
        row = assess_port_internet_readiness(
            _port("ether1", uplink_kind="pppoe", uplink_active=False, running=False)
        )
        self.assertFalse(row["verified"])
        self.assertEqual(row["level"], "block")

    def test_touch_ports_requires_all_verified(self):
        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True, running=True),
            _port("ether2", uplink_kind="dhcp", uplink_active=False, running=True),
        ]
        check = assess_touch_ports_internet(["ether1", "ether2"], ports)
        self.assertFalse(check["ok"])
        self.assertTrue(check["blocking"])

    def test_bond_members_need_link_not_per_port_dhcp(self):
        ports = [
            _port("ether1", running=True),
            _port("ether2", running=True),
        ]
        check = assess_bond_members_readiness(["ether1", "ether2"], ports)
        self.assertTrue(check["ok"])
        self.assertTrue(check["warnings"])
        self.assertIn("bond after you apply", check["warnings"][0].lower())

    def test_switch_risk_blocks_target_without_link(self):
        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True, running=True),
            _port("ether4", running=False),
        ]
        risk = assess_uplink_switch_risk(
            new_wan="ether4",
            old_wan="ether1",
            ports=ports,
            management_host="192.168.88.1",
        )
        self.assertTrue(risk["blocking"])

    def test_touch_ports_blocks_dhcp_without_lease(self):
        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True, running=True),
            _port("ether2", uplink_kind="dhcp", uplink_active=False, running=True),
        ]
        check = assess_touch_ports_internet(["ether2"], ports)
        self.assertFalse(check["ok"])


class AssessUplinkModeApplyRiskTests(SimpleTestCase):
    def test_mgmt_on_bridge_allows_confirm_for_bond_without_verified_tunnel(self):
        from core.mikrotik_connect import assess_uplink_mode_apply_risk

        ports = [
            _port("ether1", bridged=True, running=True),
            _port("ether4", bridged=True, running=True, uplink_kind="dhcp"),
        ]
        risk = assess_uplink_mode_apply_risk(
            mode="bond",
            touch_ports=["ether1", "ether4"],
            ports=ports,
            management_host="192.168.100.108",
            management_iface_by_host={"192.168.100.108": "bridgeLocal"},
            tunnel_address="",
            tunnel_verified=False,
        )
        self.assertFalse(risk["blocking"])
        self.assertTrue(risk["needs_tunnel"])
        self.assertTrue(risk["confirmable"])
        self.assertFalse(risk["safe"])

    def test_disabled_port_still_blocks_mode_apply(self):
        from core.mikrotik_connect import assess_uplink_mode_apply_risk

        ports = [
            _port("ether1", bridged=True, running=True, disabled=True),
            _port("ether4", bridged=True, running=True),
        ]
        risk = assess_uplink_mode_apply_risk(
            mode="bond",
            touch_ports=["ether1", "ether4"],
            ports=ports,
            management_host="192.168.100.108",
            management_iface_by_host={"192.168.100.108": "bridgeLocal"},
        )
        self.assertTrue(risk["blocking"])
        self.assertFalse(risk["confirmable"])

    def test_verified_tunnel_makes_bond_api_safe(self):
        from core.mikrotik_connect import assess_uplink_mode_apply_risk

        ports = [
            _port("ether1", bridged=True, running=True),
            _port("ether4", bridged=True, running=True),
        ]
        risk = assess_uplink_mode_apply_risk(
            mode="bond",
            touch_ports=["ether1", "ether4"],
            ports=ports,
            management_host="192.168.100.108",
            management_iface_by_host={"192.168.100.108": "bridgeLocal"},
            tunnel_address="10.9.0.20",
            tunnel_verified=True,
        )
        self.assertFalse(risk["blocking"])
        self.assertTrue(risk["safe"])
        self.assertTrue(risk["uses_tunnel"])
        self.assertFalse(risk["needs_tunnel"])

    def test_uplink_recovery_script_restores_bridge(self):
        from core.mikrotik_connect import build_uplink_recovery_script

        script = build_uplink_recovery_script(
            "bond",
            members=["ether1", "ether4"],
            bond_name="ispcentric-bond",
            unbridged=[
                {"interface": "ether1", "bridge": "bridgeLocal"},
                {"interface": "ether4", "bridge": "bridgeLocal"},
            ],
            primary_port="ether1",
        )
        self.assertIn("ispcentric-bond", script)
        self.assertIn("ether4", script)
        self.assertIn("bridgeLocal", script)
        self.assertIn("/interface bridge port add", script)
        self.assertIn("/interface bridge port remove [find interface=$primaryWan]", script)
        self.assertNotIn(':local port1 "ether1"', script)

    def test_uplink_recovery_primary_wan_stays_unbridged(self):
        from core.mikrotik_connect import build_uplink_recovery_script

        script = build_uplink_recovery_script(
            "balance",
            members=["ether1", "ether2"],
            primary_port="ether1",
            unbridged=[{"interface": "ether2", "bridge": "bridgeLocal"}],
        )
        self.assertIn(':local port1 "ether2"', script)
        self.assertNotIn(':local port1 "ether1"', script)
        self.assertIn("add-default-route=yes", script)

    def test_format_balance_gateway_scopes_same_modem_ip(self):
        from core.mikrotik_connect import _format_balance_gateway

        self.assertEqual(
            _format_balance_gateway("192.168.100.1", "ether2"),
            "192.168.100.1%ether2",
        )
        self.assertEqual(
            _format_balance_gateway("192.168.100.1%ether1", "ether2"),
            "192.168.100.1%ether1",
        )

    def test_balance_member_tables_ready_detects_missing_routes(self):
        from core.mikrotik_connect import _balance_member_tables_ready

        sock = object()
        with patch(
            "core.mikrotik_connect._balance_table_has_active_default",
            side_effect=[True, False],
        ):
            missing = _balance_member_tables_ready(sock, 2)
        self.assertEqual(missing, ["ispcentric-w1"])

    def test_multi_isp_reset_prepare_script_clears_and_restores(self):
        from core.mikrotik_connect import build_multi_isp_reset_prepare_script

        script = build_multi_isp_reset_prepare_script(
            primary_wan="ether1",
            shared_wan="ether2",
        )
        self.assertIn("ether1", script)
        self.assertIn("ether2", script)
        self.assertIn("add-default-route=yes", script)
        self.assertIn("add-default-route=no", script)
        self.assertIn("ispcentric", script)

    def test_duplicate_balance_gateway_ports_from_live_routes(self):
        from core.views import _duplicate_balance_gateway_ports

        physical = [
            {"name": "ether1", "uplink_gateway": "192.168.100.1"},
            {"name": "ether2", "uplink_gateway": "192.168.100.1"},
        ]
        dup = _duplicate_balance_gateway_ports(
            ["ether1", "ether2"],
            physical,
            {
                "ok": True,
                "checked_routes": [
                    {"gateway": "192.168.100.1%ether1"},
                    {"gateway": "192.168.100.1%ether2"},
                ],
            },
        )
        self.assertEqual(dup, ["ether1", "ether2"])


class CheckRouterTunnelManagementTests(SimpleTestCase):
    @patch("core.mikrotik_connect._api_session")
    @patch("core.mikrotik_connect.on_router_lan", return_value=True)
    def test_lan_api_with_saved_tunnel_verifies_without_public_key(
        self, _lan, session
    ):
        from core.mikrotik_connect import check_router_tunnel_management

        session.return_value.__enter__ = MagicMock(return_value=None)
        session.return_value.__exit__ = MagicMock(return_value=False)
        router = MikroTikRouter(
            name="r",
            host="192.168.100.108",
            username="admin",
            password="x",
            vpn_address="10.9.0.20",
            vpn_public_key="",
        )
        result = check_router_tunnel_management(router)
        self.assertTrue(result["verified"])
        self.assertTrue(result["api_ok"])

    @patch("core.wireguard.inspect_server_peer")
    @patch("core.mikrotik_connect._api_session", side_effect=OSError("refused"))
    @patch("core.mikrotik_connect.on_router_lan", return_value=False)
    def test_hosted_handshake_alone_not_enough_for_require_api(
        self, _lan, _session, inspect_peer
    ):
        from core.mikrotik_connect import check_router_tunnel_management

        inspect_peer.return_value = {"present": True, "handshake_age_sec": 12}
        router = MikroTikRouter(
            name="r",
            host="10.9.0.20",
            username="admin",
            password="x",
            vpn_address="10.9.0.20",
            vpn_public_key="pk",
        )
        soft = check_router_tunnel_management(router, require_api=False)
        self.assertTrue(soft["verified"])
        self.assertTrue(soft["handshake_ok"])
        self.assertFalse(soft["api_ok"])

        hard = check_router_tunnel_management(router, require_api=True)
        self.assertFalse(hard["verified"])
        self.assertEqual(hard["reason"], "handshake_without_api")


class BondCandidatePortTests(SimpleTestCase):
    def test_auto_assign_bond_explains_bridged_ports(self):
        from core.views import _auto_assign_bond_roles

        router = MikroTikRouter(
            name="r",
            host="192.168.88.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.BOND,
            port_roles={},
        )
        live = [
            {
                "name": "ether1",
                "running": True,
                "disabled": False,
                "is_bridged": True,
                "is_wireless": False,
            },
            {
                "name": "ether2",
                "running": True,
                "disabled": False,
                "is_bridged": True,
                "is_wireless": False,
            },
        ]
        result = _auto_assign_bond_roles(router, live)
        self.assertFalse(result["ok"])
        self.assertIn("LAN bridge", result.get("error") or "")
        self.assertIn("ether1", result.get("error") or "")


class UplinkPromptTests(SimpleTestCase):
    def _router(self, **kwargs):
        router = MikroTikRouter(
            name="test",
            host="192.168.88.1",
            username="admin",
            password="x",
            wan_interface=kwargs.pop("wan_interface", "ether1"),
            uplink_mode=kwargs.pop("uplink_mode", MikroTikRouter.UplinkMode.SINGLE),
            port_roles=kwargs.pop(
                "port_roles", {"ether1": MikroTikRouter.PortRole.WAN}
            ),
        )
        for key, value in kwargs.items():
            setattr(router, key, value)
        return router

    def test_prompt_when_suggested_differs_from_stored(self):
        router = self._router()
        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", uplink_kind="dhcp", running=True),
        ]
        prompt = _build_uplink_prompt(
            router,
            suggested_wan="ether2",
            live_ports=ports,
            management_iface_by_host={"192.168.88.1": "bridgeLocal"},
        )
        self.assertIsNotNone(prompt)
        self.assertEqual(prompt["port"], "ether2")
        self.assertEqual(prompt["current_port"], "ether1")

    def test_no_prompt_when_modes_match(self):
        router = self._router()
        ports = [_port("ether1", uplink_kind="dhcp")]
        prompt = _build_uplink_prompt(
            router,
            suggested_wan="ether1",
            live_ports=ports,
            management_iface_by_host={},
        )
        self.assertIsNone(prompt)


class ApplyDetectedUplinkTests(SimpleTestCase):
    def test_moves_internet_and_clears_old_uplink(self):
        router = MikroTikRouter(
            name="r",
            host="192.168.88.1",
            username="admin",
            password="x",
            wan_interface="ether1",
            uplink_mode=MikroTikRouter.UplinkMode.SINGLE,
            uplink_ports=["ether1"],
            port_roles={
                "ether1": MikroTikRouter.PortRole.WAN,
                "ether2": MikroTikRouter.PortRole.NONE,
            },
        )
        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", uplink_kind="dhcp", running=True),
        ]
        with patch.object(MikroTikRouter, "save"):
            result = apply_detected_uplink(router, "ether2", ports)
        self.assertTrue(result["ok"])
        self.assertEqual(router.wan_interface, "ether2")
        self.assertEqual(router.port_roles["ether2"], MikroTikRouter.PortRole.WAN)
        self.assertEqual(router.port_roles["ether1"], MikroTikRouter.PortRole.NONE)


class UplinkModeRoleRulesTests(SimpleTestCase):
    def test_single_mode_disallows_backup_and_bond(self):
        allowed = _allowed_roles_for_uplink_mode(MikroTikRouter.UplinkMode.SINGLE)
        self.assertIn(MikroTikRouter.PortRole.WAN, allowed)
        self.assertNotIn(MikroTikRouter.PortRole.WAN_BACKUP, allowed)
        self.assertNotIn(MikroTikRouter.PortRole.BOND, allowed)
        self.assertTrue(
            _role_allowed_for_uplink_mode(
                MikroTikRouter.PortRole.WAN, MikroTikRouter.UplinkMode.SINGLE
            )
        )
        self.assertFalse(
            _role_allowed_for_uplink_mode(
                MikroTikRouter.PortRole.WAN_BACKUP, MikroTikRouter.UplinkMode.SINGLE
            )
        )

    def test_failover_mode_requires_dual_wan_roles(self):
        allowed = _allowed_roles_for_uplink_mode(MikroTikRouter.UplinkMode.FAILOVER)
        self.assertIn(MikroTikRouter.PortRole.WAN, allowed)
        self.assertIn(MikroTikRouter.PortRole.WAN_BACKUP, allowed)
        self.assertNotIn(MikroTikRouter.PortRole.BOND, allowed)

    def test_normalize_single_mode_clears_backup_roles(self):
        router = MikroTikRouter(
            name="r",
            host="192.168.88.1",
            username="admin",
            password="x",
            wan_interface="ether4",
            uplink_mode=MikroTikRouter.UplinkMode.FAILOVER,
            port_roles={
                "ether1": MikroTikRouter.PortRole.WAN_BACKUP,
                "ether4": MikroTikRouter.PortRole.WAN,
            },
        )
        roles = _normalize_port_roles_for_uplink_mode(
            router, MikroTikRouter.UplinkMode.SINGLE
        )
        self.assertEqual(roles["ether4"], MikroTikRouter.PortRole.WAN)
        self.assertEqual(roles["ether1"], MikroTikRouter.PortRole.UNUSED)


class UplinkLinkNotificationTests(SimpleTestCase):
    def test_collect_links_without_internet(self):
        from core.views import _collect_mikrotik_links_without_internet

        affected = _collect_mikrotik_links_without_internet(
            physical_ports=[
                _port("ether1", running=False),
                _port("ether2", running=True, uplink_kind="dhcp"),
            ],
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            smart_balance_status={"slow_ports": ["ether2"]},
        )
        ports = {row["port"] for row in affected}
        self.assertIn("ether1", ports)
        self.assertIn("ether2", ports)

    def test_collect_links_without_internet_empty_smart_balance_status(self):
        from core.views import _collect_mikrotik_links_without_internet

        affected = _collect_mikrotik_links_without_internet(
            physical_ports=[
                _port("ether1", running=True, uplink_kind="dhcp"),
                _port("ether2", running=True, uplink_kind="dhcp"),
            ],
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            smart_balance_status={},
        )
        self.assertIsInstance(affected, list)


class UplinkHealthAlertTests(SimpleTestCase):
    def test_failover_on_backup_alert(self):
        from core.views import _build_uplink_health_alerts

        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.FAILOVER,
            uplink_live={
                "ok": True,
                "checked_routes": [{"active": True, "disabled": False, "distance": "11"}],
                "failover_clients": [
                    {"interface": "ether1", "distance": "1", "disabled": False},
                    {"interface": "ether2", "distance": "11", "disabled": False},
                ],
            },
            wan_share={},
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=[
                _port("ether1", running=False),
                _port("ether2", running=True),
            ],
            uplink_weights={},
        )
        codes = [a["code"] for a in alerts]
        self.assertIn("failover_on_backup", codes)
        msg = next(a for a in alerts if a["code"] == "failover_on_backup")
        self.assertEqual(msg.get("reason_code"), "link_down")
        self.assertIn("ether2", msg.get("title", "") + msg.get("message", ""))
        self.assertIn("ether1", msg.get("message", ""))
        self.assertIn("no cable link", msg.get("message", "").lower())
        self.assertIn("when ether1 link comes back", msg.get("message", "").lower())

    def test_failover_on_backup_routing_failure_message(self):
        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_live={
                "ok": True,
                "mode": "smart_balance",
                "checked_routes": [
                    {
                        "active": False,
                        "disabled": False,
                        "distance": "1",
                        "check_gateway": "ping",
                        "gateway": "192.168.1.1",
                    },
                    {
                        "active": True,
                        "disabled": False,
                        "distance": "11",
                        "check_gateway": "ping",
                    },
                ],
                "failover_clients": [
                    {"interface": "ether1", "distance": "1", "disabled": False},
                    {"interface": "ether2", "distance": "11", "disabled": False},
                ],
            },
            wan_share={},
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=[
                _port("ether1", running=True, uplink_kind="dhcp"),
                _port("ether2", running=True, uplink_kind="dhcp"),
            ],
            uplink_weights={},
            balance_router_applied=True,
            smart_balance_applied=True,
        )
        msg = next(a for a in alerts if a["code"] == "failover_on_backup")
        self.assertEqual(msg.get("reason_code"), "routing_health")
        self.assertIn("gateway health checks", msg.get("message", "").lower())
        self.assertIn("192.168.1.1", msg.get("message", ""))
        self.assertIn(
            "when ether1 passes gateway health checks again",
            msg.get("message", "").lower(),
        )
        self.assertIn("customers stay online", msg.get("message", "").lower())

    def test_failover_on_backup_with_empty_smart_balance_status(self):
        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_live={
                "ok": True,
                "mode": "smart_balance",
                "checked_routes": [
                    {
                        "active": False,
                        "disabled": False,
                        "distance": "1",
                        "check_gateway": "ping",
                        "gateway": "192.168.1.1",
                    },
                    {
                        "active": True,
                        "disabled": False,
                        "distance": "11",
                        "check_gateway": "ping",
                    },
                ],
                "failover_clients": [
                    {"interface": "ether1", "distance": "1", "disabled": False},
                    {"interface": "ether2", "distance": "11", "disabled": False},
                ],
            },
            wan_share={},
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=[
                _port("ether1", running=True, uplink_kind="dhcp"),
                _port("ether2", running=True, uplink_kind="dhcp"),
            ],
            uplink_weights={},
            balance_router_applied=True,
            smart_balance_applied=True,
            smart_balance_status={},
        )
        codes = [a["code"] for a in alerts]
        self.assertIn("failover_on_backup", codes)

    def test_failover_on_backup_smart_balance_slow_reason(self):
        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_live={
                "ok": True,
                "mode": "smart_balance",
                "checked_routes": [
                    {"active": False, "disabled": False, "distance": "1", "check_gateway": "ping"},
                    {"active": True, "disabled": False, "distance": "11", "check_gateway": "ping"},
                ],
                "failover_clients": [
                    {"interface": "ether1", "distance": "1", "disabled": False},
                    {"interface": "ether2", "distance": "11", "disabled": False},
                ],
            },
            wan_share={},
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=[
                _port("ether1", running=True, uplink_kind="dhcp"),
                _port("ether2", running=True, uplink_kind="dhcp"),
            ],
            uplink_weights={},
            balance_router_applied=True,
            smart_balance_applied=True,
            smart_balance_status={"ok": True, "slow_ports": ["ether1"], "members": {"ether1": "slow"}},
        )
        msg = next(a for a in alerts if a["code"] == "failover_on_backup")
        self.assertEqual(msg.get("reason_code"), "smart_balance_slow")
        self.assertIn("sidelined", msg.get("message", "").lower())

    def test_failover_using_backup_route_detects_active_backup(self):
        from core.views import _failover_using_backup_route

        live = {
            "checked_routes": [{"active": True, "disabled": False, "distance": "11"}],
            "failover_clients": [
                {"interface": "ether1", "distance": "1", "disabled": False},
                {"interface": "ether2", "distance": "11", "disabled": False},
            ],
        }
        self.assertTrue(
            _failover_using_backup_route("ether1", ["ether2"], live)
        )
        self.assertFalse(
            _failover_using_backup_route("ether1", ["ether2"], {"checked_routes": [], "failover_clients": []})
        )

    def test_backup_prompt_skips_customer_port_with_link(self):
        from core.views import _build_backup_uplink_prompt

        router = MikroTikRouter(
            name="r1",
            host="192.168.88.1",
            username="admin",
            password="x",
            wan_interface="ether1",
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            port_roles={
                "ether1": MikroTikRouter.PortRole.WAN,
                "ether2": MikroTikRouter.PortRole.WAN_BACKUP,
                "ether3": MikroTikRouter.PortRole.LAN,
            },
            uplink_ports=["ether1", "ether2"],
        )
        live = [
            _port("ether1", running=True, uplink_kind="dhcp"),
            _port("ether2", running=True, uplink_kind="dhcp"),
            _port("ether3", running=True, bridged=True),
        ]
        prompt = _build_backup_uplink_prompt(
            router,
            live_ports=live,
            management_iface_by_host={},
        )
        self.assertIsNone(prompt)

    def test_multi_uplink_alert_ignores_customer_port(self):
        from core.views import _build_uplink_health_alerts

        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.SINGLE,
            uplink_live={"ok": True},
            wan_share={},
            primary_wan_ports=["ether1"],
            backup_wan_ports=[],
            bond_member_ports=[],
            physical_ports=[
                {
                    **_port("ether1", running=True, uplink_kind="dhcp"),
                    "role": MikroTikRouter.PortRole.WAN,
                },
                {
                    **_port("ether2", running=True, uplink_kind="dhcp"),
                    "role": MikroTikRouter.PortRole.NONE,
                },
                {
                    **_port("ether3", running=True, bridged=True),
                    "role": MikroTikRouter.PortRole.LAN,
                },
            ],
            uplink_weights={},
        )
        multi = [a for a in alerts if a.get("code") == "multi_uplink_available"]
        self.assertEqual(len(multi), 1)
        self.assertIn("ether2", multi[0].get("message", ""))
        self.assertNotIn("ether3", multi[0].get("message", ""))
        self.assertEqual(multi[0].get("action"), "set_multi_isp")

    def test_bond_slave_down_alert(self):
        from core.views import _build_uplink_health_alerts

        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.BOND,
            uplink_live={"ok": True, "bonds": [{"running": True}]},
            wan_share={},
            primary_wan_ports=[],
            backup_wan_ports=[],
            bond_member_ports=["ether1", "ether2"],
            physical_ports=[
                _port("ether1", running=True),
                _port("ether2", running=False),
            ],
            uplink_weights={},
        )
        self.assertTrue(any(a["code"] == "bond_slave_down" for a in alerts))


class BalanceUplinkImprovementTests(SimpleTestCase):
    def test_pcc_slot_counts_weighted_ratio(self):
        self.assertEqual(_pcc_slot_counts([100, 20]), [5, 1])
        self.assertEqual(_pcc_slot_counts([100, 100]), [1, 1])

    def test_balance_role_label_uses_shared_isp(self):
        labels = dict(_port_role_choices_for_ui(MikroTikRouter.UplinkMode.BALANCE))
        self.assertEqual(labels[MikroTikRouter.PortRole.WAN_BACKUP], "Shared ISP")
        smart_labels = dict(_port_role_choices_for_ui(MikroTikRouter.UplinkMode.SMART_BALANCE))
        self.assertEqual(smart_labels[MikroTikRouter.PortRole.WAN_BACKUP], "Shared ISP")
        self.assertEqual(
            _friendly_role_label(
                MikroTikRouter.PortRole.WAN_BACKUP,
                mode=MikroTikRouter.UplinkMode.BALANCE,
            ),
            "Shared ISP",
        )
        self.assertEqual(
            _friendly_role_label(
                MikroTikRouter.PortRole.WAN_BACKUP,
                mode=MikroTikRouter.UplinkMode.FAILOVER,
            ),
            "Backup internet",
        )

    def test_balance_apply_readiness_messages(self):
        ready, hint = _balance_apply_readiness(
            ["ether1"],
            ["ether2"],
            [
                _port("ether1", uplink_kind="dhcp", uplink_active=True, running=True),
                _port("ether2", uplink_kind="dhcp", uplink_active=True, running=True),
            ],
        )
        self.assertTrue(ready)
        self.assertIn("Apply load balance", hint)

        ready, hint = _balance_apply_readiness(
            ["ether1"],
            ["ether2"],
            [
                _port("ether1", uplink_kind="dhcp", uplink_active=True, running=True),
                _port("ether2", uplink_kind="dhcp", uplink_active=False, running=True),
            ],
        )
        self.assertFalse(ready)
        self.assertIn("Live ISP internet", hint)

        ready, hint = _balance_apply_readiness(
            [],
            ["ether2"],
            [_port("ether2", running=True)],
        )
        self.assertFalse(ready)
        self.assertIn("Internet", hint)

        ready, hint = _balance_apply_readiness(
            ["ether1"],
            [],
            [_port("ether1", running=True)],
        )
        self.assertFalse(ready)
        self.assertIn("Shared ISP", hint)

        ready, hint = _balance_apply_readiness(
            ["ether1"],
            ["ether2"],
            [_port("ether1", running=True), _port("ether2", running=False)],
        )
        self.assertFalse(ready)
        self.assertIn("ether2", hint)

    def test_resolve_wan_speed_interfaces_includes_all_balance_ports(self):
        router = MikroTikRouter(
            name="r",
            host="192.168.88.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.BALANCE,
            uplink_ports=["ether1", "ether2", "ether3"],
        )
        ports = resolve_wan_speed_interfaces(router)
        self.assertEqual(
            [p["interface"] for p in ports],
            ["ether1", "ether2", "ether3"],
        )

    def test_balance_not_applied_alert(self):
        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.BALANCE,
            uplink_live={"ok": True, "mode": "failover"},
            wan_share={},
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=[
                _port("ether1", running=True),
                _port("ether2", running=True),
            ],
            uplink_weights={"ether1": 100, "ether2": 20},
            balance_router_applied=False,
        )
        codes = [a["code"] for a in alerts]
        self.assertIn("balance_not_applied", codes)

    def test_suppress_balance_not_applied_when_backup_prompt(self):
        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_live={"ok": True, "mode": "smart_balance"},
            wan_share={},
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=[
                _port("ether1", running=True),
                _port("ether2", running=True),
            ],
            uplink_weights={"ether1": 100, "ether2": 100},
            balance_router_applied=False,
        )
        filtered = _suppress_redundant_health_alerts(
            alerts,
            backup_uplink_prompt={"port": "ether3"},
            uplink_prompt=None,
            recommendation={},
        )
        codes = [a["code"] for a in filtered]
        self.assertNotIn("balance_not_applied", codes)

    def test_suppress_drift_when_failover_on_backup(self):
        alerts = [
            {
                "level": "warn",
                "code": "failover_on_backup",
                "title": "Internet flowing through ether2",
                "message": "ether1 has no cable link. Customers stay online.",
            },
            {
                "level": "info",
                "code": "balance_share_drift",
                "message": "Live bandwidth share differs from connection weights.",
            },
            {
                "level": "warn",
                "code": "smart_balance_monitor_off",
                "message": "PCC balance is on the MikroTik but the slow-link monitor is missing.",
            },
        ]
        filtered = _suppress_redundant_health_alerts(
            alerts,
            backup_uplink_prompt=None,
            uplink_prompt=None,
            recommendation={},
        )
        codes = [a["code"] for a in filtered]
        self.assertEqual(codes, ["failover_on_backup"])

    def test_balance_member_down_alert(self):
        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.BALANCE,
            uplink_live={"ok": True, "mode": "balance"},
            wan_share={},
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=[
                _port("ether1", running=True),
                _port("ether2", running=False),
            ],
            uplink_weights={},
            balance_router_applied=True,
        )
        self.assertTrue(any(a["code"] == "balance_member_down" for a in alerts))

    def test_smart_balance_script_contains_ping_monitor(self):
        from core.mikrotik_connect import (
            _build_smart_balance_marker_script,
            _parse_routeros_rtt_ms,
        )

        script = _build_smart_balance_marker_script()
        self.assertIn("billing server API", script)
        self.assertIn(":return", script)
        self.assertAlmostEqual(_parse_routeros_rtt_ms("10ms227us"), 10.227, places=2)
        self.assertAlmostEqual(_parse_routeros_rtt_ms("250ms"), 250.0, places=1)

    def test_smart_balance_scheduler_uses_on_event_hyphen(self):
        from core.mikrotik_connect import (
            SMART_BALANCE_SCRIPT_NAME,
            _install_smart_balance_monitor,
        )

        add_calls: list[dict] = []

        def fake_add(sock, path, **props):
            add_calls.append({"path": path, **props})
            return {"_reply": "!done", "ret": "*1"}

        def fake_add_or_set(sock, path, item_id, attempts):
            if path == "/system/scheduler":
                add_calls.append({"path": path, **attempts[0]})
                return {"_reply": "!done"}, ""
            return {"_reply": "!done"}, ""

        with (
            patch(
                "core.mikrotik_connect._remove_named_routeros_items",
                return_value=0,
            ),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch(
                "core.mikrotik_connect._add_or_set_attempts",
                side_effect=fake_add_or_set,
            ),
            patch(
                "core.mikrotik_connect._command",
                return_value=([], {"_reply": "!done"}),
            ),
        ):
            result = _install_smart_balance_monitor(
                object(),
                [
                    {"interface": "ether1", "weight": "100", "index": "0"},
                    {"interface": "ether2", "weight": "100", "index": "1"},
                ],
            )

        self.assertTrue(result.get("ok"), result)
        sched_calls = [c for c in add_calls if c.get("path") == "/system/scheduler"]
        self.assertTrue(sched_calls)
        self.assertIn("on-event", sched_calls[0])
        self.assertNotIn("on_event", sched_calls[0])
        self.assertEqual(sched_calls[0].get("on-event"), SMART_BALANCE_SCRIPT_NAME)

    def test_smart_balance_slow_alert(self):
        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_live={"ok": True, "mode": "smart_balance"},
            wan_share={},
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=[
                _port("ether1", running=True),
                _port("ether2", running=True),
            ],
            uplink_weights={},
            balance_router_applied=True,
            smart_balance_status={"ok": True, "slow_ports": ["ether2"], "members": {"ether2": "slow"}},
        )
        self.assertTrue(any(a["code"] == "smart_balance_slow" for a in alerts))


class BondAutoSetupTests(SimpleTestCase):
    def test_live_bond_candidates_prefers_plain_links(self):
        ports = [
            _port("ether1", running=True),
            _port("ether2", running=True),
            _port("ether4", uplink_kind="dhcp", uplink_active=True, running=True),
        ]
        candidates = _live_bond_candidate_ports(ports)
        self.assertEqual(candidates[:2], ["ether1", "ether2"])

    def test_auto_assign_bond_roles_picks_two_links(self):
        router = MikroTikRouter(
            name="test",
            host="192.168.88.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.BOND,
            port_roles={},
        )
        ports = [_port("ether1", running=True), _port("ether4", running=True)]
        with patch.object(MikroTikRouter, "save", return_value=None):
            result = _auto_assign_bond_roles(router, ports)
        self.assertTrue(result["ok"])
        self.assertTrue(result["changed"])
        self.assertEqual(result["members"], ["ether1", "ether4"])
        self.assertEqual(
            router.port_roles,
            {
                "ether1": MikroTikRouter.PortRole.BOND,
                "ether4": MikroTikRouter.PortRole.BOND,
            },
        )

    def test_bond_apply_readiness_requires_two_members(self):
        ready, hint = _bond_apply_readiness(["ether1"], [_port("ether1", running=True)])
        self.assertFalse(ready)
        self.assertIn("two", hint.lower())

    def test_bond_apply_readiness_skips_hint_when_already_applied(self):
        ports = [
            _port("ether1", running=True),
            _port("ether2", running=True),
        ]
        ready, hint = _bond_apply_readiness(
            ["ether1", "ether2"],
            ports,
            bond_applied=True,
        )
        self.assertTrue(ready)
        self.assertEqual(hint, "")

    def test_bond_members_readiness_uses_single_warning_not_per_port(self):
        ports = [
            _port("ether1", running=True),
            _port("ether2", running=True),
        ]
        check = assess_bond_members_readiness(["ether1", "ether2"], ports)
        self.assertTrue(check["ok"])
        self.assertEqual(len(check["warnings"]), 1)
        self.assertIn("bond after you apply", check["warnings"][0].lower())
        for status in (check.get("per_port") or {}).values():
            self.assertEqual(status.get("level"), "ok")


class SmartBalanceAutoSetupTests(SimpleTestCase):
    def test_live_isp_member_ports_orders_primary_first(self):
        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True, running=True),
            _port("ether4", uplink_kind="dhcp", uplink_active=True, running=True),
            _port("ether2", bridged=True, running=True),
        ]
        members = _live_isp_member_ports(
            ports,
            suggested_wan="ether4",
            saved_wan="ether1",
        )
        self.assertEqual(members[0], "ether4")
        self.assertIn("ether1", members)

    def test_smart_balance_health_requires_monitor(self):
        health = _smart_balance_health(
            {
                "ok": True,
                "mode": "smart_balance",
                "balance_pcc_rules": 4,
                "smart_balance_enabled": False,
            },
            MikroTikRouter.UplinkMode.SMART_BALANCE,
        )
        self.assertTrue(health.get("needs_apply"))
        self.assertFalse(health.get("effective"))

        ok = _smart_balance_health(
            {
                "ok": True,
                "mode": "smart_balance",
                "balance_pcc_rules": 4,
                "smart_balance_enabled": True,
            },
            MikroTikRouter.UplinkMode.SMART_BALANCE,
        )
        self.assertTrue(ok.get("effective"))


class SwitchSingleWanTests(SimpleTestCase):
    def test_switch_unbridges_new_port_and_retires_old(self):
        added: list[dict] = []
        sets: list[dict] = []
        removed: list[str] = []

        def fake_print(sock, path, **kwargs):
            if path == "/interface":
                return [
                    {"name": "ether1", "type": "ether"},
                    {"name": "ether4", "type": "ether"},
                ]
            if path == "/interface/bridge/port":
                return [{"interface": "ether4", "bridge": "bridgeLocal", ".id": "*bp1"}]
            if path == "/interface/list/member":
                return [
                    {
                        "list": "WAN",
                        "interface": "ether1",
                        ".id": "*lm1",
                        "comment": "",
                    }
                ]
            if path == "/ip/dhcp-client":
                return [
                    {
                        "interface": "ether1",
                        ".id": "*d1",
                        "disabled": "false",
                        "add-default-route": "yes",
                    }
                ]
            if path == "/interface/pppoe-client":
                return []
            if path == "/ip/route":
                return []
            return []

        def fake_add(sock, path, **props):
            added.append({"path": path, **props})
            return {"_reply": "!done"}

        def fake_set(sock, path, item_id, **props):
            sets.append({"path": path, "id": item_id, **props})
            return {"_reply": "!done"}

        def fake_remove(sock, path, item_id):
            removed.append(path)
            return {"_reply": "!done"}

        @contextmanager
        def session(*args, **kwargs):
            yield MagicMock()

        with (
            patch("core.mikrotik_connect._api_session", session),
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch("core.mikrotik_connect._remove", side_effect=fake_remove),
            patch(
                "core.mikrotik_connect._ensure_failover_uplink",
                return_value={"_reply": "!done", "_kind": "dhcp"},
            ),
        ):
            result = switch_mikrotik_single_wan(
                "10.9.0.3",
                "admin",
                "x",
                wan_interface="ether4",
                retire_ports=["ether1"],
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["wan_interface"], "ether4")
        self.assertIn("/interface/bridge/port", removed)
        dhcp_disables = [
            s for s in sets if s.get("path") == "/ip/dhcp-client" and s.get("disabled") == "yes"
        ]
        self.assertTrue(dhcp_disables)
        wan_members = [
            a["interface"]
            for a in added
            if a.get("path") == "/interface/list/member" and a.get("interface")
        ]
        self.assertIn("ether4", wan_members)


class WanSwitchRiskTests(SimpleTestCase):
    def test_recovery_script_targets_wan_and_clears_uplink_tag(self):
        script = build_single_wan_recovery_script(
            "ether4",
            retire_ports=["ether1"],
        )
        self.assertIn('ether4', script)
        self.assertIn('ether1', script)
        self.assertIn(UPLINK_TAG, script)
        self.assertIn("Single Internet reset", script)

    def test_wan_switch_confirmed_blocks_without_checkbox(self):
        ok, err = _wan_switch_confirmed(
            _FakeRequest(),
            {"safe": False, "blocking": False, "risks": ["Brief outage likely."]},
        )
        self.assertFalse(ok)
        self.assertIn("Confirm", err)

    def test_wan_switch_confirmed_allows_with_checkbox(self):
        ok, err = _wan_switch_confirmed(
            _FakeRequest(confirm_risk="1"),
            {"safe": False, "blocking": False, "risks": ["Brief outage likely."]},
        )
        self.assertTrue(ok)
        self.assertEqual(err, "")

    def test_build_wan_switch_risks_includes_rollback_to_previous_wan(self):
        router = MikroTikRouter(
            name="r",
            host="203.0.113.8",
            username="admin",
            password="x",
            wan_interface="ether1",
            uplink_mode=MikroTikRouter.UplinkMode.SINGLE,
            port_roles={"ether1": MikroTikRouter.PortRole.WAN},
        )
        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether4", uplink_kind="dhcp", running=True),
        ]
        risks = _build_wan_switch_risks(
            router,
            live_ports=ports,
            management_iface_by_host={},
            primary_wan_ports=["ether1"],
            tunnel_verified=True,
        )
        script = risks["ether4"].get("rollback_recovery_script") or ""
        self.assertIn("ether1", script)
        self.assertIn("ether4", script)
        self.assertIn("Single Internet reset on", script)

    def test_build_wan_switch_risks_skips_current_wan(self):
        router = MikroTikRouter(
            name="r",
            host="203.0.113.8",
            username="admin",
            password="x",
            wan_interface="ether1",
            uplink_mode=MikroTikRouter.UplinkMode.SINGLE,
            port_roles={"ether1": MikroTikRouter.PortRole.WAN},
        )
        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", uplink_kind="dhcp", running=True),
        ]
        risks = _build_wan_switch_risks(
            router,
            live_ports=ports,
            management_iface_by_host={"203.0.113.8": "pppoe-out1"},
            primary_wan_ports=["ether1"],
        )
        self.assertNotIn("ether1", risks)
        self.assertIn("ether2", risks)
        self.assertFalse(risks["ether2"].get("safe"))


class _FakeRequest:
    def __init__(self, confirm_risk: str = ""):
        self.POST = {"confirm_risk": confirm_risk}


class RouterClientAnalysisTests(SimpleTestCase):
    def test_parse_ispcentric_mark_index(self):
        self.assertEqual(_parse_ispcentric_mark_index("ispcentric-c0"), 0)
        self.assertEqual(_parse_ispcentric_mark_index("ispcentric-c2"), 2)
        self.assertIsNone(_parse_ispcentric_mark_index("no-mark"))

    def test_failover_active_wan_port_prefers_active_route_distance(self):
        uplink_live = {
            "checked_routes": [{"distance": "2", "active": True}],
            "failover_clients": [
                {"interface": "ether1", "distance": "1", "disabled": False},
                {"interface": "ether2", "distance": "2", "disabled": False},
            ],
        }
        self.assertEqual(
            _failover_active_wan_port(
                uplink_live,
                primary_wan_ports=["ether1"],
                backup_wan_ports=["ether2"],
            ),
            "ether2",
        )

    def test_build_router_client_analysis_maps_pppoe_ip_to_isp(self):
        router = MikroTikRouter(
            name="edge",
            host="10.0.0.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.BALANCE,
            uplink_ports=["ether1", "ether2"],
            uplink_weights={"ether1": 100, "ether2": 50},
        )
        customer = MagicMock()
        customer.pk = 7
        customer.full_name = "Jane Doe"
        customer.account_number = "ACC-7"
        customer.pppoe_username = "jane"
        customer.hotspot_mac = None
        customer.cpe_ip = ""
        customer.cpe_mac = ""
        customer.service_type = "pppoe"
        customer.status = "active"

        usage = {
            "ok": True,
            "uses_connection_marks": True,
            "default_isp_port": "ether1",
            "ip_usage": {
                "10.10.0.5": {
                    "isp_port": "ether2",
                    "connections": 4,
                    "source": "connection_mark",
                }
            },
            "sessions": {
                "10.10.0.5": {"pppoe_username": "jane", "source": "pppoe"},
            },
        }
        with patch("billing.models.Customer.objects") as customer_qs:
            customer_qs.filter.return_value.only.return_value = [customer]
            analysis = _build_router_client_analysis(
                router,
                uplink_mode=MikroTikRouter.UplinkMode.BALANCE,
                uplink_live={},
                wan_share={
                    "ok": True,
                    "shares": [
                        {"name": "ether1", "pct": 60, "rate_label": "12 Mbps"},
                        {"name": "ether2", "pct": 40, "rate_label": "8 Mbps"},
                    ],
                },
                smart_balance_status={"slow_ports": ["ether2"]},
                primary_wan_ports=["ether1"],
                backup_wan_ports=["ether2"],
                usage=usage,
            )

        self.assertTrue(analysis["ok"])
        self.assertEqual(len(analysis["isps"]), 2)
        self.assertEqual(analysis["isps"][1]["status"], "slow")
        self.assertEqual(analysis["summary"]["online_clients"], 1)
        client = analysis["clients"][0]
        self.assertEqual(client["name"], "Jane Doe")
        self.assertEqual(client["isp_port"], "ether2")
        self.assertEqual(client["uplink_port"], "ether2")
        self.assertEqual(client["uplink_index"], 1)
        self.assertTrue(client["uplink_tracked"])
        self.assertEqual(client["uplink_source_label"], "Live routing")
        self.assertEqual(client["connection_count"], 4)
        self.assertIn("download_label", client)
        self.assertIn("usage_url", client)
        self.assertTrue(any(p["kind"] == "isp" for p in analysis["port_analytics"]))

    def test_build_router_client_analysis_handles_string_member_status(self):
        router = MikroTikRouter(
            name="edge",
            host="10.0.0.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_ports=["ether1", "ether2"],
        )
        with patch("billing.models.Customer.objects") as customer_qs:
            customer_qs.filter.return_value.only.return_value = []
            analysis = _build_router_client_analysis(
                router,
                uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
                uplink_live={},
                wan_share={"ok": True, "shares": []},
                smart_balance_status={
                    "ok": True,
                    "slow_ports": [],
                    "members": {"ether1": "ok", "ether2": "slow"},
                },
                primary_wan_ports=["ether1"],
                backup_wan_ports=["ether2"],
                usage={"ok": True, "ip_usage": {}, "sessions": {}},
            )
        self.assertEqual(analysis["isps"][1]["status"], "slow")
        self.assertEqual(analysis["isps"][0]["status"], "active")

    def test_build_router_client_analysis_groups_lan_port_usage(self):
        router = MikroTikRouter(
            name="edge",
            host="10.0.0.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.SINGLE,
            uplink_ports=["ether1"],
            wan_interface="ether1",
            port_roles={
                "ether1": MikroTikRouter.PortRole.WAN,
                "ether3": MikroTikRouter.PortRole.LAN,
            },
        )
        customer = MagicMock()
        customer.pk = 9
        customer.full_name = "Port Client"
        customer.account_number = "ACC-9"
        customer.pppoe_username = "portuser"
        customer.hotspot_mac = None
        customer.cpe_ip = ""
        customer.cpe_mac = ""
        customer.service_type = "pppoe"
        customer.status = "active"

        usage = {
            "ok": True,
            "uses_connection_marks": False,
            "default_isp_port": "ether1",
            "ip_usage": {
                "10.10.0.9": {
                    "isp_port": "ether1",
                    "connections": 2,
                    "source": "default_wan",
                    "lan_port": "ether3",
                    "download_bps": 2_000_000,
                    "upload_bps": 500_000,
                    "download_label": "2.00 Mbps",
                    "upload_label": "500.0 Kbps",
                    "bytes_in": 1000,
                    "bytes_out": 9000,
                    "uptime": "1h",
                }
            },
            "sessions": {
                "10.10.0.9": {
                    "pppoe_username": "portuser",
                    "source": "pppoe",
                    "lan_port": "ether3",
                },
            },
        }
        with patch("billing.models.Customer.objects") as customer_qs:
            customer_qs.filter.return_value.only.return_value = [customer]
            analysis = _build_router_client_analysis(
                router,
                uplink_mode=MikroTikRouter.UplinkMode.SINGLE,
                uplink_live={},
                wan_share={
                    "ok": True,
                    "shares": [
                        {
                            "name": "ether1",
                            "pct": 100,
                            "rate_label": "12 Mbps",
                            "download_bps": 12_000_000,
                            "upload_bps": 1_000_000,
                            "download_label": "12 Mbps",
                            "upload_label": "1 Mbps",
                        }
                    ],
                },
                smart_balance_status={},
                primary_wan_ports=["ether1"],
                backup_wan_ports=[],
                usage=usage,
            )

        self.assertEqual(analysis["summary"]["online_clients"], 1)
        self.assertEqual(analysis["summary"]["download_label"], "2.00 Mbps")
        lan = next(p for p in analysis["lan_ports"] if p["port"] == "ether3")
        self.assertEqual(lan["online_clients"], 1)
        self.assertEqual(lan["clients"][0]["name"], "Port Client")
        self.assertEqual(lan["clients"][0]["lan_port"], "ether3")
        self.assertEqual(analysis["clients"][0]["data_label"], "9.8 KB")
        self.assertEqual(analysis["clients"][0]["isp_label"], "ISP 1 · ether1")

    def test_single_wan_fills_isp_and_strips_wan_as_cable(self):
        """Single internet: ISP column filled; WAN must not appear as cable port."""
        router = MikroTikRouter(
            name="edge",
            host="10.0.0.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.SINGLE,
            uplink_ports=[],
            wan_interface="ether1",
            port_roles={
                "ether1": MikroTikRouter.PortRole.WAN,
                "ether3": MikroTikRouter.PortRole.LAN,
            },
        )
        customer = MagicMock()
        customer.pk = 11
        customer.full_name = "Single WAN Client"
        customer.account_number = "ACC-11"
        customer.pppoe_username = "tint"
        customer.hotspot_mac = None
        customer.cpe_ip = ""
        customer.cpe_mac = ""
        customer.service_type = "pppoe"
        customer.status = "active"

        usage = {
            "ok": True,
            "uses_connection_marks": False,
            "default_isp_port": "",
            "ip_usage": {},
            "sessions": {
                "10.20.0.228": {
                    "pppoe_username": "tint",
                    "source": "pppoe",
                    "lan_port": "ether1",
                    "bytes_in": 1000,
                    "bytes_out": 5000,
                    "download_bps": 800_000,
                    "upload_bps": 100_000,
                    "download_label": "800.0 Kbps",
                    "upload_label": "100.0 Kbps",
                    "uptime": "2h3m",
                },
            },
        }
        with patch("billing.models.Customer.objects") as customer_qs:
            customer_qs.filter.return_value.only.return_value = [customer]
            analysis = _build_router_client_analysis(
                router,
                uplink_mode=MikroTikRouter.UplinkMode.SINGLE,
                uplink_live={},
                wan_share={"ok": True, "shares": []},
                smart_balance_status={},
                primary_wan_ports=["ether1"],
                backup_wan_ports=[],
                usage=usage,
            )

        client = analysis["clients"][0]
        self.assertTrue(client["online"])
        self.assertEqual(client["isp_port"], "ether1")
        self.assertEqual(client["isp_label"], "ISP 1 · ether1")
        self.assertEqual(client["lan_port"], "")
        self.assertEqual(client["download_label"], "800.0 Kbps")
        self.assertEqual(client["upload_label"], "100.0 Kbps")
        self.assertEqual(client["uptime"], "2h3m")
        self.assertEqual(analysis["isps"][0]["online_clients"], 1)
        self.assertFalse(any(p["port"] == "ether1" for p in analysis["lan_ports"]))

    def test_sanitize_lan_cable_port_drops_wan_and_pppoe(self):
        from core.mikrotik_connect import (
            _pppoe_dynamic_iface_name,
            _sanitize_lan_cable_port,
        )

        exclude = {"ether1"}
        self.assertEqual(_sanitize_lan_cable_port("ether3", exclude_ports=exclude), "ether3")
        self.assertEqual(_sanitize_lan_cable_port("ether1", exclude_ports=exclude), "")
        self.assertEqual(_sanitize_lan_cable_port("<pppoe-tint>", exclude_ports=set()), "")
        by_iface = {"<pppoe-+2547>": {"name": "<pppoe-+2547>"}}
        self.assertEqual(
            _pppoe_dynamic_iface_name("2547", by_iface, list(by_iface.values())),
            "<pppoe-+2547>",
        )


class ClientBalanceInsightsTests(SimpleTestCase):
    def test_balance_insights_ready_to_auto_enable(self):
        from core.views import _build_client_balance_insights

        router = MikroTikRouter(
            name="edge",
            host="10.0.0.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_ports=["ether1", "ether2"],
        )
        analysis = {
            "ok": True,
            "uses_connection_marks": False,
            "isps": [{"port": "ether1"}, {"port": "ether2"}],
            "clients": [
                {"online": True, "isp_port": "ether1"},
                {"online": True, "isp_port": "ether1"},
            ],
            "unmapped_clients": [],
        }
        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", uplink_kind="dhcp"),
        ]
        insights = _build_client_balance_insights(
            router,
            analysis,
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            physical_ports=ports,
            balance_ready=True,
            balance_router_applied=False,
            smart_balance_applied=False,
        )
        self.assertTrue(insights["can_auto_enable"])
        self.assertEqual(insights["dominant_isp"], "ether1")
        self.assertEqual(insights["online_by_isp"]["ether1"], 2)
        self.assertIn("smart balance", insights["recommendation"].lower())

    def test_balance_insights_applied_with_marks(self):
        from core.views import _build_client_balance_insights

        router = MikroTikRouter(
            name="edge",
            host="10.0.0.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_ports=["ether1", "ether2"],
        )
        analysis = {
            "ok": True,
            "uses_connection_marks": True,
            "isps": [{"port": "ether1"}, {"port": "ether2"}],
            "clients": [
                {"online": True, "isp_port": "ether1"},
                {"online": True, "isp_port": "ether2"},
            ],
            "unmapped_clients": [],
        }
        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", uplink_kind="dhcp"),
        ]
        insights = _build_client_balance_insights(
            router,
            analysis,
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            physical_ports=ports,
            balance_ready=True,
            balance_router_applied=True,
            smart_balance_applied=True,
        )
        self.assertTrue(insights["applied"])
        self.assertFalse(insights["can_auto_enable"])

    def test_balance_insights_bond_mode_can_auto_enable(self):
        from core.views import _build_client_balance_insights

        router = MikroTikRouter(
            name="edge",
            host="10.0.0.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.BOND,
            uplink_ports=["ether1", "ether2"],
        )
        analysis = {
            "ok": True,
            "uses_connection_marks": False,
            "isps": [{"port": "ether1"}, {"port": "ether2"}],
            "clients": [],
            "unmapped_clients": [],
        }
        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True),
            _port("ether2", uplink_kind="dhcp", uplink_active=True),
        ]
        insights = _build_client_balance_insights(
            router,
            analysis,
            uplink_mode=MikroTikRouter.UplinkMode.BOND,
            physical_ports=ports,
            balance_ready=False,
            balance_router_applied=False,
            smart_balance_applied=False,
        )
        self.assertTrue(insights["can_auto_enable"])


class AutomaticPortLabelTests(SimpleTestCase):
    def _router(self, **kwargs):
        router = MagicMock(spec=MikroTikRouter)
        router.pk = 6
        router.port_roles = kwargs.pop(
            "port_roles",
            {
                "ether1": MikroTikRouter.PortRole.WAN,
                "ether2": MikroTikRouter.PortRole.LAN,
            },
        )
        router.wan_interface = kwargs.pop("wan_interface", "ether1")
        router.uplink_mode = kwargs.pop(
            "uplink_mode", MikroTikRouter.UplinkMode.SINGLE
        )
        router.uplink_ports = kwargs.pop("uplink_ports", ["ether1"])
        router.uplink_weights = {}
        router.save = MagicMock()
        return router

    def test_single_wan_resyncs_when_isp_moves(self):
        from core.views import _auto_assign_single_wan_roles
        from django.core.cache import cache

        cache.clear()
        router = self._router()
        ports = [
            _port("ether1", running=False, uplink_kind="dhcp", uplink_active=False),
            _port(
                "ether4",
                bridged=True,
                running=True,
                uplink_kind="dhcp",
                uplink_active=True,
            ),
            _port("ether2", bridged=True, running=True),
            _port("wlan1", bridged=True, wireless=True, running=False, iface_type="wlan"),
        ]
        with patch("core.views._apply_single_wan_on_router") as apply_wan:
            apply_wan.return_value = {"ok": True, "skipped": True}
            # First three polls only debounce — no RouterOS push yet.
            for _ in range(3):
                result = _auto_assign_single_wan_roles(
                    router,
                    ports,
                    suggested_wan="ether4",
                    api_host="10.9.0.2",
                    apply_on_router=True,
                )
            self.assertFalse(apply_wan.called)
            self.assertEqual(result["wan"], "ether4")
            # Fourth stable poll applies once.
            result = _auto_assign_single_wan_roles(
                router,
                ports,
                suggested_wan="ether4",
                api_host="10.9.0.2",
                apply_on_router=True,
            )

        self.assertTrue(result["changed"])
        self.assertEqual(result["wan"], "ether4")
        self.assertEqual(router.port_roles["ether4"], MikroTikRouter.PortRole.WAN)
        self.assertEqual(router.port_roles["ether2"], MikroTikRouter.PortRole.LAN)
        self.assertEqual(router.port_roles["wlan1"], MikroTikRouter.PortRole.LAN)
        apply_wan.assert_called_once()

    def test_sticky_wan_ignores_flapping_suggested_port(self):
        from core.views import _auto_assign_single_wan_roles
        from django.core.cache import cache

        cache.clear()
        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True),
            _port(
                "ether4",
                bridged=True,
                running=True,
                uplink_kind="dhcp",
                uplink_active=True,
            ),
            _port("ether2", bridged=True, running=True),
        ]
        router = self._router(
            port_roles={
                "ether1": MikroTikRouter.PortRole.WAN,
                "ether2": MikroTikRouter.PortRole.LAN,
                "ether4": MikroTikRouter.PortRole.LAN,
            },
            wan_interface="ether1",
        )
        with patch("core.views._apply_single_wan_on_router") as apply_wan:
            result = _auto_assign_single_wan_roles(
                router,
                ports,
                suggested_wan="ether4",
                api_host="10.9.0.2",
                apply_on_router=True,
            )
        self.assertEqual(result["wan"], "ether1")
        self.assertTrue(result.get("sticky") or result["wan"] == "ether1")
        apply_wan.assert_not_called()
        self.assertEqual(router.port_roles["ether1"], MikroTikRouter.PortRole.WAN)

    def test_live_poll_apply_only_after_primary_outage(self):
        from core.views import _live_poll_should_apply_on_router

        router = self._router(
            port_roles={
                "ether1": MikroTikRouter.PortRole.WAN,
                "ether2": MikroTikRouter.PortRole.LAN,
            },
            wan_interface="ether1",
        )
        healthy = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True),
            _port("ether2", uplink_kind="dhcp", uplink_active=True),
        ]
        self.assertFalse(
            _live_poll_should_apply_on_router(
                router, healthy, suggested_wan="ether2"
            )
        )
        outage = [
            _port("ether1", running=False, uplink_kind="dhcp", uplink_active=False),
            _port("ether4", uplink_kind="dhcp", uplink_active=True),
        ]
        self.assertTrue(
            _live_poll_should_apply_on_router(
                router, outage, suggested_wan="ether4"
            )
        )

    def test_single_wan_no_change_when_already_synced(self):
        from core.views import _auto_assign_single_wan_roles

        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True),
            _port("ether2", bridged=True, running=True),
        ]
        router = self._router(
            port_roles=suggest_port_roles(ports, suggested_wan="ether1"),
            wan_interface="ether1",
        )
        result = _auto_assign_single_wan_roles(
            router, ports, suggested_wan="ether1", apply_on_router=False
        )
        self.assertFalse(result["changed"])
        self.assertEqual(result["wan"], "ether1")

    def test_fill_non_uplink_customer_roles(self):
        from core.views import _fill_non_uplink_customer_roles

        roles = {
            "ether1": MikroTikRouter.PortRole.WAN,
            "ether2": MikroTikRouter.PortRole.NONE,
        }
        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", bridged=True, running=True),
            _port("ether3", bridged=True, running=False),
        ]
        filled = _fill_non_uplink_customer_roles(
            roles, ports, uplink_names=["ether1"]
        )
        self.assertEqual(filled["ether2"], MikroTikRouter.PortRole.LAN)
        self.assertEqual(filled["ether3"], MikroTikRouter.PortRole.LAN)


class AntiFlapUplinkTests(SimpleTestCase):
    def test_smart_balance_skips_reapply_when_pcc_present(self):
        from core.views import _try_auto_apply_smart_balance
        from django.core.cache import cache

        cache.clear()
        router = MagicMock(spec=MikroTikRouter)
        router.pk = 9
        router.uplink_mode = MikroTikRouter.UplinkMode.SMART_BALANCE
        router.username = "admin"
        router.password = "x"
        router.uplink_weights = {}
        with patch("core.views.apply_mikrotik_uplink_balance") as apply_balance:
            with patch("core.views._router_tunnel_verified", return_value=True):
                result = _try_auto_apply_smart_balance(
                    router,
                    "10.9.0.2",
                    member_ports=["ether1", "ether2"],
                    member_weights={},
                    uplink_live={
                        "ok": True,
                        "mode": "balance",
                        "balance_pcc_rules": 4,
                        "smart_balance_enabled": False,
                    },
                    live_ports=[
                        _port("ether1", uplink_kind="dhcp"),
                        _port("ether2", uplink_kind="dhcp"),
                    ],
                )
        self.assertTrue(result.get("skipped"))
        self.assertEqual(result.get("reason"), "pcc_already_present")
        apply_balance.assert_not_called()

    def test_smart_balance_success_sets_long_cooldown(self):
        from core.views import (
            _smart_balance_auto_cache_key,
            _try_auto_apply_smart_balance,
        )
        from django.core.cache import cache

        cache.clear()
        router = MagicMock(spec=MikroTikRouter)
        router.pk = 11
        router.uplink_mode = MikroTikRouter.UplinkMode.SMART_BALANCE
        router.username = "admin"
        router.password = "x"
        router.uplink_weights = {}
        router.organization_id = 1
        router.save = MagicMock()
        with (
            patch("core.views._router_tunnel_verified", return_value=True),
            patch("core.views.active_uplink_apply_job", return_value=False),
            patch("core.views._router_api_host", return_value="10.9.0.2"),
            patch(
                "core.views._guard_touch_ports_internet",
                return_value=(True, ""),
            ),
            patch(
                "core.views._reject_behind_provider_unbridge",
                return_value=None,
            ),
            patch(
                "core.views.apply_mikrotik_uplink_balance",
                return_value={
                    "ok": True,
                    "ports": ["ether1", "ether2"],
                    "weights": {"ether1": 100, "ether2": 100},
                    "wan_interface": "ether1",
                    "unbridged": [],
                    "message": "ok",
                },
            ),
            patch(
                "core.views._finalize_uplink_apply_result",
                side_effect=lambda router, result: result,
            ),
            patch(
                "core.views._sync_roles_for_uplink",
                return_value={},
            ),
            patch(
                "core.views.schedule_mikrotik_job",
                side_effect=lambda target, **kwargs: target(),
            ),
            patch(
                "core.views.MikroTikRouter.objects.get",
                return_value=router,
            ),
        ):
            first = _try_auto_apply_smart_balance(
                router,
                "10.9.0.2",
                member_ports=["ether1", "ether2"],
                member_weights={},
                uplink_live={
                    "ok": True,
                    "mode": "",
                    "balance_pcc_rules": 0,
                    "smart_balance_enabled": False,
                },
                live_ports=[
                    _port("ether1", uplink_kind="dhcp"),
                    _port("ether2", uplink_kind="dhcp"),
                ],
            )
            second = _try_auto_apply_smart_balance(
                router,
                "10.9.0.2",
                member_ports=["ether1", "ether2"],
                member_weights={},
                uplink_live={
                    "ok": True,
                    "mode": "",
                    "balance_pcc_rules": 0,
                    "smart_balance_enabled": False,
                },
                live_ports=[
                    _port("ether1", uplink_kind="dhcp"),
                    _port("ether2", uplink_kind="dhcp"),
                ],
            )
        self.assertTrue(first.get("ok"))
        self.assertTrue(first.get("scheduled") or first.get("auto_applied"))
        self.assertTrue(second.get("skipped"))
        self.assertEqual(cache.get(_smart_balance_auto_cache_key(11)), "applied")


class SimplifiedUplinkGoalTests(SimpleTestCase):
    def test_multi_goal_maps_to_smart_balance(self):
        from core.views import (
            UPLINK_UI_GOAL_MULTI,
            _normalize_uplink_goal,
            _ui_uplink_goal,
            _ui_uplink_goal_label,
        )

        self.assertEqual(
            _normalize_uplink_goal(UPLINK_UI_GOAL_MULTI),
            MikroTikRouter.UplinkMode.SMART_BALANCE,
        )
        self.assertEqual(
            _ui_uplink_goal(MikroTikRouter.UplinkMode.FAILOVER),
            UPLINK_UI_GOAL_MULTI,
        )
        self.assertEqual(
            _ui_uplink_goal(MikroTikRouter.UplinkMode.BALANCE),
            UPLINK_UI_GOAL_MULTI,
        )
        self.assertEqual(
            _ui_uplink_goal(MikroTikRouter.UplinkMode.SMART_BALANCE),
            UPLINK_UI_GOAL_MULTI,
        )
        self.assertEqual(_ui_uplink_goal(MikroTikRouter.UplinkMode.SINGLE), "single")
        self.assertEqual(_ui_uplink_goal(MikroTikRouter.UplinkMode.BOND), "bond")
        self.assertIn("failover", _ui_uplink_goal_label(MikroTikRouter.UplinkMode.SMART_BALANCE).lower())

    def test_setup_status_warns_when_multi_link_incomplete(self):
        from core.views import _build_uplink_setup_status

        status = _build_uplink_setup_status(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            primary_wan_ports=["ether1"],
            backup_wan_ports=[],
            bond_member_ports=[],
            physical_ports=[_port("ether1", uplink_kind="dhcp")],
            dual_wan_ready=False,
            bond_ready=False,
            balance_ready=False,
            balance_router_applied=False,
            smart_balance_applied=False,
            uplink_live={},
            health_alerts=[],
        )
        self.assertTrue(status["applies"])
        self.assertFalse(status["can_proceed"])
        self.assertFalse(status["ok"])
        self.assertEqual(status["level"], "warn")
        self.assertTrue(status["problems"])

    def test_setup_status_ok_when_multi_applied_and_healthy(self):
        from core.views import _build_uplink_setup_status

        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", uplink_kind="dhcp"),
        ]
        status = _build_uplink_setup_status(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=ports,
            dual_wan_ready=True,
            bond_ready=False,
            balance_ready=True,
            balance_router_applied=True,
            smart_balance_applied=True,
            uplink_live={"ok": True, "mode": "smart_balance"},
            health_alerts=[],
        )
        self.assertTrue(status["ok"])
        self.assertTrue(status["can_proceed"])
        self.assertTrue(status["applied"])
        self.assertIn("proceed", status["message"].lower())

    def test_failover_alert_applies_to_smart_balance(self):
        alerts = _build_uplink_health_alerts(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_live={
                "ok": True,
                "mode": "smart_balance",
                "balance_pcc_rules": 4,
            },
            wan_share={},
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=[
                _port("ether1", running=False, uplink_kind="dhcp"),
                _port("ether2", running=True, uplink_kind="dhcp"),
            ],
            uplink_weights={},
            balance_router_applied=True,
            smart_balance_applied=True,
        )
        codes = [a["code"] for a in alerts]
        self.assertIn("failover_on_backup", codes)
        msg = next(a for a in alerts if a["code"] == "failover_on_backup")
        self.assertIn("Customers stay online", msg.get("message", ""))
        self.assertIn("ether1", msg.get("message", ""))

    def test_setup_status_ignores_failover_banner_alert(self):
        from core.views import _build_uplink_setup_status

        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", uplink_kind="dhcp"),
        ]
        alert = {
            "level": "warn",
            "code": "failover_on_backup",
            "message": (
                "ether1 failed gateway health checks. Customers stay online — "
                "traffic returns to ether1 (Internet) when ether1 passes "
                "gateway health checks again."
            ),
        }
        status = _build_uplink_setup_status(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=ports,
            dual_wan_ready=True,
            bond_ready=False,
            balance_ready=True,
            balance_router_applied=True,
            smart_balance_applied=True,
            uplink_live={"ok": True, "mode": "smart_balance"},
            health_alerts=[alert],
        )
        self.assertTrue(status["ok"])
        self.assertTrue(status["applied"])
        self.assertEqual(status["level"], "ok")
        self.assertNotIn("gateway health checks", " ".join(status.get("problems") or []))


class UplinkRecommendationTests(SimpleTestCase):
    def _router(self, **kwargs):
        router = MikroTikRouter(
            name="test",
            host="192.168.88.1",
            username="admin",
            password="x",
            wan_interface=kwargs.pop("wan_interface", ""),
            uplink_mode=kwargs.pop(
                "uplink_mode", MikroTikRouter.UplinkMode.SMART_BALANCE
            ),
            port_roles=kwargs.pop("port_roles", {}),
            uplink_ports=kwargs.pop("uplink_ports", []),
        )
        for key, value in kwargs.items():
            setattr(router, key, value)
        return router

    def test_ranks_verified_isp_above_link_up(self):
        from core.views import _list_uplink_candidates

        ports = [
            _port("ether2", running=True, uplink_kind=""),
            _port("ether1", running=True, uplink_kind="dhcp", uplink_active=True),
        ]
        ranked = _list_uplink_candidates(ports, suggested_wan="ether1")
        self.assertEqual(ranked[0]["name"], "ether1")
        self.assertTrue(ranked[0]["verified"])
        self.assertEqual(ranked[0]["status"], "isp_online")
        ether2 = next(c for c in ranked if c["name"] == "ether2")
        self.assertEqual(ether2["status"], "link_up")
        self.assertFalse(ether2["verified"])

    def test_multi_waits_when_second_link_not_verified(self):
        from core.views import _build_uplink_recommendation

        router = self._router(
            wan_interface="ether1",
            port_roles={"ether1": MikroTikRouter.PortRole.WAN},
        )
        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True),
            _port("ether2", running=True, uplink_kind=""),
        ]
        rec = _build_uplink_recommendation(
            router,
            ports,
            suggested_wan="ether1",
            balance_ready=False,
        )
        self.assertEqual(rec["phase"], "waiting")
        self.assertFalse(rec["can_accept"])
        self.assertIn("ether2", rec["waiting_ports"])
        self.assertTrue(
            "wait" in rec["message"].lower() or "linked" in rec["message"].lower()
        )

    def test_multi_recommends_two_verified_links(self):
        from core.views import _build_uplink_recommendation

        router = self._router(port_roles={})
        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True),
            _port("ether2", uplink_kind="pppoe", uplink_active=True),
        ]
        rec = _build_uplink_recommendation(
            router,
            ports,
            suggested_wan="ether1",
            balance_ready=False,
        )
        self.assertEqual(rec["phase"], "recommend")
        self.assertTrue(rec["can_accept"])
        self.assertEqual(rec["primary"], "ether1")
        self.assertEqual(rec["backups"], ["ether2"])

    def test_bond_recommendation_hides_when_applied(self):
        from core.views import _build_uplink_recommendation

        router = self._router(
            uplink_mode=MikroTikRouter.UplinkMode.BOND,
            bond_interface="bond-wan",
            port_roles={
                "ether1": MikroTikRouter.PortRole.BOND,
                "ether2": MikroTikRouter.PortRole.BOND,
            },
            uplink_ports=["ether1", "ether2"],
        )
        ports = [
            _port("ether1", running=True),
            _port("ether2", running=True),
        ]
        rec = _build_uplink_recommendation(
            router,
            ports,
            bond_ready=True,
            bond_router_applied=True,
        )
        self.assertEqual(rec["phase"], "applied")
        self.assertFalse(rec["can_accept"])
        self.assertTrue(rec["can_proceed"])
        self.assertIn("bond-wan", rec["message"])

    def test_bond_router_applied_requires_matching_slaves(self):
        from core.views import _bond_router_applied

        self.assertFalse(
            _bond_router_applied(
                MikroTikRouter.UplinkMode.BOND,
                {
                    "ok": True,
                    "bonds": [
                        {
                            "name": "bond-wan",
                            "running": True,
                            "disabled": False,
                            "slaves": ["ether1", "ether3"],
                        }
                    ],
                },
                bond_member_ports=["ether1", "ether2"],
                bond_interface="bond-wan",
            )
        )
        self.assertTrue(
            _bond_router_applied(
                MikroTikRouter.UplinkMode.BOND,
                {
                    "ok": True,
                    "bonds": [
                        {
                            "name": "bond-wan",
                            "running": True,
                            "disabled": False,
                            "slaves": ["ether1", "ether2"],
                        }
                    ],
                },
                bond_member_ports=["ether1", "ether2"],
                bond_interface="bond-wan",
            )
        )

    def test_accept_multi_recommendation_labels_roles(self):
        from core.views import apply_uplink_recommendation

        router = self._router(port_roles={})
        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True),
            _port("ether2", uplink_kind="dhcp", uplink_active=True),
            _port("ether3", bridged=True, running=True),
        ]
        with patch.object(MikroTikRouter, "save"):
            result = apply_uplink_recommendation(
                router, ports, suggested_wan="ether1"
            )
        self.assertTrue(result["ok"])
        self.assertEqual(router.port_roles.get("ether1"), MikroTikRouter.PortRole.WAN)
        self.assertEqual(
            router.port_roles.get("ether2"), MikroTikRouter.PortRole.WAN_BACKUP
        )

    def test_auto_assign_keeps_unverified_shared_isp(self):
        from core.views import _auto_assign_multi_isp_roles

        router = self._router(
            wan_interface="ether1",
            port_roles={
                "ether1": MikroTikRouter.PortRole.WAN,
                "ether2": MikroTikRouter.PortRole.WAN_BACKUP,
            },
            uplink_ports=["ether1", "ether2"],
        )
        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True),
            _port("ether2", running=True, uplink_kind=""),
        ]
        with patch.object(MikroTikRouter, "save"):
            result = _auto_assign_multi_isp_roles(
                router,
                ports,
                mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
                suggested_wan="ether1",
            )
        self.assertFalse(result.get("changed"))
        self.assertEqual(
            router.port_roles.get("ether2"), MikroTikRouter.PortRole.WAN_BACKUP
        )

    def test_auto_assign_soft_labels_waiting_shared_isp(self):
        from core.views import _auto_assign_multi_isp_roles

        router = self._router(
            wan_interface="ether1",
            port_roles={"ether1": MikroTikRouter.PortRole.WAN},
            uplink_ports=["ether1"],
        )
        ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True),
            _port("ether2", running=True, uplink_kind=""),
        ]
        with patch.object(MikroTikRouter, "save"):
            result = _auto_assign_multi_isp_roles(
                router,
                ports,
                mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
                suggested_wan="ether1",
            )
        self.assertTrue(result.get("ok"))
        self.assertTrue(result.get("changed"))
        self.assertEqual(result.get("primary"), "ether1")
        self.assertEqual(result.get("backups"), ["ether2"])
        self.assertEqual(
            router.port_roles.get("ether2"), MikroTikRouter.PortRole.WAN_BACKUP
        )

    def test_setup_status_title_ready_to_apply(self):
        from core.views import _build_uplink_setup_status

        ports = [
            _port("ether1", uplink_kind="dhcp"),
            _port("ether2", uplink_kind="dhcp"),
        ]
        status = _build_uplink_setup_status(
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            primary_wan_ports=["ether1"],
            backup_wan_ports=["ether2"],
            bond_member_ports=[],
            physical_ports=ports,
            dual_wan_ready=True,
            bond_ready=False,
            balance_ready=True,
            balance_router_applied=False,
            smart_balance_applied=False,
            uplink_live={},
            health_alerts=[],
            recommendation={
                "title": "Ready to apply multi-ISP",
                "message": "Apply now",
                "waiting_ports": [],
            },
        )
        self.assertEqual(status["title"], "Ready to apply")
        self.assertEqual(status["phase"], "ready_to_apply")
        self.assertTrue(status["can_proceed"])


class UplinkJobStaleMessageTests(SimpleTestCase):
    def test_bond_stale_message_is_not_billing_push(self):
        from core.mikrotik_jobs import stale_error_for_job, stale_max_age_for_job

        err, hint = stale_error_for_job("uplink_bond")
        self.assertIn("Bond", err)
        self.assertNotIn("Billing settings push", err)
        self.assertTrue(hint)
        self.assertGreaterEqual(stale_max_age_for_job("uplink_bond"), 600)

    def test_multi_isp_stale_message_is_specific(self):
        from core.mikrotik_jobs import stale_error_for_job

        err, _hint = stale_error_for_job("uplink_smart_balance")
        self.assertIn("Multi-ISP", err)
        self.assertNotIn("Billing settings push", err)
        err2, _ = stale_error_for_job("uplink_failover")
        self.assertIn("Failover", err2)


class HotMultiUplinkApplySimulationTests(SimpleTestCase):
    """Dummy RouterOS simulation: rebuild policy without tearing down DHCP clients."""

    def test_clear_routing_policy_keeps_dhcp_clients(self):
        from core.mikrotik_connect import _clear_tagged_routing_policy

        removed: list[tuple[str, str]] = []

        def fake_print(sock, path, props=""):
            if path == "/ip/route":
                return [{".id": "*r1", "comment": UPLINK_TAG, "dst-address": "0.0.0.0/0"}]
            if path == "/ip/firewall/mangle":
                return [{".id": "*m1", "comment": UPLINK_TAG}]
            if path == "/routing/table":
                return [{".id": "*t1", "name": "ispcentric-w0", "comment": UPLINK_TAG}]
            if path == "/system/script":
                return [{".id": "*s1", "comment": UPLINK_TAG}]
            if path == "/system/scheduler":
                return [{".id": "*h1", "comment": UPLINK_TAG}]
            if path == "/ip/dhcp-client":
                return [{".id": "*d1", "comment": UPLINK_TAG, "interface": "ether1"}]
            return []

        def fake_remove(sock, path, item_id):
            removed.append((path, item_id))
            return {"_reply": "!done"}

        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._remove", side_effect=fake_remove),
        ):
            result = _clear_tagged_routing_policy(object())

        self.assertGreaterEqual(result.get("routes", 0), 1)
        self.assertGreaterEqual(result.get("mangle", 0), 1)
        self.assertFalse(any(path == "/ip/dhcp-client" for path, _ in removed))

    def test_balance_apply_clears_policy_before_pcc(self):
        from core.mikrotik_connect import apply_mikrotik_uplink_balance

        calls: list[str] = []

        @contextmanager
        def fake_session(*args, **kwargs):
            calls.append("session")
            yield (object(), "10.9.0.2")

        def fake_phase1(*args, **kwargs):
            return [], None

        def fake_ensure(sock, iface, distance=1, add_default_route=False):
            return {
                "_reply": "!done",
                "_interface": iface,
                "_kind": "dhcp",
                "_pppoe": "",
            }

        def fake_gateway(sock, *, interface, kind, pppoe_name, gateway_hint=""):
            return interface, f"1.1.1.{interface[-1]}"

        def fake_clear(sock):
            calls.append("clear_policy")
            return {"routes": 1, "mangle": 1, "routing_tables": 1, "scripts": 0, "schedulers": 0}

        def fake_pcc(sock, members):
            calls.append("install_pcc")
            self.assertEqual(len(members), 2)
            return {
                "ok": True,
                "members": [m["interface"] for m in members],
                "slot_counts": [1, 1],
                "preferred": members[0]["interface"],
                "mangle_rules": 4,
            }

        with (
            patch(
                "core.mikrotik_connect._api_hosts_for_uplink_apply",
                return_value=["10.9.0.2"],
            ),
            patch(
                "core.mikrotik_connect._phase1_prepare_uplink_ports",
                side_effect=fake_phase1,
            ),
            patch(
                "core.mikrotik_connect._api_session_on_any",
                side_effect=fake_session,
            ),
            patch(
                "core.mikrotik_connect._extract_balance_gateway_hints",
                return_value={},
            ),
            patch(
                "core.mikrotik_connect._ensure_failover_uplink",
                side_effect=fake_ensure,
            ),
            patch("core.mikrotik_connect._ensure_uplink_list_member"),
            patch(
                "core.mikrotik_connect._find_pppoe_client_for_wan",
                return_value="",
            ),
            patch("core.mikrotik_connect.time.sleep"),
            patch(
                "core.mikrotik_connect._resolve_balance_member_gateway",
                side_effect=fake_gateway,
            ),
            patch("core.mikrotik_connect._disable_client_default_route"),
            patch(
                "core.mikrotik_connect._clear_tagged_routing_policy",
                side_effect=fake_clear,
            ),
            patch(
                "core.mikrotik_connect._install_balance_pcc",
                side_effect=fake_pcc,
            ),
            patch(
                "core.mikrotik_connect._install_smart_balance_monitor",
                return_value={"ok": True},
            ),
            patch(
                "core.mikrotik_connect.read_smart_balance_status",
                return_value={"ok": True, "slow_ports": [], "members": {}},
            ),
            patch(
                "core.mikrotik_connect._ensure_uplink_no_backflow",
                return_value={"ok": True, "changed": True},
            ),
        ):
            result = apply_mikrotik_uplink_balance(
                "10.9.0.2",
                "admin",
                "x",
                member_ports=["ether1", "ether2"],
                member_weights={"ether1": 100, "ether2": 50},
                smart_balance=True,
            )

        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("mode"), "smart_balance")
        self.assertIn("clear_policy", calls)
        self.assertIn("install_pcc", calls)
        self.assertLess(calls.index("clear_policy"), calls.index("install_pcc"))


class NoDropUplinkSimulationTests(SimpleTestCase):
    """Dummy simulations: bond + multi-ISP must not drop clients / management."""

    def test_phase1_preserves_dhcp_clients(self):
        from core.mikrotik_connect import _phase1_prepare_uplink_ports

        removed: list[tuple[str, str]] = []

        @contextmanager
        def fake_session(*args, **kwargs):
            yield (object(), "10.9.0.2")

        def fake_print(sock, path, props=""):
            if path == "/interface":
                return [
                    {"name": "ether1"},
                    {"name": "ether2"},
                    {"name": "bridgeLocal"},
                ]
            if path == "/ip/dhcp-client":
                return [
                    {
                        ".id": "*d1",
                        "interface": "ether1",
                        "comment": UPLINK_TAG,
                    }
                ]
            if path == "/interface/bridge/port":
                return [
                    {".id": "*b1", "interface": "ether1", "bridge": "bridgeLocal"},
                    {".id": "*b2", "interface": "ether2", "bridge": "bridgeLocal"},
                ]
            if path in {
                "/ip/route",
                "/ip/firewall/mangle",
                "/routing/table",
                "/system/script",
                "/system/scheduler",
                "/interface/bonding",
                "/interface/list/member",
            }:
                return [{".id": "*x1", "comment": UPLINK_TAG, "name": "ispcentric-w0"}]
            return []

        def fake_remove(sock, path, item_id):
            removed.append((path, item_id))
            return {"_reply": "!done"}

        with (
            patch(
                "core.mikrotik_connect._api_session_on_any",
                side_effect=fake_session,
            ),
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._remove", side_effect=fake_remove),
            patch(
                "core.mikrotik_connect._iface_names",
                return_value={"ether1", "ether2", "bridgeLocal"},
            ),
        ):
            unbridged, err = _phase1_prepare_uplink_ports(
                ["10.9.0.2"], "admin", "x", ports=["ether1", "ether2"]
            )

        self.assertIsNone(err)
        self.assertEqual(len(unbridged), 2)
        self.assertFalse(any(path == "/ip/dhcp-client" for path, _ in removed))
        self.assertTrue(any(path == "/ip/route" for path, _ in removed))

    def test_failover_check_gateway_only_on_tagged_routes(self):
        from core.mikrotik_connect import apply_mikrotik_uplink_failover

        set_calls: list[dict] = []

        @contextmanager
        def fake_session(*args, **kwargs):
            yield (object(), "10.9.0.2")

        def fake_set(sock, path, item_id, **props):
            set_calls.append({"path": path, "id": item_id, **props})
            return {"_reply": "!done"}

        def fake_print(sock, path, props=""):
            if path == "/ip/route":
                return [
                    {
                        ".id": "*op",
                        "dst-address": "0.0.0.0/0",
                        "gateway": "9.9.9.9",
                        "dynamic": "false",
                        "comment": "operator-static",
                    },
                    {
                        ".id": "*tag",
                        "dst-address": "0.0.0.0/0",
                        "gateway": "1.1.1.1",
                        "dynamic": "false",
                        "comment": UPLINK_TAG,
                    },
                ]
            return []

        with (
            patch(
                "core.mikrotik_connect._api_hosts_for_uplink_apply",
                return_value=["10.9.0.2"],
            ),
            patch(
                "core.mikrotik_connect._phase1_prepare_uplink_ports",
                return_value=([], None),
            ),
            patch(
                "core.mikrotik_connect._api_session_on_any",
                side_effect=fake_session,
            ),
            patch("core.mikrotik_connect._clear_tagged_routing_policy"),
            patch(
                "core.mikrotik_connect._ensure_failover_uplink",
                side_effect=lambda sock, iface, distance=1, add_default_route=True: {
                    "_reply": "!done",
                    "_interface": iface,
                    "_kind": "dhcp",
                    "_pppoe": "",
                    "_distance": str(distance),
                },
            ),
            patch("core.mikrotik_connect._ensure_uplink_list_member"),
            patch(
                "core.mikrotik_connect._find_pppoe_client_for_wan",
                return_value="",
            ),
            patch(
                "core.mikrotik_connect._install_failover_gateway_checks",
                return_value=[{"gateway": "1.1.1.1"}],
            ),
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch("core.mikrotik_connect.time.sleep"),
            patch(
                "core.mikrotik_connect._ensure_uplink_no_backflow",
                return_value={"ok": True, "changed": True},
            ),
        ):
            result = apply_mikrotik_uplink_failover(
                "10.9.0.2",
                "admin",
                "x",
                primary_port="ether1",
                backup_ports=["ether2"],
            )

        self.assertTrue(result.get("ok"), result)
        tagged = [c for c in set_calls if c.get("id") == "*tag"]
        operator = [c for c in set_calls if c.get("id") == "*op"]
        self.assertTrue(tagged)
        self.assertFalse(operator)

    def test_behind_provider_blocks_bond_and_multi(self):
        from core.mikrotik_connect import (
            apply_mikrotik_uplink_balance,
            apply_mikrotik_uplink_bond,
            apply_mikrotik_uplink_failover,
        )

        live = [
            _port(
                "ether1",
                bridged=True,
                running=True,
                uplink_kind="dhcp",
                uplink_active=True,
                uplink_iface="bridgeLocal",
            ),
            _port(
                "ether2",
                bridged=True,
                running=True,
                uplink_kind="dhcp",
                uplink_active=True,
                uplink_iface="bridgeLocal",
            ),
        ]
        bond = apply_mikrotik_uplink_bond(
            "10.9.0.2",
            "admin",
            "x",
            member_ports=["ether1", "ether2"],
            live_ports=live,
        )
        multi = apply_mikrotik_uplink_balance(
            "10.9.0.2",
            "admin",
            "x",
            member_ports=["ether1", "ether2"],
            smart_balance=True,
            live_ports=live,
        )
        failover = apply_mikrotik_uplink_failover(
            "10.9.0.2",
            "admin",
            "x",
            primary_port="ether1",
            backup_ports=["ether2"],
            live_ports=live,
        )
        for result, label in (
            (bond, "bond"),
            (multi, "multi"),
            (failover, "failover"),
        ):
            self.assertFalse(result.get("ok"), label)
            self.assertTrue(result.get("skipped"), label)
            self.assertIn("behind-provider", (result.get("error") or "").lower())
            self.assertIn("dedicated WAN", result.get("error") or "")

    def test_balance_missing_gateway_restores_bridge(self):
        from core.mikrotik_connect import apply_mikrotik_uplink_balance

        restored: list = []

        @contextmanager
        def fake_session(*args, **kwargs):
            yield (object(), "10.9.0.2")

        with (
            patch(
                "core.mikrotik_connect._api_hosts_for_uplink_apply",
                return_value=["10.9.0.2"],
            ),
            patch(
                "core.mikrotik_connect._phase1_prepare_uplink_ports",
                return_value=(
                    [
                        {"interface": "ether1", "bridge": "bridgeLocal"},
                        {"interface": "ether2", "bridge": "bridgeLocal"},
                    ],
                    None,
                ),
            ),
            patch(
                "core.mikrotik_connect._api_session_on_any",
                side_effect=fake_session,
            ),
            patch(
                "core.mikrotik_connect._extract_balance_gateway_hints",
                return_value={},
            ),
            patch(
                "core.mikrotik_connect._ensure_failover_uplink",
                side_effect=lambda sock, iface, distance=1, add_default_route=False: {
                    "_reply": "!done",
                    "_interface": iface,
                    "_kind": "dhcp",
                    "_pppoe": "",
                },
            ),
            patch("core.mikrotik_connect._ensure_uplink_list_member"),
            patch(
                "core.mikrotik_connect._find_pppoe_client_for_wan",
                return_value="",
            ),
            patch("core.mikrotik_connect.time.sleep"),
            patch(
                "core.mikrotik_connect._wait_for_balance_member_gateways",
                return_value=({}, ["ether1", "ether2"]),
            ),
            patch(
                "core.mikrotik_connect._restore_bridged_interfaces",
                side_effect=lambda sock, entries, **kwargs: restored.extend(entries) or len(entries),
            ),
        ):
            result = apply_mikrotik_uplink_balance(
                "10.9.0.2",
                "admin",
                "x",
                member_ports=["ether1", "ether2"],
            )

        self.assertFalse(result.get("ok"))
        self.assertEqual(len(restored), 2)
        self.assertEqual(result.get("unbridged"), [])

    def test_bond_dhcp_failure_rolls_back(self):
        from core.mikrotik_connect import apply_mikrotik_uplink_bond

        restored: list = []
        removed_bonds: list[str] = []

        @contextmanager
        def fake_session(*args, **kwargs):
            yield (object(), "10.9.0.2")

        def fake_print(sock, path, props=""):
            if path == "/interface/bonding":
                return [
                    {
                        ".id": "*bond1",
                        "name": "bond-wan",
                        "comment": UPLINK_TAG,
                    }
                ]
            return []

        def fake_remove(sock, path, item_id):
            if path == "/interface/bonding":
                removed_bonds.append(item_id)
            return {"_reply": "!done"}

        with (
            patch(
                "core.mikrotik_connect._api_hosts_for_uplink_apply",
                return_value=["10.9.0.2"],
            ),
            patch(
                "core.mikrotik_connect._api_session_on_any",
                side_effect=fake_session,
            ),
            patch(
                "core.mikrotik_connect._iface_names",
                return_value={"ether1", "ether2"},
            ),
            patch("core.mikrotik_connect._clear_tagged_uplink_hot"),
            patch(
                "core.mikrotik_connect._unbridge_interfaces",
                return_value=[
                    {"interface": "ether1", "bridge": "bridgeLocal"},
                    {"interface": "ether2", "bridge": "bridgeLocal"},
                ],
            ),
            patch("core.mikrotik_connect.time.sleep"),
            patch(
                "core.mikrotik_connect._wait_for_api_any",
            ),
            patch(
                "core.mikrotik_connect._create_bonding_interface",
                return_value=({"_reply": "!done"}, "balance-xor"),
            ),
            patch(
                "core.mikrotik_connect._disable_member_dhcp_clients",
                return_value=["ether1", "ether2"],
            ),
            patch(
                "core.mikrotik_connect._move_member_pppoe_to_bond",
                return_value=[],
            ),
            patch(
                "core.mikrotik_connect._ensure_bond_dhcp_client",
                return_value={"_reply": "!trap", "message": "dhcp failed"},
            ),
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._remove", side_effect=fake_remove),
            patch(
                "core.mikrotik_connect._restore_bridged_interfaces",
                side_effect=lambda sock, entries, **kwargs: restored.extend(entries) or len(entries),
            ),
        ):
            result = apply_mikrotik_uplink_bond(
                "10.9.0.2",
                "admin",
                "x",
                member_ports=["ether1", "ether2"],
            )

        self.assertFalse(result.get("ok"))
        self.assertIn("*bond1", removed_bonds)
        self.assertEqual(len(restored), 2)
        self.assertEqual(result.get("unbridged"), [])


class BalanceGatewayLearningTests(SimpleTestCase):
    def test_infer_gateway_from_bound_dhcp_address(self):
        from core.mikrotik_connect import _infer_gateway_from_dhcp_row

        self.assertEqual(
            _infer_gateway_from_dhcp_row(
                {"status": "bound", "address": "192.168.8.42/24", "gateway": ""}
            ),
            "192.168.8.1",
        )
        self.assertEqual(
            _infer_gateway_from_dhcp_row(
                {"status": "bound", "gateway": "10.0.0.1%ether2"}
            ),
            "10.0.0.1",
        )
        self.assertEqual(
            _infer_gateway_from_dhcp_row({"status": "searching", "address": "10.0.0.2/24"}),
            "",
        )

    def test_resolve_balance_member_gateway_uses_hint(self):
        from core.mikrotik_connect import _resolve_balance_member_gateway

        with patch("core.mikrotik_connect._detect_dhcp_gateways", return_value=[]), patch(
            "core.mikrotik_connect._default_route_gateway_for_interface",
            return_value="",
        ), patch(
            "core.mikrotik_connect._connected_gateway_for_interface",
            return_value="",
        ):
            wan_iface, gateway = _resolve_balance_member_gateway(
                object(),
                interface="ether1",
                kind="dhcp",
                gateway_hint="192.168.1.1",
            )
        self.assertEqual(wan_iface, "ether1")
        self.assertEqual(gateway, "192.168.1.1")

    def test_wait_for_balance_member_gateways_polls_until_ready(self):
        from core.mikrotik_connect import _wait_for_balance_member_gateways

        uplink_results = [
            {"_interface": "ether1", "_kind": "dhcp", "_pppoe": ""},
            {"_interface": "ether2", "_kind": "dhcp", "_pppoe": ""},
        ]
        calls = {"n": 0}

        def fake_resolve(sock, *, interface, kind, pppoe_name="", gateway_hint=""):
            calls["n"] += 1
            if calls["n"] < 3:
                return interface, ""
            return interface, f"10.0.0.{interface[-1]}"

        with patch(
            "core.mikrotik_connect._resolve_balance_member_gateway",
            side_effect=fake_resolve,
        ), patch(
            "core.mikrotik_connect._renew_balance_member_dhcp",
        ), patch("core.mikrotik_connect.time.sleep"):
            resolved, missing = _wait_for_balance_member_gateways(
                object(),
                uplink_results,
                {"ether1": "10.0.0.1", "ether2": "10.0.0.2"},
                timeout=3.0,
                interval=0.01,
            )

        self.assertEqual(missing, [])
        self.assertEqual(resolved["ether1"][1], "10.0.0.1")
        self.assertEqual(resolved["ether2"][1], "10.0.0.2")


class ClientIspDistributionTests(SimpleTestCase):
    def test_equal_capacity_targets_even_split(self):
        plan = plan_client_isp_distribution(
            member_ports=["ether1", "ether2"],
            port_weights={},
            counts_by_port={"ether1": 3, "ether2": 1},
        )
        self.assertTrue(plan["imbalanced"])
        self.assertEqual(plan["targets"], {"ether1": 2, "ether2": 2})
        self.assertEqual(plan["moves_needed"], 1)

    def test_weighted_capacity_targets_proportional_split(self):
        plan = plan_client_isp_distribution(
            member_ports=["ether1", "ether2"],
            port_weights={"ether1": 100, "ether2": 20},
            counts_by_port={"ether1": 6, "ether2": 0},
        )
        self.assertTrue(plan["imbalanced"])
        self.assertEqual(plan["targets"], {"ether1": 5, "ether2": 1})
        self.assertEqual(plan["moves_needed"], 1)

    def test_balanced_within_tolerance_skips_rebalance(self):
        plan = plan_client_isp_distribution(
            member_ports=["ether1", "ether2"],
            port_weights={"ether1": 100, "ether2": 100},
            counts_by_port={"ether1": 2, "ether2": 2},
        )
        self.assertFalse(plan["imbalanced"])
        self.assertEqual(plan["moves_needed"], 0)

    def test_bandwidth_imbalance_even_when_counts_match(self):
        plan = plan_client_isp_distribution(
            member_ports=["ether1", "ether2"],
            port_weights={"ether1": 100, "ether2": 100},
            counts_by_port={"ether1": 2, "ether2": 2},
            bps_by_port={"ether1": 8_000_000, "ether2": 500_000},
        )
        self.assertTrue(plan["imbalanced"])
        self.assertEqual(plan["imbalance_reason"], "bandwidth")
        self.assertEqual(plan["overloaded_isp"], "ether1")
        self.assertEqual(plan["underloaded_isp"], "ether2")

    def test_detect_bandwidth_share_drift(self):
        drift = detect_bandwidth_share_drift(
            {
                "ok": True,
                "total_bps": 10_000_000,
                "shares": [
                    {"name": "ether1", "bps": 8_500_000, "pct": 85},
                    {"name": "ether2", "bps": 1_500_000, "pct": 15},
                ],
            },
            {"ether1": 100, "ether2": 100},
            threshold_pct=15,
            min_total_bps=500_000,
        )
        self.assertTrue(drift["drifted"])
        self.assertEqual(drift["overloaded_isp"], "ether1")
        self.assertEqual(drift["underloaded_isp"], "ether2")


class ClientIspSwitchTests(SimpleTestCase):
    def test_auto_rebalance_moves_one_client_off_dominant_isp(self):
        sock = object()
        clients = [
            {
                "customer_id": 1,
                "name": "Alice",
                "online": True,
                "ip": "10.10.0.1",
                "isp_port": "ether1",
                "connection_count": 3,
            },
            {
                "customer_id": 2,
                "name": "Bob",
                "online": True,
                "ip": "10.10.0.2",
                "isp_port": "ether1",
                "connection_count": 1,
            },
            {
                "customer_id": 3,
                "name": "Carol",
                "online": True,
                "ip": "10.10.0.3",
                "isp_port": "ether1",
                "connection_count": 1,
            },
            {
                "customer_id": 4,
                "name": "Dan",
                "online": True,
                "ip": "10.10.0.4",
                "isp_port": "ether2",
                "connection_count": 1,
            },
        ]
        with patch(
            "core.mikrotik_connect.switch_client_to_isp_port",
            return_value={"ok": True, "isp_port": "ether2"},
        ) as switch_mock:
            result = auto_rebalance_client_isps(
                sock,
                member_ports=["ether1", "ether2"],
                clients=clients,
                slow_ports=[],
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["dominant_isp"], "ether1")
        self.assertEqual(result["target_isp"], "ether2")
        switch_mock.assert_called_once()
        moved = result["moved"][0]
        self.assertEqual(moved["from_isp"], "ether1")
        self.assertEqual(moved["to_isp"], "ether2")

    def test_auto_rebalance_skips_when_balanced(self):
        clients = [
            {
                "customer_id": 1,
                "online": True,
                "ip": "10.10.0.1",
                "isp_port": "ether1",
            },
            {
                "customer_id": 2,
                "online": True,
                "ip": "10.10.0.2",
                "isp_port": "ether2",
            },
        ]
        result = auto_rebalance_client_isps(
            object(),
            member_ports=["ether1", "ether2"],
            clients=clients,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result.get("reason"), "already_balanced")

    def test_auto_rebalance_moves_multiple_when_heavily_skewed(self):
        sock = object()
        clients = [
            {
                "customer_id": i,
                "name": f"User{i}",
                "online": True,
                "ip": f"10.10.0.{i}",
                "isp_port": "ether1",
                "connection_count": 1,
            }
            for i in range(1, 7)
        ]
        with patch(
            "core.mikrotik_connect.switch_client_to_isp_port",
            return_value={"ok": True, "isp_port": "ether2"},
        ) as switch_mock:
            result = auto_rebalance_client_isps(
                sock,
                member_ports=["ether1", "ether2"],
                clients=clients,
                slow_ports=[],
                port_weights={"ether1": 100, "ether2": 100},
            )

        self.assertTrue(result["ok"])
        self.assertEqual(len(result["moved"]), 3)
        self.assertEqual(switch_mock.call_count, 3)
        self.assertEqual(result["target_isp"], "ether2")

    def test_auto_rebalance_prefers_idle_client_for_count_skew(self):
        sock = object()
        clients = [
            {
                "customer_id": 1,
                "name": "Light",
                "online": True,
                "ip": "10.10.0.1",
                "isp_port": "ether1",
                "download_bps": 20_000,
                "upload_bps": 5_000,
                "connection_count": 1,
            },
            {
                "customer_id": 2,
                "name": "Quiet",
                "online": True,
                "ip": "10.10.0.2",
                "isp_port": "ether1",
                "download_bps": 80_000,
                "upload_bps": 10_000,
                "connection_count": 1,
            },
            {
                "customer_id": 3,
                "name": "Calm",
                "online": True,
                "ip": "10.10.0.3",
                "isp_port": "ether1",
                "download_bps": 40_000,
                "upload_bps": 5_000,
                "connection_count": 1,
            },
            {
                "customer_id": 4,
                "name": "Other",
                "online": True,
                "ip": "10.10.0.4",
                "isp_port": "ether2",
                "download_bps": 50_000,
                "upload_bps": 10_000,
                "connection_count": 1,
            },
        ]
        with patch(
            "core.mikrotik_connect.switch_client_to_isp_port",
            return_value={"ok": True, "isp_port": "ether2"},
        ) as switch_mock:
            auto_rebalance_client_isps(
                sock,
                member_ports=["ether1", "ether2"],
                clients=clients,
                port_weights={"ether1": 100, "ether2": 100},
            )
        self.assertEqual(switch_mock.call_args.kwargs["client_ip"], "10.10.0.1")
        self.assertTrue(switch_mock.call_args.kwargs.get("seamless"))

    def test_auto_rebalance_prefers_heavy_client_for_bandwidth_skew(self):
        sock = object()
        clients = [
            {
                "customer_id": 1,
                "name": "Light",
                "online": True,
                "ip": "10.10.0.1",
                "isp_port": "ether1",
                "download_bps": 100_000,
                "upload_bps": 0,
            },
            {
                "customer_id": 2,
                "name": "Heavy",
                "online": True,
                "ip": "10.10.0.2",
                "isp_port": "ether1",
                "download_bps": 8_000_000,
                "upload_bps": 0,
            },
            {
                "customer_id": 3,
                "name": "Other",
                "online": True,
                "ip": "10.10.0.3",
                "isp_port": "ether2",
                "download_bps": 100_000,
                "upload_bps": 0,
            },
        ]
        with patch(
            "core.mikrotik_connect.switch_client_to_isp_port",
            return_value={"ok": True, "isp_port": "ether2"},
        ) as switch_mock:
            auto_rebalance_client_isps(
                sock,
                member_ports=["ether1", "ether2"],
                clients=clients,
                port_weights={"ether1": 100, "ether2": 100},
            )
        self.assertEqual(switch_mock.call_args.kwargs["client_ip"], "10.10.0.2")

    def test_pin_client_seamless_skips_connection_kill(self):
        sock = object()
        with patch("core.mikrotik_connect._remove_client_isp_pins"), patch(
            "core.mikrotik_connect._add",
            return_value={"_reply": "ok"},
        ), patch(
            "core.mikrotik_connect._kill_firewall_connections_for_addresses",
        ) as kill_mock:
            result = pin_client_to_isp_mark(
                sock,
                client_ip="10.10.0.5",
                mark_index=1,
                customer_id=9,
                seamless=True,
            )
        self.assertTrue(result["ok"])
        self.assertTrue(result["seamless"])
        self.assertEqual(result["connections_cleared"], 0)
        kill_mock.assert_not_called()

    def test_auto_rebalance_forced_by_bandwidth_drift(self):
        clients = [
            {
                "customer_id": 1,
                "online": True,
                "ip": "10.10.0.1",
                "isp_port": "ether1",
                "download_bps": 100_000,
                "upload_bps": 0,
            },
            {
                "customer_id": 2,
                "online": True,
                "ip": "10.10.0.2",
                "isp_port": "ether2",
                "download_bps": 100_000,
                "upload_bps": 0,
            },
        ]
        with patch(
            "core.mikrotik_connect.switch_client_to_isp_port",
            return_value={"ok": True, "isp_port": "ether2"},
        ) as switch_mock:
            result = auto_rebalance_client_isps(
                object(),
                member_ports=["ether1", "ether2"],
                clients=clients,
                preferred_overloaded_isp="ether1",
                preferred_underloaded_isp="ether2",
            )
        self.assertTrue(result["ok"])
        switch_mock.assert_called_once()

    def test_client_traffic_bps_sums_download_and_upload(self):
        self.assertEqual(
            _client_traffic_bps({"download_bps": 1000, "upload_bps": 250}),
            1250,
        )

    def test_switch_client_rejects_slow_target(self):
        result = switch_client_to_isp_port(
            object(),
            client_ip="10.10.0.5",
            target_port="ether2",
            member_ports=["ether1", "ether2"],
            customer_id=7,
            slow_ports=["ether2"],
        )
        self.assertFalse(result["ok"])
        self.assertIn("sidelined", result["error"].lower())

    def test_build_router_client_analysis_exposes_switch_controls(self):
        router = MikroTikRouter(
            name="edge",
            host="10.0.0.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_ports=["ether1", "ether2"],
        )
        customer = MagicMock()
        customer.pk = 7
        customer.full_name = "Jane Doe"
        customer.account_number = "ACC-7"
        customer.pppoe_username = "jane"
        customer.hotspot_mac = None
        customer.cpe_ip = ""
        customer.cpe_mac = ""
        customer.service_type = "pppoe"
        customer.status = "active"

        usage = {
            "ok": True,
            "uses_connection_marks": True,
            "default_isp_port": "ether1",
            "client_pins": {},
            "ip_usage": {
                "10.10.0.5": {
                    "isp_port": "ether1",
                    "connections": 2,
                    "source": "connection_mark",
                }
            },
            "sessions": {"10.10.0.5": {"pppoe_username": "jane", "source": "pppoe"}},
        }
        with patch("billing.models.Customer.objects") as customer_qs:
            customer_qs.filter.return_value.only.return_value = [customer]
            analysis = _build_router_client_analysis(
                router,
                uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
                uplink_live={},
                wan_share={"ok": True, "shares": []},
                smart_balance_status={"slow_ports": []},
                primary_wan_ports=["ether1"],
                backup_wan_ports=["ether2"],
                usage=usage,
            )

        self.assertTrue(analysis["can_switch_clients"])
        self.assertEqual(len(analysis["isp_switch_options"]), 2)
        client = analysis["clients"][0]
        self.assertTrue(client["can_switch_isp"])
        self.assertEqual(client["ip"], "10.10.0.5")

    def test_can_switch_when_balance_rules_exist_without_live_marks(self):
        from core.views import _build_router_client_analysis

        router = MikroTikRouter(
            name="edge",
            host="10.0.0.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_ports=["ether1", "ether2"],
        )
        customer = MagicMock()
        customer.pk = 7
        customer.full_name = "Jane Doe"
        customer.account_number = "ACC-7"
        customer.pppoe_username = "jane"
        customer.hotspot_mac = None
        customer.cpe_ip = ""
        customer.cpe_mac = ""
        customer.service_type = "pppoe"
        customer.status = "active"

        usage = {
            "ok": True,
            "uses_connection_marks": False,
            "mark_to_port": {"0": "ether1", "1": "ether2"},
            "default_isp_port": "ether1",
            "client_pins": {},
            "ip_usage": {
                "10.10.0.5": {
                    "isp_port": "ether1",
                    "connections": 0,
                    "source": "default_wan",
                }
            },
            "sessions": {"10.10.0.5": {"pppoe_username": "jane", "source": "pppoe"}},
        }
        with patch("billing.models.Customer.objects") as customer_qs:
            customer_qs.filter.return_value.only.return_value = [customer]
            analysis = _build_router_client_analysis(
                router,
                uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
                uplink_live={},
                wan_share={"ok": True, "shares": []},
                smart_balance_status={"slow_ports": []},
                primary_wan_ports=["ether1"],
                backup_wan_ports=["ether2"],
                usage=usage,
            )

        self.assertTrue(analysis["can_switch_clients"])
        self.assertTrue(analysis["clients"][0]["can_switch_isp"])

    def test_perform_client_isp_switch_delegates_to_router_api(self):
        router = MikroTikRouter(
            pk=7,
            name="edge",
            host="10.0.0.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_ports=["ether1", "ether2"],
        )
        org = MagicMock()
        org.pk = 3
        customer = MagicMock()
        customer.pk = 9
        customer.full_name = "Jane Doe"

        @contextmanager
        def fake_session(*args, **kwargs):
            yield object()

        cached_live = {
            "router_analysis": {
                "can_switch_clients": True,
                "clients": [{"customer_id": 9, "ip": "10.10.0.5", "isp_port": "ether1"}],
            },
            "smart_balance_status": {"slow_ports": []},
        }
        with patch(
            "core.views.Customer.objects.filter",
            return_value=MagicMock(first=MagicMock(return_value=customer)),
        ), patch("core.views._router_api_host", return_value="10.0.0.1"), patch(
            "core.views._api_session", side_effect=fake_session
        ), patch(
            "core.views.router_client_isp_switch_ready",
            return_value={"ok": True, "active_mark_indexes": [0, 1]},
        ), patch(
            "core.views.switch_client_to_isp_port",
            return_value={"ok": True, "isp_port": "ether2"},
        ) as switch_mock, patch(
            "core.views.cache.get", return_value=cached_live
        ), patch("core.views.cache.delete") as cache_delete, patch(
            "core.views.record_client_isp_movement"
        ) as record_mock:
            result = _perform_client_isp_switch(
                router,
                org,
                customer_id=9,
                client_ip="10.10.0.5",
                target_port="ether2",
            )

        self.assertTrue(result["ok"])
        self.assertIn("Jane Doe", result["message"])
        switch_mock.assert_called_once()
        self.assertEqual(cache_delete.call_count, 2)
        record_mock.assert_called_once()

    def test_perform_client_isp_switch_works_without_live_cache(self):
        router = MikroTikRouter(
            pk=7,
            name="edge",
            host="10.0.0.1",
            username="admin",
            password="x",
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            uplink_ports=["ether1", "ether2"],
        )
        org = MagicMock()
        org.pk = 3
        customer = MagicMock()
        customer.pk = 9
        customer.full_name = "Jane Doe"

        @contextmanager
        def fake_session(*args, **kwargs):
            yield object()

        with patch(
            "core.views.Customer.objects.filter",
            return_value=MagicMock(first=MagicMock(return_value=customer)),
        ), patch("core.views._router_api_host", return_value="10.0.0.1"), patch(
            "core.views._api_session", side_effect=fake_session
        ), patch(
            "core.views.router_client_isp_switch_ready",
            return_value={"ok": True, "active_mark_indexes": [0, 1]},
        ), patch(
            "core.views.switch_client_to_isp_port",
            return_value={"ok": True, "isp_port": "ether2"},
        ), patch("core.views.cache.get", return_value=None), patch(
            "core.views.cache.delete"
        ), patch("core.views.record_client_isp_movement"):
            result = _perform_client_isp_switch(
                router,
                org,
                customer_id=9,
                client_ip="10.10.0.5",
                target_port="ether2",
            )

        self.assertTrue(result["ok"])

    def test_clear_all_client_isp_pins_removes_rules_and_refreshes_sessions(self):
        sock = object()
        with patch(
            "core.mikrotik_connect.read_client_isp_pins",
            return_value={
                "10.10.0.1": {"pinned": True, "isp_port": "ether2"},
                "10.10.0.2": {"pinned": True, "isp_port": "ether1"},
            },
        ), patch(
            "core.mikrotik_connect._remove_client_isp_pins",
            return_value=4,
        ) as remove_mock, patch(
            "core.mikrotik_connect._kill_firewall_connections_for_addresses",
            return_value=2,
        ) as kill_mock:
            result = clear_all_client_isp_pins(sock)

        self.assertTrue(result["ok"])
        self.assertEqual(result["clients_reset"], 2)
        self.assertEqual(result["removed_rules"], 4)
        self.assertEqual(result["connections_cleared"], 2)
        remove_mock.assert_called_once_with(sock)
        kill_mock.assert_called_once_with(sock, ["10.10.0.1", "10.10.0.2"])


class SmartBalanceMemberConnectivityTests(SimpleTestCase):
    def test_monitor_sidelines_member_without_gateway(self):
        from core.mikrotik_connect import run_smart_balance_monitor_via_api

        sock = object()
        members = [
            {"interface": "ether1", "wan_iface": "ether1", "weight": "100", "index": "0"},
            {"interface": "ether2", "wan_iface": "ether2", "weight": "100", "index": "1"},
        ]
        with patch(
            "core.mikrotik_connect.read_smart_balance_status",
            return_value={"members": {}},
        ), patch(
            "core.mikrotik_connect._balance_member_connectivity",
            side_effect=[
                {
                    "has_gateway": True,
                    "route_active": True,
                    "ping_recv": 3,
                    "ping_loss": 0,
                    "ping_rtt_ms": 20.0,
                },
                {
                    "has_gateway": False,
                    "route_active": False,
                    "ping_recv": 0,
                    "ping_loss": 100,
                    "ping_rtt_ms": 0.0,
                },
            ],
        ), patch(
            "core.mikrotik_connect._set_smart_balance_member_active"
        ) as set_active, patch(
            "core.mikrotik_connect._remove_client_isp_pins_for_mark"
        ), patch("django.core.cache.cache.set"):
            result = run_smart_balance_monitor_via_api(
                sock, members, force=True, host="10.0.0.1"
            )

        self.assertTrue(result.get("ok"))
        self.assertIn("ether2", result.get("slow_ports") or [])
        set_active.assert_any_call(sock, 1, active=False)

    def test_monitor_keeps_member_when_gateway_up_but_ping_blocked(self):
        from core.mikrotik_connect import run_smart_balance_monitor_via_api

        sock = object()
        members = [
            {"interface": "ether1", "wan_iface": "ether1", "weight": "100", "index": "0"},
            {"interface": "ether2", "wan_iface": "ether2", "weight": "100", "index": "1"},
        ]
        with patch(
            "core.mikrotik_connect.read_smart_balance_status",
            return_value={"members": {}},
        ), patch(
            "core.mikrotik_connect._balance_member_connectivity",
            return_value={
                "has_gateway": True,
                "route_active": True,
                "ping_recv": 0,
                "ping_loss": 100,
                "ping_rtt_ms": 0.0,
            },
        ), patch(
            "core.mikrotik_connect._set_smart_balance_member_active"
        ) as set_active, patch("django.core.cache.cache.set"):
            result = run_smart_balance_monitor_via_api(
                sock, members, force=True, host="10.0.0.1"
            )

        self.assertTrue(result.get("ok"))
        self.assertNotIn("ether2", result.get("slow_ports") or [])
        set_active.assert_any_call(sock, 1, active=True)


class SharedIspProbeTests(SimpleTestCase):
    def test_unbridged_shared_isp_nudges_dhcp_while_waiting(self):
        from core.views import _try_probe_shared_isp_ports

        router = MikroTikRouter(
            pk=99,
            uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
            port_roles={"ether1": "wan", "ether2": "wan_backup"},
            username="admin",
            password="secret",
        )
        live_ports = [
            _port("ether1", uplink_kind="dhcp", uplink_active=True, bridged=False),
            _port(
                "ether2",
                uplink_kind="dhcp",
                uplink_active=False,
                bridged=False,
            ),
        ]
        with patch("core.views.active_uplink_apply_job", return_value=None), patch(
            "core.views.nudge_mikrotik_shared_isp_dhcp",
            return_value={"ok": True, "nudged": True},
        ) as nudge_mock, patch("core.views.cache") as cache_mock:
            cache_mock.get.return_value = None
            outcomes = _try_probe_shared_isp_ports(router, "10.0.0.1", live_ports)

        nudge_mock.assert_called_once_with(
            "10.0.0.1",
            "admin",
            "secret",
            port_name="ether2",
            timeout=8.0,
        )
        self.assertIn("ether2", outcomes)
        self.assertTrue(outcomes["ether2"].get("nudged"))

    def test_nudge_shared_isp_dhcp_renews_client(self):
        from core.mikrotik_connect import nudge_mikrotik_shared_isp_dhcp

        with patch("core.mikrotik_connect._api_session") as session, patch(
            "core.mikrotik_connect._iface_names",
            return_value={"ether2"},
        ), patch(
            "core.mikrotik_connect._renew_dhcp_on_port",
            side_effect=lambda sock, port, notes: notes.append("renewed DHCP on ether2"),
        ):
            session.return_value.__enter__.return_value = object()
            result = nudge_mikrotik_shared_isp_dhcp(
                "192.168.88.1", "admin", "x", port_name="ether2"
            )

        self.assertTrue(result.get("ok"))
        self.assertTrue(result.get("nudged"))
        self.assertIn("renewed DHCP on ether2", result.get("notes") or [])
