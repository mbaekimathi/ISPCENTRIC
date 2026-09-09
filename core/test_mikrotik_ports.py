"""Ports page: WAN detection, auto-assign, bond/failover for any ISP."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from core.mikrotik_connect import (
    UPLINK_TAG,
    _build_smart_balance_ros_script,
    _default_route_wan,
    _ensure_failover_uplink,
    _parse_ispcentric_mark_index,
    _pcc_slot_counts,
    _port_uplink_hints,
    _resolve_wan_to_physical,
    apply_mikrotik_single_wan,
    switch_mikrotik_single_wan,
    apply_mikrotik_uplink_bond,
    apply_mikrotik_uplink_failover,
    assess_bond_members_readiness,
    assess_port_internet_readiness,
    assess_touch_ports_internet,
    assess_uplink_switch_risk,
    build_api_enable_terminal_script,
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
    _build_wan_switch_risks,
    _failover_active_wan_port,
    _failover_ports_from_roles,
    _friendly_role_label,
    _live_isp_member_ports,
    _normalize_port_roles_for_uplink_mode,
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
                disabled.append(item_id)
            return {"_reply": "!done"}

        def fake_add(sock, path, **props):
            if path == "/interface/bonding":
                bond_creates.append(dict(props))
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
        )
        self.assertIn("ispcentric-bond", script)
        self.assertIn("ether1", script)
        self.assertIn("bridgeLocal", script)
        self.assertIn("/interface bridge port add", script)


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
        script = _build_smart_balance_ros_script(
            [
                {"interface": "ether1", "index": "0", "weight": "100"},
                {"interface": "ether2", "index": "1", "weight": "20"},
            ]
        )
        self.assertIn("ispcentric-w0", script)
        self.assertIn("ispcentric-c1", script)
        self.assertIn("/ping address=$target", script)
        self.assertIn("ispcentricSmart0", script)

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
        self.assertEqual(client["connection_count"], 4)
        self.assertIn("download_label", client)
        self.assertIn("usage_url", client)
        self.assertTrue(any(p["kind"] == "isp" for p in analysis["port_analytics"]))

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
        router.save = MagicMock()
        with (
            patch("core.views._router_tunnel_verified", return_value=True),
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
        self.assertTrue(
            any("every" in (a.get("message") or "").lower() for a in alerts if a["code"] == "failover_on_backup")
        )


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

        def fake_gateway(sock, *, interface, kind, pppoe_name):
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
                "core.mikrotik_connect._resolve_balance_member_gateway",
                return_value=("", ""),
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
