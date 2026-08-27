"""Ports page: WAN detection, auto-assign, bond/failover for any ISP."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from core.mikrotik_connect import (
    UPLINK_TAG,
    _default_route_wan,
    _ensure_failover_uplink,
    _resolve_wan_to_physical,
    apply_mikrotik_single_wan,
    switch_mikrotik_single_wan,
    apply_mikrotik_uplink_bond,
    apply_mikrotik_uplink_failover,
    assess_uplink_switch_risk,
    build_single_wan_recovery_script,
    list_mikrotik_ports,
)
from core.models import MikroTikRouter
from core.views import (
    _allowed_roles_for_uplink_mode,
    _build_uplink_prompt,
    _build_wan_switch_risks,
    _failover_ports_from_roles,
    _normalize_port_roles_for_uplink_mode,
    _pick_auto_wan,
    _role_allowed_for_uplink_mode,
    _wan_switch_confirmed,
    apply_detected_uplink,
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
    iface_type: str = "ether",
) -> dict:
    return {
        "name": name,
        "type": iface_type,
        "running": running,
        "disabled": disabled,
        "is_bridged": bridged,
        "bridge": "bridgeLocal" if bridged else "",
        "is_wireless": wireless,
        "uplink_kind": uplink_kind,
        "uplink_iface": "pppoe-out1" if uplink_kind == "pppoe" else "",
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

    def test_management_on_old_wan_blocks_switch(self):
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
        self.assertTrue(risk["blocking"])
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
