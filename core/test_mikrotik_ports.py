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
    apply_mikrotik_uplink_bond,
    apply_mikrotik_uplink_failover,
    list_mikrotik_ports,
)
from core.models import MikroTikRouter
from core.views import (
    _pick_auto_wan,
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
                return []
            return []

        with (
            patch("core.mikrotik_connect._api_session", self._session()),
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch(
                "core.mikrotik_connect._set",
                return_value={"_reply": "!done"},
            ),
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

    def test_bond_disables_member_dhcp(self):
        names = {"ether1", "ether2", "bridgeLocal"}
        disabled: list[str] = []

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
            return []

        def fake_set(sock, path, item_id, **props):
            if path == "/ip/dhcp-client" and props.get("disabled") == "yes":
                disabled.append(item_id)
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
        self.assertEqual(sorted(result.get("disabled_member_dhcp") or []), ["ether1", "ether2"])
        self.assertEqual(sorted(disabled), ["*d1", "*d2"])


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
