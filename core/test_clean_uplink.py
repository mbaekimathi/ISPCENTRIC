"""Clean uplink: ISP-agnostic routing / provider-block behaviour."""

from __future__ import annotations

import ipaddress
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from core.forms import MikroTikCleanUplinkForm
from core.mikrotik_connect import (
    CLEAN_UPLINK_TAG,
    ensure_mikrotik_lan_passthrough,
    parse_provider_gateways,
    pick_clean_uplink_lan_plan,
    set_mikrotik_clean_uplink,
    _ensure_filter_rules,
)


class ParseProviderGatewaysTests(SimpleTestCase):
    def test_single_and_multi_ipv4(self):
        self.assertEqual(parse_provider_gateways("192.168.1.1"), ["192.168.1.1"])
        self.assertEqual(
            parse_provider_gateways("192.168.1.1, 192.168.100.1;10.0.0.1"),
            ["192.168.1.1", "192.168.100.1", "10.0.0.1"],
        )

    def test_dedupes_and_rejects_bad(self):
        self.assertEqual(
            parse_provider_gateways("192.168.1.1, 192.168.1.1"),
            ["192.168.1.1"],
        )
        with self.assertRaises(ValueError):
            parse_provider_gateways("not-an-ip")


class PickLanPlanTests(SimpleTestCase):
    def test_keeps_safe_existing_lan(self):
        existing = ipaddress.ip_network("192.168.88.0/24")
        wan = [ipaddress.ip_network("192.168.1.0/24")]
        network, gateway, _ranges = pick_clean_uplink_lan_plan(wan, existing)
        self.assertEqual(network, "192.168.88.0/24")
        self.assertEqual(gateway, "192.168.88.1")

    def test_avoids_wan_overlap_including_starlink_and_fibre(self):
        # Starlink / home routers often use 192.168.1.0/24; fibre ONTs 192.168.100.0/24.
        wan = [
            ipaddress.ip_network("192.168.1.0/24"),
            ipaddress.ip_network("192.168.100.0/24"),
        ]
        network, gateway, ranges = pick_clean_uplink_lan_plan(wan, None)
        self.assertEqual(network, "10.10.0.0/24")
        self.assertEqual(gateway, "10.10.0.1")
        self.assertIn("10.10.0.10", ranges)

    def test_skips_first_candidate_when_wan_is_10_10(self):
        wan = [ipaddress.ip_network("10.10.0.0/24")]
        network, gateway, _ = pick_clean_uplink_lan_plan(wan, None)
        self.assertEqual(network, "10.11.0.0/24")
        self.assertEqual(gateway, "10.11.0.1")

    def test_moves_existing_lan_when_it_overlaps_wan(self):
        existing = ipaddress.ip_network("192.168.1.0/24")
        wan = [ipaddress.ip_network("192.168.1.0/24")]
        network, _, _ = pick_clean_uplink_lan_plan(wan, existing)
        self.assertEqual(network, "10.10.0.0/24")


class CleanUplinkFormTests(SimpleTestCase):
    def test_bypass_does_not_require_gateway(self):
        form = MikroTikCleanUplinkForm(
            data={
                "mode": "bypass",
                "wan_interface": "ether1",
                "lan_bridge": "bridgeLocal",
                "provider_gateway": "",
                "confirm": "on",
            }
        )
        self.assertTrue(form.is_valid(), form.errors)

    def test_behind_requires_valid_gateway(self):
        form = MikroTikCleanUplinkForm(
            data={
                "mode": "behind",
                "wan_interface": "ether1",
                "lan_bridge": "bridge",
                "provider_gateway": "",
                "confirm": "on",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("provider_gateway", form.errors)

    def test_behind_accepts_fibre_ont_and_multi(self):
        form = MikroTikCleanUplinkForm(
            data={
                "mode": "behind",
                "wan_interface": "ether1",
                "lan_bridge": "bridge",
                "provider_gateway": "192.168.100.1, 192.168.1.1",
                "confirm": "on",
            }
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(
            form.cleaned_data["provider_gateway"],
            "192.168.100.1, 192.168.1.1",
        )

    def test_rejects_invalid_gateway(self):
        form = MikroTikCleanUplinkForm(
            data={
                "mode": "behind",
                "wan_interface": "ether1",
                "lan_bridge": "bridge",
                "provider_gateway": "gateway.local",
                "confirm": "on",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("provider_gateway", form.errors)


class EnsureFilterRulesTests(SimpleTestCase):
    def test_behind_blocks_multiple_gateways_and_private_provider_lan(self):
        added: list[dict] = []

        with (
            patch("core.mikrotik_connect._remove_tagged"),
            patch(
                "core.mikrotik_connect._add",
                side_effect=lambda sock, path, **props: added.append(props) or {"_reply": "!done"},
            ),
        ):
            _ensure_filter_rules(
                object(),
                mode="behind",
                provider_gateways=["192.168.1.1", "192.168.100.1"],
                provider_networks=["192.168.1.0/24", "8.8.8.0/24"],
            )

        drops = [r for r in added if r.get("action") == "drop"]
        self.assertEqual(
            {r["dst-address"] for r in drops},
            {"192.168.1.1", "192.168.100.1", "192.168.1.0/24"},
        )
        # Public provider_networks must not be blocked.
        self.assertFalse(any(r.get("dst-address") == "8.8.8.0/24" for r in drops))

    def test_bypass_does_not_add_provider_drops(self):
        added: list[dict] = []
        with (
            patch("core.mikrotik_connect._remove_tagged"),
            patch(
                "core.mikrotik_connect._add",
                side_effect=lambda sock, path, **props: added.append(props) or {"_reply": "!done"},
            ),
        ):
            _ensure_filter_rules(
                object(),
                mode="bypass",
                provider_gateways=["192.168.1.1"],
                provider_networks=["192.168.1.0/24"],
            )
        self.assertFalse(any(r.get("action") == "drop" for r in added))
        self.assertTrue(any(CLEAN_UPLINK_TAG in (r.get("comment") or "") for r in added))


class FakeRouterState:
    """Minimal RouterOS print/add/set/remove store for clean-uplink tests."""

    def __init__(self):
        self.tables: dict[str, list[dict[str, str]]] = {
            "/interface": [
                {"name": "ether1"},
                {"name": "ether2"},
                {"name": "bridgeLocal"},
                {"name": "pppoe-out1"},
            ],
            "/interface/pppoe-client": [],
            "/interface/list": [{"name": "WAN"}, {"name": "LAN"}],
            "/interface/list/member": [],
            "/interface/bridge/port": [],
            "/ip/address": [
                {".id": "*1", "address": "192.168.88.1/24", "interface": "bridgeLocal"},
            ],
            "/ip/dhcp-client": [],
            "/ip/pool": [],
            "/ip/dhcp-server": [],
            "/ip/dhcp-server/network": [],
            "/ip/firewall/filter": [],
            "/ip/firewall/nat": [],
            "/ip/dns": [],
        }
        self._seq = 10

    def _next_id(self) -> str:
        self._seq += 1
        return f"*{self._seq}"

    def print(self, sock, path, **kwargs):
        return [dict(row) for row in self.tables.get(path, [])]

    def add(self, sock, path, **props):
        row = {k: str(v) for k, v in props.items()}
        row[".id"] = self._next_id()
        self.tables.setdefault(path, []).append(row)
        return {"_reply": "!done"}

    def set(self, sock, path, item_id, **props):
        for row in self.tables.get(path, []):
            if row.get(".id") == item_id:
                row.update({k: str(v) for k, v in props.items()})
                return {"_reply": "!done"}
        return {"_reply": "!trap", "message": "not found"}

    def remove(self, sock, path, item_id):
        rows = self.tables.get(path, [])
        self.tables[path] = [r for r in rows if r.get(".id") != item_id]
        return {"_reply": "!done"}


class LanPassthroughTests(SimpleTestCase):
    def _run(self, state: FakeRouterState):
        with (
            patch("core.mikrotik_connect._print", side_effect=state.print),
            patch("core.mikrotik_connect._add", side_effect=state.add),
            patch("core.mikrotik_connect._set", side_effect=state.set),
            patch("core.mikrotik_connect._remove", side_effect=state.remove),
            patch(
                "core.mikrotik_connect._command",
                return_value=([], {"_reply": "!done"}),
            ),
        ):
            return ensure_mikrotik_lan_passthrough(
                object(), wan_interface="ether1", lan_bridge="bridgeLocal"
            )

    def test_dhcp_wan_keeps_safe_mikrotik_lan(self):
        state = FakeRouterState()
        state.tables["/ip/address"].append(
            {".id": "*w", "address": "192.168.1.50/24", "interface": "ether1"}
        )
        notes = self._run(state)
        self.assertIn("wan_mode=dhcp", notes)
        self.assertIn("lan_plan=192.168.88.0/24", notes)
        self.assertTrue(
            any(
                r.get("interface") == "ether1"
                for r in state.tables["/ip/dhcp-client"]
            )
        )

    def test_pppoe_skips_dhcp_and_adds_pppoe_to_wan_list(self):
        state = FakeRouterState()
        state.tables["/interface/pppoe-client"] = [
            {
                ".id": "*p",
                "name": "pppoe-out1",
                "interface": "ether1",
                "disabled": "no",
            }
        ]
        state.tables["/ip/address"].append(
            {".id": "*w", "address": "100.64.1.10/32", "interface": "pppoe-out1"}
        )
        notes = self._run(state)
        self.assertIn("wan_mode=pppoe", notes)
        self.assertTrue(any("using PPPoE uplink" in n for n in notes))
        self.assertEqual(state.tables["/ip/dhcp-client"], [])
        members = {
            (r.get("list"), r.get("interface"))
            for r in state.tables["/interface/list/member"]
        }
        self.assertIn(("WAN", "ether1"), members)
        self.assertIn(("WAN", "pppoe-out1"), members)

    def test_lan_moves_off_overlapping_isp_subnet(self):
        state = FakeRouterState()
        # Both WAN and LAN stuck on 192.168.1.0/24 (common behind-provider mistake).
        state.tables["/ip/address"] = [
            {".id": "*1", "address": "192.168.1.2/24", "interface": "bridgeLocal"},
            {".id": "*w", "address": "192.168.1.50/24", "interface": "ether1"},
        ]
        notes = self._run(state)
        self.assertIn("lan_plan=10.10.0.0/24", notes)
        lan_addrs = [
            r["address"]
            for r in state.tables["/ip/address"]
            if r.get("interface") == "bridgeLocal"
        ]
        self.assertEqual(lan_addrs, ["10.10.0.1/24"])


class SetCleanUplinkTests(SimpleTestCase):
    def _session(self):
        @contextmanager
        def _api(*args, **kwargs):
            yield MagicMock()

        return _api

    def test_enable_bypass_on_dhcp_isp(self):
        state = FakeRouterState()
        state.tables["/ip/address"].append(
            {".id": "*w", "address": "10.0.0.50/24", "interface": "ether1"}
        )
        filter_calls: list[dict] = []

        def capture_filters(sock, *, mode, provider_gateways=None, provider_networks=None):
            filter_calls.append(
                {
                    "mode": mode,
                    "gateways": list(provider_gateways or []),
                    "networks": list(provider_networks or []),
                }
            )

        with (
            patch("core.mikrotik_connect._api_session", self._session()),
            patch("core.mikrotik_connect._print", side_effect=state.print),
            patch("core.mikrotik_connect._add", side_effect=state.add),
            patch("core.mikrotik_connect._set", side_effect=state.set),
            patch("core.mikrotik_connect._remove", side_effect=state.remove),
            patch(
                "core.mikrotik_connect._command",
                return_value=([], {"_reply": "!done"}),
            ),
            patch(
                "core.mikrotik_connect._ensure_filter_rules",
                side_effect=capture_filters,
            ),
            patch("core.mikrotik_connect._ensure_dns_redirect"),
            patch("core.mikrotik_connect._remove_tagged"),
        ):
            result = set_mikrotik_clean_uplink(
                "192.168.88.1",
                "admin",
                "secret",
                enabled=True,
                mode="bypass",
                wan_interface="ether1",
                lan_bridge="bridgeLocal",
                separate_wan=False,
            )

        self.assertTrue(result["ok"], result)
        self.assertTrue(result["enabled"])
        self.assertEqual(result["mode"], "bypass")
        self.assertEqual(result.get("wan_mode"), "dhcp")
        self.assertEqual(filter_calls[-1]["mode"], "bypass")
        self.assertEqual(filter_calls[-1]["gateways"], [])

    def test_enable_behind_fibre_ont_blocks_gateways(self):
        state = FakeRouterState()
        state.tables["/ip/address"].append(
            {".id": "*w", "address": "192.168.100.10/24", "interface": "ether1"}
        )
        filter_calls: list[dict] = []

        def capture_filters(sock, *, mode, provider_gateways=None, provider_networks=None):
            filter_calls.append(
                {
                    "mode": mode,
                    "gateways": list(provider_gateways or []),
                    "networks": list(provider_networks or []),
                }
            )

        with (
            patch("core.mikrotik_connect._api_session", self._session()),
            patch("core.mikrotik_connect._print", side_effect=state.print),
            patch("core.mikrotik_connect._add", side_effect=state.add),
            patch("core.mikrotik_connect._set", side_effect=state.set),
            patch("core.mikrotik_connect._remove", side_effect=state.remove),
            patch(
                "core.mikrotik_connect._command",
                return_value=([], {"_reply": "!done"}),
            ),
            patch(
                "core.mikrotik_connect._ensure_filter_rules",
                side_effect=capture_filters,
            ),
            patch("core.mikrotik_connect._ensure_dns_redirect"),
            patch("core.mikrotik_connect._remove_tagged"),
        ):
            result = set_mikrotik_clean_uplink(
                "192.168.88.1",
                "admin",
                "secret",
                enabled=True,
                mode="behind",
                wan_interface="ether1",
                lan_bridge="bridgeLocal",
                provider_gateway="192.168.100.1, 192.168.1.1",
                separate_wan=False,
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(filter_calls[-1]["mode"], "behind")
        self.assertEqual(
            filter_calls[-1]["gateways"],
            ["192.168.100.1", "192.168.1.1"],
        )
        self.assertIn("192.168.100.0/24", filter_calls[-1]["networks"])

    def test_enable_pppoe_isp(self):
        state = FakeRouterState()
        state.tables["/interface/pppoe-client"] = [
            {
                ".id": "*p",
                "name": "pppoe-out1",
                "interface": "ether1",
                "disabled": "no",
            }
        ]
        with (
            patch("core.mikrotik_connect._api_session", self._session()),
            patch("core.mikrotik_connect._print", side_effect=state.print),
            patch("core.mikrotik_connect._add", side_effect=state.add),
            patch("core.mikrotik_connect._set", side_effect=state.set),
            patch("core.mikrotik_connect._remove", side_effect=state.remove),
            patch(
                "core.mikrotik_connect._command",
                return_value=([], {"_reply": "!done"}),
            ),
            patch("core.mikrotik_connect._ensure_filter_rules"),
            patch("core.mikrotik_connect._ensure_dns_redirect"),
            patch("core.mikrotik_connect._remove_tagged"),
        ):
            result = set_mikrotik_clean_uplink(
                "10.9.0.3",
                "admin",
                "secret",
                enabled=True,
                mode="bypass",
                wan_interface="ether1",
                lan_bridge="bridgeLocal",
                separate_wan=False,
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result.get("wan_mode"), "pppoe")

    def test_disable_removes_tagged_rules(self):
        removed_paths: list[str] = []

        def fake_remove_tagged(sock, path):
            removed_paths.append(path)
            return 1

        with (
            patch("core.mikrotik_connect._api_session", self._session()),
            patch(
                "core.mikrotik_connect._remove_tagged",
                side_effect=fake_remove_tagged,
            ),
            patch("core.mikrotik_connect._bridge_port_id", return_value=""),
        ):
            result = set_mikrotik_clean_uplink(
                "192.168.88.1",
                "admin",
                "secret",
                enabled=False,
                mode="bypass",
                wan_interface="ether1",
                lan_bridge="bridgeLocal",
                restore_wan_to_bridge=False,
            )

        self.assertTrue(result["ok"])
        self.assertFalse(result["enabled"])
        self.assertIn("/ip/firewall/filter", removed_paths)
        self.assertIn("/ip/firewall/nat", removed_paths)

    def test_behind_without_gateway_fails_clearly(self):
        state = FakeRouterState()
        with (
            patch("core.mikrotik_connect._api_session", self._session()),
            patch("core.mikrotik_connect._print", side_effect=state.print),
        ):
            result = set_mikrotik_clean_uplink(
                "192.168.88.1",
                "admin",
                "secret",
                enabled=True,
                mode="behind",
                wan_interface="ether1",
                lan_bridge="bridgeLocal",
                provider_gateway="",
                separate_wan=False,
            )
        self.assertFalse(result["ok"])
        self.assertIn("Provider gateway", result["error"])

    def test_invalid_gateway_rejected_before_api(self):
        result = set_mikrotik_clean_uplink(
            "192.168.88.1",
            "admin",
            "secret",
            enabled=True,
            mode="behind",
            provider_gateway="bad-ip",
        )
        self.assertFalse(result["ok"])
        self.assertIn("Invalid provider gateway", result["error"])
