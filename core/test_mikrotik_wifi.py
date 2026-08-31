"""Wi‑Fi detection and apply across classic / wifi / wifiwave2 packages."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from core.mikrotik_connect import (
    WIFI_PACKAGES,
    _apply_on_package,
    _detect_wifi_package,
    _hint_wifi_mode_from_interfaces,
    _read_wifi_settings,
    _wifi_packages_to_try,
    configure_mikrotik_wifi,
)


class WifiPackageOrderTests(SimpleTestCase):
    def test_modern_packages_come_first(self):
        modes = [p["mode"] for p in WIFI_PACKAGES]
        self.assertEqual(modes[0], "wifi")
        self.assertIn("wireless", modes)

    def test_preferred_mode_first_then_fallbacks(self):
        modes = [p["mode"] for p in _wifi_packages_to_try("wireless")]
        self.assertEqual(modes[0], "wireless")
        self.assertIn("wifi", modes)
        self.assertEqual(len(modes), len(WIFI_PACKAGES))


class DetectWifiPackageTests(SimpleTestCase):
    def test_skips_empty_wireless_and_finds_wifi(self):
        def fake_print(sock, path, **kwargs):
            if path == "/interface":
                return [{"name": "wifi1", "type": "wifi"}]
            if path == "/interface/wireless":
                return []
            if path == "/interface/wifi":
                return [
                    {
                        ".id": "*1",
                        "name": "wifi1",
                        "ssid": "ISP-Home",
                        "mode": "ap",
                        "disabled": "false",
                    }
                ]
            if path == "/interface/wifiwave2":
                return []
            return []

        with patch("core.mikrotik_connect._print", side_effect=fake_print):
            package = _detect_wifi_package(MagicMock())
        self.assertIsNotNone(package)
        self.assertEqual(package["mode"], "wifi")

    def test_timeout_on_wireless_still_finds_wifi(self):
        calls = {"n": 0}

        def fake_print(sock, path, **kwargs):
            calls["n"] += 1
            if path == "/interface":
                return [{"name": "wifi1", "type": "wifi"}]
            if path == "/interface/wireless":
                raise TimeoutError("slow")
            if path == "/interface/wifi":
                return [{".id": "*1", "name": "wifi1", "mode": "ap"}]
            return []

        with patch("core.mikrotik_connect._print", side_effect=fake_print):
            package = _detect_wifi_package(MagicMock())
        self.assertEqual(package["mode"], "wifi")

    def test_hint_from_interface_type(self):
        def fake_print(sock, path, **kwargs):
            if path == "/interface":
                return [
                    {"name": "ether1", "type": "ether"},
                    {"name": "wifi1", "type": "wifi"},
                ]
            return []

        with patch("core.mikrotik_connect._print", side_effect=fake_print):
            self.assertEqual(_hint_wifi_mode_from_interfaces(MagicMock()), "wifi")


class ReadWifiSettingsTests(SimpleTestCase):
    def test_reads_ssid_from_configuration_profile(self):
        def fake_print(sock, path, **kwargs):
            if path == "/interface/wifi":
                return [
                    {
                        ".id": "*1",
                        "name": "wifi1",
                        "mode": "ap",
                        "configuration": "cfg-home",
                        "security": "sec-home",
                        "disabled": "false",
                    }
                ]
            if path == "/interface/wifi/configuration":
                return [{".id": "*c", "name": "cfg-home", "ssid": "OfficeWifi"}]
            if path == "/interface/wifi/security":
                return [{".id": "*s", "name": "sec-home", "passphrase": "secret123"}]
            return []

        package = next(p for p in WIFI_PACKAGES if p["mode"] == "wifi")
        with patch("core.mikrotik_connect._print", side_effect=fake_print):
            settings = _read_wifi_settings(MagicMock(), package)
        self.assertEqual(settings["wifi_ssid"], "OfficeWifi")
        self.assertEqual(settings["wifi_password"], "secret123")
        self.assertEqual(settings["wifi_mode"], "wifi")


class ApplyOnPackageTests(SimpleTestCase):
    def test_applies_ssid_via_configuration_when_direct_fails(self):
        sets: list[dict] = []
        adds: list[dict] = []

        def fake_print(sock, path, **kwargs):
            if path == "/interface/wifi":
                return [
                    {
                        ".id": "*1",
                        "name": "wifi1",
                        "mode": "ap",
                        "configuration": "",
                        "security": "",
                        "disabled": "false",
                    }
                ]
            if path == "/interface/wifi/cap":
                return []
            if path == "/interface/wifi/configuration":
                return []
            if path == "/interface/wifi/security":
                return []
            return []

        def fake_set(sock, path, item_id, **props):
            sets.append({"path": path, "id": item_id, **props})
            if path == "/interface/wifi" and "ssid" in props:
                return {"_reply": "!trap", "message": "unknown parameter"}
            if path == "/interface/wifi" and "configuration.ssid" in props:
                return {"_reply": "!trap", "message": "unknown parameter"}
            return {"_reply": "!done"}

        def fake_add(sock, path, **props):
            adds.append({"path": path, **props})
            return {"_reply": "!done"}

        package = next(p for p in WIFI_PACKAGES if p["mode"] == "wifi")
        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
            patch("core.mikrotik_connect._add", side_effect=fake_add),
        ):
            result = _apply_on_package(
                MagicMock(),
                package,
                ssid="NewSSID",
                wifi_password="",
                apply_ssid=True,
                apply_password=False,
            )

        self.assertTrue(result["ok"], result)
        self.assertTrue(
            any(a.get("path") == "/interface/wifi/configuration" for a in adds),
            adds,
        )
        self.assertTrue(
            any(
                s.get("path") == "/interface/wifi" and s.get("configuration") == "ispcentric-wifi"
                for s in sets
            ),
            sets,
        )

    def test_station_radio_is_reclaimed_not_skipped(self):
        sets: list[dict] = []

        def fake_print(sock, path, **kwargs):
            if path == "/interface/wireless":
                return [
                    {
                        ".id": "*1",
                        "name": "wlan1",
                        "mode": "station",
                        "ssid": "Upstream",
                        "security-profile": "default",
                        "disabled": "false",
                    }
                ]
            if path == "/interface/wireless/cap":
                return []
            return []

        def fake_set(sock, path, item_id, **props):
            sets.append({"path": path, "id": item_id, **props})
            return {"_reply": "!done"}

        package = next(p for p in WIFI_PACKAGES if p["mode"] == "wireless")
        with (
            patch("core.mikrotik_connect._print", side_effect=fake_print),
            patch("core.mikrotik_connect._set", side_effect=fake_set),
        ):
            result = _apply_on_package(
                MagicMock(),
                package,
                ssid="CustomerWifi",
                wifi_password="",
                apply_ssid=True,
                apply_password=False,
            )

        self.assertTrue(result["ok"], result)
        self.assertTrue(
            any(s.get("mode") == "ap-bridge" for s in sets),
            sets,
        )
        self.assertTrue(
            any(s.get("ssid") == "CustomerWifi" for s in sets),
            sets,
        )


class ConfigureMikrotikWifiTests(SimpleTestCase):
    def test_falls_through_wrong_mode_to_wifi_package(self):
        @contextmanager
        def session(*args, **kwargs):
            yield MagicMock()

        def fake_apply(sock, package, **kwargs):
            if package["mode"] == "wireless":
                return {"ok": False, "updated": False, "error": "", "skip": True}
            if package["mode"] == "wifi":
                return {"ok": True, "updated": True, "mode": "wifi", "message": "ok"}
            return {"ok": False, "updated": False, "error": "", "skip": True}

        with (
            patch("core.mikrotik_connect._device_api_session", session),
            patch(
                "core.mikrotik_connect._detect_wifi_package",
                return_value=None,
            ),
            patch(
                "core.mikrotik_connect._read_wifi_settings",
                return_value={"wifi_ssid": "", "wifi_password": "", "wifi_mode": ""},
            ),
            patch(
                "core.mikrotik_connect._apply_on_package",
                side_effect=fake_apply,
            ),
            patch(
                "core.mikrotik_connect._verify_wifi",
                return_value={
                    "ok": True,
                    "updated": True,
                    "mode": "wifi",
                    "message": "ok",
                    "wifi_ssid": "Home",
                    "wifi_password": "",
                },
            ),
        ):
            # Stale wifi_mode=wireless used to lock apply to classic only.
            result = configure_mikrotik_wifi(
                "10.9.0.3",
                "admin",
                "x",
                wifi_ssid="Home",
                wifi_mode="wireless",
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result.get("mode") or result.get("wifi_mode") or "wifi", "wifi")
