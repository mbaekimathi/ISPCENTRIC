import hashlib
from contextlib import contextmanager
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import Client, TestCase

from accounts.models import Organization
from billing.models import Customer
from core import mikrotik_connect
from core.models import MikroTikRouter


class _FakeUpstream:
    status = 200

    def getheaders(self):
        return [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Set-Cookie", "stok=router-session; Path=/"),
        ]

    def read(self, amount=None):
        return b'<html><a href="/status.asp">Status</a></html>'


class _FakeConnection:
    last_request = None

    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port

    def request(self, method, target, body=None, headers=None):
        type(self).last_request = (method, target, body, headers)

    def getresponse(self):
        return _FakeUpstream()

    def close(self):
        pass


class ClientRouterProxyTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("router-owner", password="x")
        self.org = Organization.objects.create(
            name="Router ISP",
            owner=self.owner,
            join_code="123987",
        )
        self.nas = MikroTikRouter.objects.create(
            organization=self.org,
            name="Main NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.9.0.2",
            username="admin",
            password="secret",
        )
        self.customer = Customer.objects.create(
            organization=self.org,
            full_name="PPPoE Customer",
            phone="254700000001",
            account_number="CPE-WEB-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="customer1",
            router=self.nas,
        )
        self.client.force_login(self.owner)
        self.cpe_target_patcher = patch(
            "core.views.resolve_customer_cpe_target",
            return_value={
                "ok": True,
                "session_active": True,
                "address": "10.20.0.55",
                "scope": "customer1",
                "gateway": "10.20.0.1",
                "mode": "pppoe",
            },
        )
        self.cpe_target_patcher.start()
        self.addCleanup(self.cpe_target_patcher.stop)
        self.cpe_login_patcher = patch(
            "core.views.login_customer_cpe_web_session",
            return_value={
                "ok": False,
                "authenticated": False,
                "cookies": {},
                "basic_header": "",
                "error": "",
                "steps": [],
            },
        )
        self.cpe_login_patcher.start()
        self.addCleanup(self.cpe_login_patcher.stop)
        self.nas_check_patcher = patch(
            "core.connectivity_verification.evaluate_nas_connectivity",
            return_value={
                "ok": True,
                "reachable": True,
                "api_ok": True,
                "error": "",
                "hint": "",
                "details": {},
            },
        )
        self.nas_check_patcher.start()
        self.addCleanup(self.nas_check_patcher.stop)

    def _start_url(self, client=None, port=80):
        client = client or self.client
        with patch(
            "core.views.probe_customer_cpe_web",
            return_value={
                "ok": True,
                "session_active": True,
                "cpe_host": "10.20.0.55",
                "port": port,
                "reachable": True,
                "ping_ok": True,
            },
        ):
            response = client.get(
                f"/app/clients/{self.customer.pk}/router-login/start/",
            )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["proxy_url"])
        return payload["proxy_url"]

    @staticmethod
    @contextmanager
    def _proxy(*args, **kwargs):
        yield {
            "host": "10.9.0.2",
            "port": 39001,
            "cpe_host": "10.20.0.55",
        }

    def test_client_page_has_router_login_link(self):
        response = self.client.get(f"/app/clients/{self.customer.pk}/")

        self.assertContains(response, "Open client router")
        self.assertContains(
            response,
            f"/app/clients/{self.customer.pk}/router-login/",
        )
        html = response.content.decode()
        self.assertNotRegex(
            html,
            r'href="/app/clients/%s/router-login/"[^>]*target="_blank"'
            % self.customer.pk,
        )

    @patch("core.views.http.client.HTTPConnection", _FakeConnection)
    @patch("core.views.customer_cpe_web_proxy", _proxy)
    def test_proxy_rewrites_root_links_and_forwards_post_without_django_csrf(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.owner)
        proxy_url = self._start_url(client=csrf_client)

        response = csrf_client.post(
            proxy_url + "goform/setWifi",
            data="ssid=NewName",
            content_type="application/x-www-form-urlencoded",
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, proxy_url + "status.asp")
        self.assertEqual(_FakeConnection.last_request[0], "POST")
        self.assertEqual(_FakeConnection.last_request[1], "/goform/setWifi")

    def test_proxy_rejects_tampered_token(self):
        proxy_url = self._start_url()
        token = proxy_url.rstrip("/").rsplit("/", 1)[-1]
        response = self.client.get(proxy_url.replace(token, token + "x"))

        self.assertEqual(response.status_code, 403)

    def test_router_login_page_loads_without_blocking_on_probe(self):
        with patch("core.views.probe_customer_cpe_web") as probe:
            response = self.client.get(
                f"/app/clients/{self.customer.pk}/router-login/",
            )

        probe.assert_not_called()
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/client_router_access.html")
        self.assertContains(response, "Opening the client router")
        self.assertContains(response, "Remote client router")
        self.assertContains(
            response,
            f"/app/clients/{self.customer.pk}/router-login/start/",
        )

    def test_preflight_blocked_cpe_shows_remote_management_guidance(self):
        with patch(
            "core.views.probe_customer_cpe_web",
            return_value={
                "ok": False,
                "session_active": True,
                "cpe_host": "10.20.0.55",
                "port": None,
                "reachable": False,
                "ping_ok": True,
                "hint": "router refuses management from the ISP side",
            },
        ) as probe:
            response = self.client.get(
                f"/app/clients/{self.customer.pk}/router-login/start/",
            )

        probe.assert_called_once()
        self.assertTrue(probe.call_args.kwargs.get("auto_enable_www"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["session_active"])
        self.assertTrue(payload["ping_ok"])
        self.assertEqual(payload["failure_class"], "wan_mgmt_blocked")
        self.assertIn("refuses management", payload["detail"])
        self.assertTrue(payload["guidance"])
        self.assertIn("Remote / WAN Web Management", payload["guidance"][1])
        self.assertNotIn("proxy_url", payload)

    def test_preflight_offline_client_explains_pppoe_is_down(self):
        with patch(
            "core.views.probe_customer_cpe_web",
            return_value={
                "ok": False,
                "session_active": False,
                "cpe_host": "",
                "port": None,
                "reachable": False,
                "ping_ok": False,
                "hint": "The client is not online on PPPoE right now.",
            },
        ):
            response = self.client.get(
                f"/app/clients/{self.customer.pk}/router-login/start/",
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["session_active"])
        self.assertEqual(payload["failure_class"], "offline")
        self.assertIn("PPPoE", payload["detail"])
        self.assertTrue(any("PPPoE" in step for step in payload["guidance"]))

    def test_start_fails_fast_when_nas_unreachable(self):
        with (
            patch(
                "core.connectivity_verification.evaluate_nas_connectivity",
                return_value={
                    "ok": False,
                    "reachable": False,
                    "api_ok": False,
                    "error": "10.9.0.2: unreachable",
                    "hint": "Tunnel router unreachable — paste the WireGuard script.",
                    "details": {},
                },
            ),
            patch("core.views.probe_customer_cpe_web") as probe,
        ):
            response = self.client.get(
                f"/app/clients/{self.customer.pk}/router-login/start/",
            )

        probe.assert_not_called()
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["failure_class"], "nas_down")
        self.assertIn("WireGuard", payload["detail"] + " ".join(payload["guidance"]))
        self.assertTrue(payload["nas_url"])
        self.assertNotIn("proxy_url", payload)

    @patch("core.views.http.client.HTTPConnection", _FakeConnection)
    @patch("core.views.customer_cpe_web_proxy", _proxy)
    def test_detected_port_is_carried_in_the_signed_token(self):
        proxy_url = self._start_url(port=8080)

        captured = {}
        real_proxy = self._proxy

        @contextmanager
        def _capturing_proxy(*args, **kwargs):
            captured["cpe_port"] = kwargs.get("cpe_port")
            with real_proxy(*args, **kwargs) as value:
                yield value

        with patch("core.views.customer_cpe_web_proxy", _capturing_proxy):
            response = self.client.get(proxy_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(captured["cpe_port"], 8080)

    def test_rewrite_does_not_double_prefix_on_form_actions(self):
        from core.views import _normalize_proxied_path, _rewrite_cpe_body

        prefix = (
            f"/app/clients/{self.customer.pk}/router/"
            "eyJjdXN0b21lcl9pZCI6MTAsInVzZXJfaWQiOjQsImNwZV9wb3J0Ijo4MH0:token/"
        )
        html = (
            b'<form action="/login/Auth" method="post">'
            b'<script>var u="/goform/getstok";</script>'
            b'<a href="/login.html">login</a>'
            b"</form>"
        )
        once = _rewrite_cpe_body(html, "text/html", prefix, "10.20.0.11").decode()
        twice = _rewrite_cpe_body(
            once.encode(), "text/html", prefix, "10.20.0.11"
        ).decode()

        expected_action = f'action="{prefix}login/Auth"'
        self.assertIn(expected_action, once)
        self.assertIn(expected_action, twice)
        self.assertEqual(once.count(prefix + "login/Auth"), 1)
        self.assertEqual(twice.count(prefix + "login/Auth"), 1)
        self.assertNotIn(prefix + prefix, twice)
        self.assertIn(f'href="{prefix}login.html"', twice)
        self.assertIn(f'"{prefix}goform/getstok"', twice)

    def test_inbound_double_prefixed_path_is_unwrapped_before_forward(self):
        from core.views import _normalize_proxied_path

        prefix = f"/app/clients/{self.customer.pk}/router/tok/"
        doubled = (
            f"app/clients/{self.customer.pk}/router/tok/login/Auth"
        )
        self.assertEqual(
            _normalize_proxied_path(doubled, prefix),
            "/login/Auth",
        )

    @patch("core.views.http.client.HTTPConnection", _FakeConnection)
    @patch("core.views.customer_cpe_web_proxy", _proxy)
    def test_proxy_forwards_unwrapped_path_when_browser_posts_doubled_url(self):
        proxy_url = self._start_url()
        doubled = proxy_url + proxy_url.lstrip("/") + "login/Auth"

        response = self.client.post(
            doubled,
            data="password=admin",
            content_type="application/x-www-form-urlencoded",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(_FakeConnection.last_request[1], "/login/Auth")


    @patch("core.views.http.client.HTTPConnection", _FakeConnection)
    @patch("core.views.customer_cpe_web_proxy", _proxy)
    def test_asset_that_escaped_the_prefix_is_sent_back_under_the_page_token(self):
        proxy_url = self._start_url()

        # Tenda's login page asks for "../img/visible.png"; from the proxy root
        # that ".." eats the token segment instead of clamping at the CPE root.
        escaped = f"/app/clients/{self.customer.pk}/router/img/visible.png"
        response = self.client.get(
            escaped,
            HTTP_REFERER=f"http://testserver{proxy_url}login.html",
        )

        self.assertEqual(response.status_code, 307)
        self.assertEqual(response["Location"], proxy_url + "img/visible.png")

        # Following it reaches the CPE at the path the router actually meant.
        self.client.get(response["Location"])
        self.assertEqual(_FakeConnection.last_request[1], "/img/visible.png")

    @patch("core.views.http.client.HTTPConnection", _FakeConnection)
    @patch("core.views.customer_cpe_web_proxy", _proxy)
    def test_escaped_asset_keeps_its_query_string(self):
        proxy_url = self._start_url()

        response = self.client.get(
            f"/app/clients/{self.customer.pk}/router/goform/getWAN",
            {"modules": "internetStatus"},
            HTTP_REFERER=f"http://testserver{proxy_url}index.html",
        )

        self.assertEqual(
            response["Location"],
            proxy_url + "goform/getWAN?modules=internetStatus",
        )

    def test_bad_token_without_a_proxy_referer_is_still_rejected(self):
        response = self.client.get(
            f"/app/clients/{self.customer.pk}/router/img/visible.png"
        )

        self.assertEqual(response.status_code, 403)

    def test_bad_token_is_not_recovered_from_another_customers_page(self):
        other = Customer.objects.create(
            organization=self.org,
            full_name="Other PPPoE",
            phone="254700000002",
            account_number="CPE-WEB-2",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="customer2",
            router=self.nas,
        )
        proxy_url = self._start_url()

        response = self.client.get(
            f"/app/clients/{other.pk}/router/img/visible.png",
            HTTP_REFERER=f"http://testserver{proxy_url}login.html",
        )

        self.assertEqual(response.status_code, 403)


    @patch("core.views.http.client.HTTPConnection", _FakeConnection)
    @patch("core.views.customer_cpe_web_proxy", _proxy)
    def test_token_cached_cpe_host_skips_per_asset_resolve(self):
        # Open stamps cpe_host into the signed token; subsequent asset GETs must
        # not re-resolve the PPPoE session on the NAS for every image/AJAX call.
        proxy_url = self._start_url()
        with patch(
            "core.views.resolve_customer_cpe_target",
            side_effect=AssertionError("resolve must not run when token has cpe_host"),
        ):
            response = self.client.get(proxy_url + "status.asp")
        self.assertEqual(response.status_code, 200)

    @patch("core.views.http.client.HTTPConnection", _FakeConnection)
    @patch("core.views.customer_cpe_web_proxy", _proxy)
    def test_active_requests_keep_the_session_alive(self):
        # Repeated traffic within the idle window must keep succeeding; the
        # sliding window is refreshed on every proxied request.
        proxy_url = self._start_url()
        for _ in range(3):
            response = self.client.get(proxy_url + "goform/getWifi")
            self.assertEqual(response.status_code, 200)

    @patch("core.views.http.client.HTTPConnection", _FakeConnection)
    @patch("core.views.customer_cpe_web_proxy", _proxy)
    def test_idle_session_times_out_after_inactivity(self):
        import hashlib
        import time

        from django.core.cache import cache

        from core.views import _CPE_PROXY_IDLE_AGE

        proxy_url = self._start_url()
        # Prime the session, then age its activity marker past the idle window.
        self.assertEqual(self.client.get(proxy_url).status_code, 200)

        token = proxy_url.rstrip("/").rsplit("/", 1)[-1]
        activity_key = "cpe-web-activity:" + hashlib.sha256(token.encode()).hexdigest()
        cache.set(activity_key, time.time() - (_CPE_PROXY_IDLE_AGE + 5))

        response = self.client.get(proxy_url + "goform/getWifi")
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"timed out", response.content)

    def test_client_page_loads_live_router_data_panel(self):
        response = self.client.get(f"/app/clients/{self.customer.pk}/")

        self.assertContains(response, "Router details")
        self.assertContains(
            response,
            f"/app/clients/{self.customer.pk}/router-data/",
        )

    @patch("core.views.fetch_customer_cpe_web_data")
    @patch("core.views.probe_customer_cpe_web")
    def test_router_data_endpoint_returns_normalized_snapshot(self, probe, fetch):
        probe.return_value = {
            "reachable": True,
            "port": 80,
            "cpe_host": "10.20.0.55",
        }
        fetch.return_value = {
            "ok": True,
            "vendor": "Tenda",
            "model": "Tenda_0C8890",
            "cpe_host": "10.20.0.55",
            "status": {"connected": True, "online_devices": "2"},
            "wifi": {"ssid": "Client WiFi", "enabled": True},
            "wan": {"ip": "10.20.0.55", "type": "pppoe"},
            "system": {"firmware": "V12.03"},
            "devices": [],
            "error": "",
        }

        response = self.client.get(
            f"/app/clients/{self.customer.pk}/router-data/?refresh=1"
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.assertEqual(response.json()["wifi"]["ssid"], "Client WiFi")
        fetch.assert_called_once()
        self.assertEqual(fetch.call_args.kwargs["cpe_port"], 80)

    def test_web_ports_include_webfig_8081(self):
        self.assertEqual(mikrotik_connect.CPE_WEB_PORTS[0], 80)
        self.assertEqual(mikrotik_connect.CPE_WEB_PORTS[1], 8081)

    def test_start_saves_router_password_before_probe(self):
        with patch(
            "core.views.probe_customer_cpe_web",
            return_value={
                "ok": True,
                "session_active": True,
                "cpe_host": "10.20.0.55",
                "port": 80,
                "reachable": True,
                "ping_ok": True,
            },
        ) as probe:
            response = self.client.post(
                f"/app/clients/{self.customer.pk}/router-login/start/",
                {"cpe_password": "newsecret"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.cpe_password, "newsecret")
        self.assertEqual(probe.call_args.kwargs.get("cpe_password"), "newsecret")

    def test_start_auto_login_seeds_proxy_cookies_and_basic_auth(self):
        from django.core.cache import cache

        self.cpe_login_patcher.stop()
        self.addCleanup(self.cpe_login_patcher.start)
        with (
            patch(
                "core.views.probe_customer_cpe_web",
                return_value={
                    "ok": True,
                    "session_active": True,
                    "cpe_host": "10.20.0.55",
                    "port": 80,
                    "reachable": True,
                    "ping_ok": True,
                    "steps": ["found client IP"],
                },
            ),
            patch(
                "core.views.login_customer_cpe_web_session",
                return_value={
                    "ok": True,
                    "authenticated": True,
                    "cookies": {"stok": "router-session"},
                    "basic_header": "Basic YWRtaW46c2VjcmV0",
                    "vendor": "tenda",
                    "cpe_username": "admin",
                    "cpe_password": "secret",
                    "support_user": False,
                    "error": "",
                    "steps": ["signed in to Tenda web UI as admin"],
                },
            ),
        ):
            response = self.client.get(
                f"/app/clients/{self.customer.pk}/router-login/start/",
            )

        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["authenticated"])
        token = payload["proxy_url"].rstrip("/").rsplit("/", 1)[-1]
        digest = hashlib.sha256(token.encode()).hexdigest()
        self.assertEqual(cache.get("cpe-web:" + digest)["stok"], "router-session")
        self.assertEqual(
            cache.get("cpe-web-basic:" + digest)["header"],
            "Basic YWRtaW46c2VjcmV0",
        )

    @patch("core.views.http.client.HTTPConnection", _FakeConnection)
    @patch("core.views.customer_cpe_web_proxy", _proxy)
    def test_proxy_sends_cached_basic_authorization(self):
        from django.core.cache import cache

        proxy_url = self._start_url()
        token = proxy_url.rstrip("/").rsplit("/", 1)[-1]
        cache.set(
            "cpe-web-basic:" + hashlib.sha256(token.encode()).hexdigest(),
            {"header": "Basic YWRtaW46c2VjcmV0"},
            60,
        )

        response = self.client.get(proxy_url + "status.asp")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            _FakeConnection.last_request[3].get("Authorization"),
            "Basic YWRtaW46c2VjcmV0",
        )

    def test_saving_the_router_password_clears_the_cached_snapshot(self):
        from django.core.cache import cache

        cache_key = f"client_cpe_router_data:{self.org.pk}:{self.customer.pk}"
        cache.set(cache_key, {"ok": False, "error": "rejected"}, 60)

        response = self.client.post(
            f"/app/clients/{self.customer.pk}/",
            {"action": "update_router_password", "cpe_password": "realsecret"},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.cpe_password, "realsecret")
        self.assertIsNone(cache.get(cache_key))


class CpeWebAutoLoginTests(TestCase):
    def test_login_page_detection(self):
        self.assertTrue(
            mikrotik_connect._html_looks_like_login_page(
                '<form><input name="name"><input type="password"></form>'
            )
        )
        self.assertFalse(
            mikrotik_connect._html_looks_like_login_page(
                "<html><title>WebFig</title><div id=app></div></html>"
            )
        )

    @patch.object(mikrotik_connect, "customer_cpe_web_proxy")
    @patch.object(mikrotik_connect, "_cpe_web_json_request")
    def test_tenda_auto_login_returns_session_cookies(self, json_request, proxy):
        @contextmanager
        def _proxy(*args, **kwargs):
            yield {"host": "10.9.0.2", "port": 39001, "cpe_host": "10.20.0.11"}

        proxy.side_effect = _proxy

        def _responses(_proxy, path, **kwargs):
            if path.endswith("getStatus") or "getStatus" in path:
                if kwargs.get("cookies") and kwargs["cookies"].get("stok") == "ok":
                    return 200, {"internetStatus": {"wan": "up"}}, {}, ""
                return 302, {}, {}, "/login.html"
            if path == "/goform/getstok":
                return 200, {"random": "abc"}, {}, ""
            if path == "/login/Auth":
                return 200, {"errCode": "0"}, {"stok": "ok"}, ""
            return 404, {}, {}, ""

        json_request.side_effect = _responses
        result = mikrotik_connect.login_customer_cpe_web_session(
            "10.9.0.2",
            "admin",
            "secret",
            pppoe_username="customer1",
            cpe_username="admin",
            cpe_password="housepass",
            cpe_port=80,
        )
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["vendor"], "tenda")
        self.assertEqual(result["cookies"].get("stok"), "ok")


class CpeWebLoginLockoutTests(TestCase):
    """A wrong password must not be retried until the credential changes."""

    def setUp(self):
        mikrotik_connect._CPE_WEB_LOGIN_BLOCKS.clear()
        mikrotik_connect._CPE_WEB_DATA_SESSIONS.clear()

    def tearDown(self):
        mikrotik_connect._CPE_WEB_LOGIN_BLOCKS.clear()
        mikrotik_connect._CPE_WEB_DATA_SESSIONS.clear()

    @staticmethod
    @contextmanager
    def _proxy(*args, **kwargs):
        yield {"host": "10.9.0.2", "port": 39001, "cpe_host": "10.20.0.11"}

    def _fetch(self, password="wrong"):
        return mikrotik_connect.fetch_customer_cpe_web_data(
            "10.9.0.2",
            "admin",
            "secret",
            pppoe_username="customer1",
            cpe_password=password,
        )

    def test_rejected_password_reports_remaining_attempts_and_stops_retrying(self):
        def _responses(proxy, path, **kwargs):
            if path == "/goform/getstok":
                return 200, {"random": "abc"}, {}, ""
            if path == "/login/Auth":
                return 302, {}, {}, "http://10.20.0.11/login.html?11"
            return 302, {}, {}, "http://10.20.0.11/login.html"

        with (
            patch.object(mikrotik_connect, "customer_cpe_web_proxy", self._proxy),
            patch.object(
                mikrotik_connect, "_cpe_web_json_request", side_effect=_responses
            ) as request,
        ):
            first = self._fetch()
            calls_after_first = request.call_count
            second = self._fetch()
            calls_after_second = request.call_count

        self.assertFalse(first["ok"])
        self.assertIn("1 attempt left", first["error"])
        self.assertEqual(first["error"], second["error"])
        # The blocked retry only probes status; it never posts to /login/Auth.
        self.assertEqual(calls_after_second - calls_after_first, 1)

    def test_lockout_response_explains_the_three_minute_wait(self):
        def _responses(proxy, path, **kwargs):
            if path == "/goform/getstok":
                return 200, {"random": "abc"}, {}, ""
            if path == "/login/Auth":
                return 302, {}, {}, "http://10.20.0.11/login.html?10"
            return 302, {}, {}, ""

        with (
            patch.object(mikrotik_connect, "customer_cpe_web_proxy", self._proxy),
            patch.object(mikrotik_connect, "_cpe_web_json_request", side_effect=_responses),
        ):
            result = self._fetch()

        self.assertIn("three minutes", result["error"])

    def test_a_new_password_is_allowed_to_try_again(self):
        attempts = []

        def _responses(proxy, path, **kwargs):
            if path == "/goform/getstok":
                return 200, {"random": "abc"}, {}, ""
            if path == "/login/Auth":
                attempts.append(kwargs.get("body"))
                return 302, {}, {}, "http://10.20.0.11/login.html?11"
            return 302, {}, {}, ""

        with (
            patch.object(mikrotik_connect, "customer_cpe_web_proxy", self._proxy),
            patch.object(mikrotik_connect, "_cpe_web_json_request", side_effect=_responses),
        ):
            self._fetch("wrong")
            self._fetch("wrong")
            self._fetch("corrected")

        self.assertEqual(len(attempts), 2)

    def test_a_valid_session_cookie_skips_login_entirely(self):
        status = {
            "internetStatus": {"wanConnectStatus": "13103061"},
            "deviceStastics": {"routerName": "Tenda_0C8890", "statusOnlineNumber": "1"},
            "systemInfo": {"statusWanIP": "10.20.0.11", "softVersion": "V12.03"},
        }

        def _responses(proxy, path, **kwargs):
            if path == "/login/Auth":
                raise AssertionError("login must not be attempted with a live session")
            if path.startswith("/goform/getStatus"):
                return 200, status, {}, ""
            return 200, {}, {}, ""

        with (
            patch.object(mikrotik_connect, "customer_cpe_web_proxy", self._proxy),
            patch.object(mikrotik_connect, "_cpe_web_json_request", side_effect=_responses),
        ):
            result = mikrotik_connect.fetch_customer_cpe_web_data(
                "10.9.0.2",
                "admin",
                "secret",
                pppoe_username="customer1",
                cpe_password="",
                session_cookies={"ecos_pw": "live-session"},
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["model"], "Tenda_0C8890")
        self.assertEqual(result["wan"]["ip"], "10.20.0.11")


class CustomerCpeWebProxyCacheTests(TestCase):
    def setUp(self):
        from django.core.cache import cache

        mikrotik_connect._CPE_WEB_PROXY_CACHE.clear()
        mikrotik_connect._CPE_WEB_PROXY_LOCKS.clear()
        cache.delete("cpe-web-proxy:v1:10.9.0.2|customer1|80")

    def tearDown(self):
        from django.core.cache import cache

        mikrotik_connect._CPE_WEB_PROXY_CACHE.clear()
        mikrotik_connect._CPE_WEB_PROXY_LOCKS.clear()
        cache.delete("cpe-web-proxy:v1:10.9.0.2|customer1|80")

    def test_repeated_calls_reuse_one_installed_proxy(self):
        @contextmanager
        def _fake_api_session(*args, **kwargs):
            class _Sock:
                def getsockname(self):
                    return ("192.168.88.253", 0)

            yield _Sock()

        with (
            patch.object(
                mikrotik_connect,
                "resolve_customer_cpe_session",
                return_value={
                    "ok": True,
                    "session_active": True,
                    "address": "10.20.0.11",
                },
            ) as resolve,
            patch.object(mikrotik_connect, "_api_session", _fake_api_session),
            patch.object(
                mikrotik_connect, "_install_cpe_proxy", return_value=None
            ) as install,
        ):
            first_ports = []
            for _ in range(5):
                with mikrotik_connect.customer_cpe_web_proxy(
                    "10.9.0.2",
                    "admin",
                    "secret",
                    pppoe_username="customer1",
                    cpe_port=80,
                ) as proxy:
                    first_ports.append(proxy["port"])

        # One install, one session resolve — the rest served from cache.
        self.assertEqual(install.call_count, 1)
        self.assertEqual(resolve.call_count, 1)
        self.assertEqual(len(set(first_ports)), 1)
        self.assertEqual(proxy["cpe_host"], "10.20.0.11")

    def test_proxy_cache_ttl_matches_idle_window(self):
        self.assertGreaterEqual(mikrotik_connect._CPE_WEB_PROXY_TTL, 15 * 60)

    def test_proxy_cache_hit_slides_expiry(self):
        @contextmanager
        def _fake_api_session(*args, **kwargs):
            class _Sock:
                def getsockname(self):
                    return ("192.168.88.253", 0)

            yield _Sock()

        with (
            patch.object(
                mikrotik_connect,
                "resolve_customer_cpe_session",
                return_value={
                    "ok": True,
                    "session_active": True,
                    "address": "10.20.0.11",
                },
            ),
            patch.object(mikrotik_connect, "_api_session", _fake_api_session),
            patch.object(mikrotik_connect, "_install_cpe_proxy", return_value=None),
        ):
            with mikrotik_connect.customer_cpe_web_proxy(
                "10.9.0.2",
                "admin",
                "secret",
                pppoe_username="customer1",
                cpe_port=80,
            ) as first:
                key = ("10.9.0.2", "customer1|80")
                entry = mikrotik_connect._CPE_WEB_PROXY_CACHE[key]
                first_expiry = entry["expires_at"]
            # Force an almost-expired L1 entry; a hit must slide TTL forward.
            mikrotik_connect._CPE_WEB_PROXY_CACHE[key]["expires_at"] = (
                __import__("time").monotonic() + 2.0
            )
            with mikrotik_connect.customer_cpe_web_proxy(
                "10.9.0.2",
                "admin",
                "secret",
                pppoe_username="customer1",
                cpe_port=80,
            ) as second:
                slid = mikrotik_connect._CPE_WEB_PROXY_CACHE[key]["expires_at"]
        self.assertEqual(first["port"], second["port"])
        self.assertGreater(slid, first_expiry - 1)


class CustomerCpeAccessModeTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("access-owner", password="x")
        self.org = Organization.objects.create(
            name="Access ISP",
            owner=self.owner,
            join_code="456789",
        )
        self.nas = MikroTikRouter.objects.create(
            organization=self.org,
            name="Access NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.9.0.5",
            username="admin",
            password="secret",
            lan_bridge="bridgeLocal",
        )

    def test_pppoe_client_eligible_with_username(self):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="PPPoE User",
            phone="254700000010",
            account_number="ACC-PPP-1",
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username="user1",
            router=self.nas,
        )
        self.assertTrue(mikrotik_connect.customer_cpe_access_eligible(customer))
        self.assertEqual(mikrotik_connect.customer_cpe_access_mode(customer), "pppoe")

    def test_static_client_eligible_with_ip(self):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Static User",
            phone="254700000011",
            account_number="ACC-STA-1",
            service_type=Customer.ServiceType.STATIC,
            cpe_ip="192.168.88.50",
            router=self.nas,
        )
        self.assertTrue(mikrotik_connect.customer_cpe_access_eligible(customer))
        self.assertEqual(mikrotik_connect.customer_cpe_access_mode(customer), "static")

    def test_dhcp_client_eligible_with_mac(self):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="DHCP User",
            phone="254700000012",
            account_number="ACC-DHCP-1",
            service_type=Customer.ServiceType.STATIC,
            cpe_mac="AA:BB:CC:DD:EE:01",
            router=self.nas,
        )
        self.assertTrue(mikrotik_connect.customer_cpe_access_eligible(customer))
        self.assertEqual(mikrotik_connect.customer_cpe_access_mode(customer), "dhcp")

    @patch("core.mikrotik_connect._api_session")
    def test_resolve_static_target(self, mock_api):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Static User",
            phone="254700000013",
            account_number="ACC-STA-2",
            service_type=Customer.ServiceType.STATIC,
            cpe_ip="192.168.88.60",
            router=self.nas,
        )

        @contextmanager
        def _fake_session(*args, **kwargs):
            yield object()

        mock_api.side_effect = _fake_session
        with patch.object(
            mikrotik_connect,
            "_nas_lan_gateway_ip",
            return_value="192.168.88.1",
        ):
            with patch(
                "core.mikrotik_connect._nas_ping_host",
                return_value={"ok": True, "reachable": True, "received": 1, "error": ""},
            ):
                target = mikrotik_connect.resolve_customer_cpe_target(
                    self.nas.host,
                    self.nas.username,
                    self.nas.password,
                    customer,
                )
        self.assertTrue(target["ok"])
        self.assertTrue(target["session_active"])
        self.assertEqual(target["address"], "192.168.88.60")
        self.assertEqual(target["mode"], "static")
        self.assertEqual(target["gateway"], "192.168.88.1")

    @patch("core.mikrotik_connect._api_session")
    def test_resolve_dhcp_target_from_lease(self, mock_api):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="DHCP User",
            phone="254700000014",
            account_number="ACC-DHCP-2",
            service_type=Customer.ServiceType.STATIC,
            cpe_mac="AA:BB:CC:DD:EE:02",
            router=self.nas,
        )

        @contextmanager
        def _fake_session(*args, **kwargs):
            yield object()

        mock_api.side_effect = _fake_session
        with (
            patch.object(
                mikrotik_connect,
                "_nas_lan_gateway_ip",
                return_value="192.168.88.1",
            ),
            patch.object(
                mikrotik_connect,
                "_resolve_dhcp_client_ip",
                return_value="192.168.88.75",
            ),
        ):
            target = mikrotik_connect.resolve_customer_cpe_target(
                self.nas.host,
                self.nas.username,
                self.nas.password,
                customer,
            )
        self.assertTrue(target["ok"])
        self.assertTrue(target["session_active"])
        self.assertEqual(target["address"], "192.168.88.75")
        self.assertEqual(target["mode"], "dhcp")

    @patch("core.views.login_customer_cpe_web_session")
    @patch("core.views.probe_customer_cpe_web")
    @patch(
        "core.connectivity_verification.evaluate_nas_connectivity",
        return_value={
            "ok": True,
            "reachable": True,
            "api_ok": True,
            "error": "",
            "hint": "",
            "details": {},
        },
    )
    def test_static_client_router_login_starts_proxy(
        self, _mock_nas, mock_probe, mock_login
    ):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Static User",
            phone="254700000015",
            account_number="ACC-STA-3",
            service_type=Customer.ServiceType.STATIC,
            cpe_ip="192.168.88.80",
            router=self.nas,
        )
        mock_probe.return_value = {
            "ok": True,
            "session_active": True,
            "cpe_host": "192.168.88.80",
            "port": 80,
            "reachable": True,
            "ping_ok": True,
            "gateway": "192.168.88.1",
            "mode": "static",
        }
        mock_login.return_value = {
            "ok": False,
            "authenticated": False,
            "cookies": {},
            "basic_header": "",
            "error": "",
            "steps": [],
        }
        client = Client()
        client.force_login(self.owner)
        response = client.get(
            f"/app/clients/{customer.pk}/router-login/start/",
            follow=False,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["proxy_url"].endswith("/"))
        mock_probe.assert_called_once()
        self.assertEqual(mock_probe.call_args.kwargs.get("customer").pk, customer.pk)
        self.assertTrue(mock_probe.call_args.kwargs.get("auto_enable_www"))


class StaticClientDhcpLeaseTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user("dhcp-owner", password="x")
        self.org = Organization.objects.create(
            name="DHCP ISP",
            owner=self.owner,
            join_code="789012",
        )
        self.nas = MikroTikRouter.objects.create(
            organization=self.org,
            name="DHCP NAS",
            model=MikroTikRouter.ModelChoice.HEX,
            host="10.9.0.6",
            username="admin",
            password="secret",
        )

    def test_skips_without_ip_and_mac(self):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Partial Static",
            phone="254700000020",
            account_number="ACC-PARTIAL",
            service_type=Customer.ServiceType.STATIC,
            router=self.nas,
            cpe_ip="192.168.88.90",
        )
        result = mikrotik_connect.provision_static_client_dhcp_lease(customer)
        self.assertFalse(result["ok"])
        self.assertTrue(result["skipped"])

    @patch.object(mikrotik_connect, "_api_session")
    def test_binds_static_lease_on_nas(self, mock_api):
        customer = Customer.objects.create(
            organization=self.org,
            full_name="Bound Static",
            phone="254700000021",
            account_number="ACC-BIND-1",
            service_type=Customer.ServiceType.STATIC,
            router=self.nas,
            cpe_ip="192.168.88.91",
            cpe_mac="AA:BB:CC:DD:EE:99",
        )

        @contextmanager
        def _fake_session(*args, **kwargs):
            yield object()

        mock_api.side_effect = _fake_session
        with (
            patch.object(
                mikrotik_connect,
                "_remove_stale_static_client_dhcp_leases",
                return_value=[],
            ) as remove_stale,
            patch.object(
                mikrotik_connect,
                "_ensure_static_dhcp_lease",
                return_value=["DHCP reservation 192.168.88.91 -> AA:BB:CC:DD:EE:99"],
            ) as ensure,
        ):
            result = mikrotik_connect.provision_static_client_dhcp_lease(customer)

        self.assertTrue(result["ok"])
        remove_stale.assert_called_once()
        ensure.assert_called_once()
        args, kwargs = ensure.call_args
        self.assertEqual(args[1], "192.168.88.91")
        self.assertEqual(args[2], "AA:BB:CC:DD:EE:99")
        self.assertIn(customer.account_number, kwargs["comment"])

