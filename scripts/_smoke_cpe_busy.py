"""Smoke the open-router path against a real management-login lock.

No MySQL and no live MikroTik. A background thread holds the writer login
the same way a sweep does. The probe must open a side login and find the
client web port without asking that sweep to drop its socket. A second
operator, when the side login is already taken, reports nas_busy instead
of an unreachable client router.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ispcentric.settings")
os.environ["MIKROTIK_API_POOL"] = "0"
os.environ["SUBSCRIPTION_SWEEP_ENABLED"] = "false"
os.environ["SUBSCRIPTION_EXPIRY_WATCH_ENABLED"] = "false"
os.environ["USAGE_SAMPLE_ENABLED"] = "false"
os.environ["WIREGUARD_AUTO_SYNC"] = "false"

import django

django.setup()

from unittest.mock import patch

from django.core.cache import caches

from core import mikrotik_connect as mk
from core.views import _cpe_router_failure_class

DIAL = "10.9.0.14"


class _Sock:
    def settimeout(self, _timeout):
        return None

    def close(self):
        return None

    def getsockname(self):
        return ("10.9.0.1", 40000)


def _clear() -> None:
    jobs = caches["jobs"]
    jobs.delete(mk._api_gate_key(DIAL))
    jobs.delete(mk._api_op_gate_key(DIAL))
    jobs.delete(mk._api_yield_key(DIAL))


def _hold(seconds: float, yield_ok: bool, started: threading.Event, released: threading.Event) -> None:
    with mk.background_mikrotik_work():
        if not mk._api_gate_acquire(DIAL):
            raise AssertionError("background job did not get the login")
        started.set()
        end = time.monotonic() + seconds
        try:
            while time.monotonic() < end:
                if yield_ok:
                    try:
                        mk._background_yield_if_requested()
                    except mk.MikrotikApiYield:
                        break
                time.sleep(0.05)
        finally:
            mk._api_gate_release(DIAL)
            released.set()


def _probe(timeout: float) -> tuple[dict, float]:
    customer = SimpleNamespace()
    with (
        patch.object(
            mk,
            "resolve_customer_cpe_target",
            return_value={
                "ok": True,
                "session_active": True,
                "address": "10.20.0.235",
                "scope": "connuser",
                "gateway": "10.20.0.1",
                "mode": "pppoe",
            },
        ),
        patch.object(mk, "_try_cached_cpe_web_ports", return_value=None),
        patch.object(mk, "_preferred_cpe_web_ports", return_value=(80, 8081, 8080)),
        patch.object(mk, "_api_connect_and_login", return_value=(_Sock(), 1, 1)),
        patch.object(mk, "_nas_socket_source_address", return_value="10.9.0.1"),
        patch.object(mk, "_ensure_hotspot_bypass"),
        patch.object(mk, "_nas_ping_host", return_value={"reachable": True, "error": ""}),
        patch.object(mk, "_try_cpe_web_ports", return_value=(80, "")),
    ):
        started = time.monotonic()
        result = mk.probe_customer_cpe_web(
            DIAL,
            "admin",
            "secret",
            customer=customer,
            timeout=timeout,
            auto_enable_www=False,
        )
        return result, time.monotonic() - started


def _scenario(
    name: str,
    hold_s: float,
    yield_ok: bool,
    timeout: float,
    before_probe=None,
) -> tuple[dict, str, float]:
    _clear()
    started = threading.Event()
    released = threading.Event()
    thread = threading.Thread(
        target=_hold,
        args=(hold_s, yield_ok, started, released),
        daemon=True,
    )
    thread.start()
    if not started.wait(3):
        raise AssertionError(f"{name}: background login never started")
    if before_probe:
        before_probe()
    result, elapsed = _probe(timeout)
    thread.join(timeout + 3)
    failure = _cpe_router_failure_class(result, nas_ok=True)
    print(
        f"{name}: ok={result.get('ok')} busy={result.get('api_busy')} "
        f"class={failure} port={result.get('port')} elapsed={elapsed:.2f}s "
        f"error={result.get('error')!r}",
        flush=True,
    )
    _clear()
    return result, failure, elapsed


def main() -> None:
    beside, beside_class, beside_elapsed = _scenario("beside-sweep", 5, False, 12)
    if not beside.get("ok") or beside.get("port") != 80 or beside.get("api_busy"):
        raise SystemExit(f"beside-sweep: expected the router to open, got {beside}")
    if beside_elapsed > 3:
        raise SystemExit(f"beside-sweep: operator waited too long ({beside_elapsed:.2f}s)")

    jobs = caches["jobs"]

    def _take_side_login() -> None:
        jobs.set(mk._api_op_gate_key(DIAL), f"i:{os.getpid()}", 30)

    busy, busy_class, _busy_elapsed = _scenario(
        "side-taken", 30, False, 3, before_probe=_take_side_login
    )
    if not busy.get("api_busy") or busy.get("ok"):
        raise SystemExit(f"side-taken: expected a busy login, got {busy}")
    if busy_class != "nas_busy":
        raise SystemExit(f"side-taken: classified as {busy_class}, not nas_busy")
    if "unreachable" in (busy.get("hint") or "").lower():
        raise SystemExit(f"side-taken: hint blames the client router: {busy.get('hint')}")

    print("SMOKE OK")
    print(f"classes beside={beside_class} busy={busy_class}")
    os._exit(0)


if __name__ == "__main__":
    main()
