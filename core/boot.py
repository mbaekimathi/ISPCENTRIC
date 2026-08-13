"""Background work that starts whenever the Django process starts.

Local ``runserver`` and hosted gunicorn/Passenger both load AppConfig.ready,
so WireGuard peers and subscription access refresh without extra commands.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time

logger = logging.getLogger(__name__)

_started = False

_SKIP_COMMANDS = (
    "migrate",
    "makemigrations",
    "check",
    "test",
    "shell",
    "dbshell",
    "collectstatic",
    "wireguard_peer",
)


def should_start_runtime_tasks() -> bool:
    """False during one-shot management commands and the runserver reloader parent."""
    if any(cmd in sys.argv for cmd in _SKIP_COMMANDS):
        return False
    if "--no-sweep" in sys.argv and "--no-tunnel-sync" in sys.argv:
        return False
    if "runserver" in sys.argv or "devserver" in sys.argv:
        return os.environ.get("RUN_MAIN") == "true"
    return True


def _subscription_sweep_enabled() -> bool:
    if "--no-sweep" in sys.argv:
        return False
    return os.getenv("SUBSCRIPTION_SWEEP_ENABLED", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }


def _tunnel_sync_enabled() -> bool:
    if "--no-tunnel-sync" in sys.argv:
        return False
    return os.getenv("WIREGUARD_AUTO_SYNC", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }


def _subscription_sweep_interval_sec() -> float:
    try:
        return max(60.0, float(os.getenv("SUBSCRIPTION_SWEEP_INTERVAL_SEC", "300")))
    except (TypeError, ValueError):
        return 300.0


def _subscription_sweep_startup_delay_sec() -> float:
    """Delay the first sweep so a just-started process can serve STK/recharge."""
    try:
        return max(0.0, float(os.getenv("SUBSCRIPTION_SWEEP_STARTUP_DELAY_SEC", "20")))
    except (TypeError, ValueError):
        return 20.0


def _run_subscription_sweep(*, label: str = "sweep") -> None:
    from io import StringIO

    from django.core.management import call_command

    out = StringIO()
    try:
        call_command("sync_subscription_access", stdout=out, stderr=out)
        text = out.getvalue().strip()
        if text:
            logger.info("subscription %s: %s", label, text.splitlines()[-1])
    except Exception:
        logger.exception("subscription %s failed", label)


def _start_subscription_sweep_loop() -> None:
    if not _subscription_sweep_enabled():
        return
    interval = _subscription_sweep_interval_sec()

    def _loop() -> None:
        delay = _subscription_sweep_startup_delay_sec()
        if delay:
            logger.info(
                "Subscription sweep startup delayed %.0fs so pay/recharge is not blocked.",
                delay,
            )
            time.sleep(delay)
        _run_subscription_sweep(label="startup")
        while True:
            time.sleep(interval)
            _run_subscription_sweep(label="interval")

    threading.Thread(
        target=_loop,
        name="subscription-sweep",
        daemon=True,
    ).start()
    logger.info(
        "Subscription sweep armed (every %.0fs). Disable with SUBSCRIPTION_SWEEP_ENABLED=false.",
        interval,
    )


def _sync_wireguard() -> None:
    if not _tunnel_sync_enabled():
        return
    try:
        from core.wireguard import ensure_tunnel_runtime

        ensure_tunnel_runtime()
    except Exception:
        logger.exception("WireGuard startup sync failed")


def start_runtime_tasks() -> None:
    """Idempotent: WireGuard peer sync + subscription sweep in background threads."""
    global _started
    if _started or not should_start_runtime_tasks():
        return
    _started = True

    def _boot() -> None:
        _sync_wireguard()
        _start_subscription_sweep_loop()

    threading.Thread(target=_boot, name="ispcentric-boot", daemon=True).start()
