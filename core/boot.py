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
    # Match deploy/systemd/ispcentric-sweep.timer (2 min) so local runserver
    # does not leave expired clients surfing for ~5 minutes.
    try:
        return max(60.0, float(os.getenv("SUBSCRIPTION_SWEEP_INTERVAL_SEC", "120")))
    except (TypeError, ValueError):
        return 120.0


def _subscription_sweep_startup_delay_sec() -> float:
    """Delay the first sweep so a just-started process can serve STK/recharge."""
    try:
        return max(0.0, float(os.getenv("SUBSCRIPTION_SWEEP_STARTUP_DELAY_SEC", "20")))
    except (TypeError, ValueError):
        return 20.0


def _usage_sample_enabled() -> bool:
    if "--no-usage-sample" in sys.argv:
        return False
    if "--no-sweep" in sys.argv:
        return False
    return os.getenv("USAGE_SAMPLE_ENABLED", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }


def _usage_sample_interval_sec() -> float:
    """How often to snapshot PPPoE/Hotspot usage from every org's MikroTiks."""
    try:
        # Default 60s — dense enough for trend charts, light on RouterOS.
        return max(30.0, float(os.getenv("USAGE_SAMPLE_INTERVAL_SEC", "60")))
    except (TypeError, ValueError):
        return 60.0


def _usage_sample_startup_delay_sec() -> float:
    try:
        return max(0.0, float(os.getenv("USAGE_SAMPLE_STARTUP_DELAY_SEC", "35")))
    except (TypeError, ValueError):
        return 35.0


def _expiry_watch_interval_sec() -> float:
    """How often to check customers near their access deadline."""
    try:
        return max(15.0, float(os.getenv("SUBSCRIPTION_EXPIRY_WATCH_INTERVAL_SEC", "30")))
    except (TypeError, ValueError):
        return 30.0


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


def _run_near_deadline_expiry_sync() -> None:
    """
    Immediately block customers whose package deadline is due or imminent.

    The full sweep can take up to SUBSCRIPTION_SWEEP_INTERVAL_SEC. Hourly
    Hotspot/PPPoE packages need a tighter loop so surfing stops near the
    exact deadline instead of minutes later.
    """
    from billing.services import customers_near_access_deadline
    from core.mikrotik_connect import sync_customer_subscription_access

    near = list(customers_near_access_deadline(past_seconds=90, future_seconds=45))
    if not near:
        return
    synced = 0
    for customer in near:
        try:
            # Hotspot + PPPoE both get a direct push here so expiry does not
            # wait for the next full org Hotspot rewrite.
            result = sync_customer_subscription_access(customer, provision=True)
            if result.get("ok") or result.get("allowed") is False:
                synced += 1
        except Exception:
            logger.exception(
                "near-deadline sync failed for %s",
                getattr(customer, "account_number", customer.pk),
            )
    if synced:
        logger.info("near-deadline expiry synced %s customer(s)", synced)


def _start_subscription_sweep_loop() -> None:
    if not _subscription_sweep_enabled():
        return
    interval = _subscription_sweep_interval_sec()
    watch_interval = _expiry_watch_interval_sec()

    def _loop() -> None:
        delay = _subscription_sweep_startup_delay_sec()
        if delay:
            logger.info(
                "Subscription sweep startup delayed %.0fs so pay/recharge is not blocked.",
                delay,
            )
            time.sleep(delay)
        _run_subscription_sweep(label="startup")
        next_full = time.monotonic() + interval
        while True:
            time.sleep(watch_interval)
            try:
                _run_near_deadline_expiry_sync()
            except Exception:
                logger.exception("near-deadline expiry watch failed")
            if time.monotonic() >= next_full:
                _run_subscription_sweep(label="interval")
                next_full = time.monotonic() + interval

    threading.Thread(
        target=_loop,
        name="subscription-sweep",
        daemon=True,
    ).start()
    logger.info(
        "Subscription sweep armed (full every %.0fs, expiry watch every %.0fs). "
        "Disable with SUBSCRIPTION_SWEEP_ENABLED=false.",
        interval,
        watch_interval,
    )


def _run_usage_sample_all_orgs(*, label: str = "interval") -> None:
    """
    Persist live PPPoE/Hotspot counters for every organization.

    Runs without anyone viewing usage pages so client/org trend charts keep
    history. One worker wins via cache lock when multiple app processes boot.
    """
    from django.core.cache import cache

    interval = int(_usage_sample_interval_sec())
    lock_ttl = max(20, interval - 5)
    if not cache.add("usage_sample_bg_lock", 1, timeout=lock_ttl):
        return

    from accounts.models import Organization
    from billing.usage_samples import sample_organization_usage

    sampled_total = 0
    org_count = 0
    for org in Organization.objects.order_by("id").iterator():
        org_count += 1
        try:
            result = sample_organization_usage(org, force=True)
            sampled_total += int((result or {}).get("sampled") or 0)
        except Exception:
            logger.exception(
                "usage sample %s failed for org %s",
                label,
                getattr(org, "pk", "?"),
            )
    if org_count:
        logger.info(
            "usage sample %s: %s org(s), %s new row(s)",
            label,
            org_count,
            sampled_total,
        )


def _start_usage_sample_loop() -> None:
    if not _usage_sample_enabled():
        return
    interval = _usage_sample_interval_sec()

    def _loop() -> None:
        delay = _usage_sample_startup_delay_sec()
        if delay:
            logger.info(
                "Usage sampling startup delayed %.0fs so boot traffic stays light.",
                delay,
            )
            time.sleep(delay)
        try:
            _run_usage_sample_all_orgs(label="startup")
        except Exception:
            logger.exception("usage sample startup failed")
        while True:
            time.sleep(interval)
            try:
                _run_usage_sample_all_orgs(label="interval")
            except Exception:
                logger.exception("usage sample interval failed")

    threading.Thread(
        target=_loop,
        name="usage-sample",
        daemon=True,
    ).start()
    logger.info(
        "Usage sampling armed (every %.0fs). Disable with USAGE_SAMPLE_ENABLED=false.",
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


def _nas_config_pending_path() -> str:
    from pathlib import Path

    from django.conf import settings

    base = Path(getattr(settings, "BASE_DIR", Path.cwd()))
    return str(base / "logs" / ".nas_config_sync_pending")


def _nas_config_sync_requested() -> bool:
    env = os.getenv("NAS_CONFIG_SYNC_ON_BOOT", "").strip().lower()
    if env in {"1", "true", "yes"}:
        return True
    if env in {"0", "false", "no"}:
        return False
    # Deploy scripts touch this stamp so the first app boot after pull
    # re-pushes MikroTiks even if the deploy-time sync ran before WireGuard.
    try:
        return os.path.exists(_nas_config_pending_path())
    except Exception:
        return False


def _run_nas_config_sync_once() -> None:
    """
    One-shot post-deploy NAS push (single winner across gunicorn workers).

    Deploy scripts also call ``sync_nas_config`` directly; this boot path
    covers the case where routers are only reachable after WireGuard comes up
    inside the app process.
    """
    if not _nas_config_sync_requested():
        return

    lock_path = _nas_config_pending_path() + ".lock"
    pending = _nas_config_pending_path()
    try:
        os.makedirs(os.path.dirname(pending), exist_ok=True)
        # Exclusive create — only one worker runs the fleet push.
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(lock_fd)
    except FileExistsError:
        return
    except Exception:
        logger.exception("NAS config sync lock failed")
        return

    try:
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        logger.info("NAS config sync starting (post-deploy / boot).")
        call_command("sync_nas_config", stdout=out, stderr=out)
        text = out.getvalue().strip()
        if text:
            for line in text.splitlines()[-8:]:
                logger.info("nas-sync: %s", line)
        try:
            if os.path.exists(pending):
                os.remove(pending)
        except Exception:
            pass
    except Exception:
        logger.exception("NAS config sync on boot failed")
    finally:
        try:
            if os.path.exists(lock_path):
                os.remove(lock_path)
        except Exception:
            pass


def start_runtime_tasks() -> None:
    """Idempotent: WireGuard sync, subscription sweep, and usage sampling."""
    global _started
    if _started or not should_start_runtime_tasks():
        return
    _started = True

    def _boot() -> None:
        _sync_wireguard()
        # After the tunnel is up, push any pending post-deploy NAS config.
        try:
            _run_nas_config_sync_once()
        except Exception:
            logger.exception("NAS config sync boot hook failed")
        _start_subscription_sweep_loop()
        _start_usage_sample_loop()

    threading.Thread(target=_boot, name="ispcentric-boot", daemon=True).start()
