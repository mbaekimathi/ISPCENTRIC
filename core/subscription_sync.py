"""Push subscription access to MikroTik without blocking callers longer than one NAS restore."""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

# Cross-process locks so gunicorn workers + the systemd timer never rewrite the
# same MikroTik fleet at once (partial secret/user updates = some clients offline).
_SWEEP_LOCK_NAME = "subscription_sweep_lock"
_EXPIRY_WATCH_LOCK_NAME = "subscription_expiry_watch_lock"
_FLEET_READ_LOCK_NAME = "mikrotik_fleet_read_lock"


def _jobs_cache():
    """File-backed cache shared across workers (even when default is locmem)."""
    from django.core.cache import caches

    try:
        return caches["jobs"]
    except Exception:
        from django.core.cache import cache

        return cache


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    # Windows: signal 0 is not a valid existence probe (often WinError 87).
    if os.name == "nt":
        try:
            import ctypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid)
            )
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            # Prefer "alive" so we never steal a live holder's lock.
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we cannot signal it — treat as alive.
        return True
    except OSError:
        return False
    return True


def try_acquire_subscription_sweep_lock(*, ttl_sec: int = 600) -> bool:
    """
    True when this process should run a full subscription/NAS sweep.

    Uses the jobs FileBasedCache so locks work across gunicorn workers and the
    systemd oneshot timer. Stale locks expire via TTL if a process dies mid-run;
    locks whose stored PID is already dead are stolen immediately (Ctrl+C / kill).

    Also used by ``sync_nas_config`` and the near-deadline expiry watch so only
    one fleet writer touches MikroTiks at a time.
    """
    ttl = max(60, int(ttl_sec))
    cache = _jobs_cache()
    try:
        if cache.add(_SWEEP_LOCK_NAME, os.getpid(), timeout=ttl):
            return True
        holder = cache.get(_SWEEP_LOCK_NAME)
        try:
            holder_pid = int(holder)
        except (TypeError, ValueError):
            holder_pid = 0
        if holder_pid and not _pid_is_alive(holder_pid):
            cache.delete(_SWEEP_LOCK_NAME)
            return bool(cache.add(_SWEEP_LOCK_NAME, os.getpid(), timeout=ttl))
        return False
    except Exception:
        logger.exception("subscription sweep lock acquire failed")
        # Fail open only if cache is broken — better a rare race than no expiry.
        return True


def release_subscription_sweep_lock() -> None:
    try:
        holder = _jobs_cache().get(_SWEEP_LOCK_NAME)
        try:
            holder_pid = int(holder)
        except (TypeError, ValueError):
            holder_pid = 0
        # Only the owner (or a dead-PID leftover) should clear the lock.
        if holder_pid in (0, os.getpid()) or (
            holder_pid and not _pid_is_alive(holder_pid)
        ):
            _jobs_cache().delete(_SWEEP_LOCK_NAME)
    except Exception:
        logger.exception("subscription sweep lock release failed")


def force_clear_subscription_sweep_lock() -> None:
    """Admin/test override — delete the lock even when another PID holds it."""
    try:
        _jobs_cache().delete(_SWEEP_LOCK_NAME)
    except Exception:
        logger.exception("subscription sweep lock force-clear failed")


def try_acquire_expiry_watch_lock(*, ttl_sec: int = 25) -> bool:
    """
    Near-deadline / paid-repair watch.

    Shares the fleet sweep lock so deploy + full sweep + expiry never rewrite
    the same MikroTiks concurrently.
    """
    return try_acquire_subscription_sweep_lock(ttl_sec=max(30, int(ttl_sec)))


def release_expiry_watch_lock() -> None:
    release_subscription_sweep_lock()


def is_fleet_write_active() -> bool:
    """True while subscription sweep / expiry watch is rewriting MikroTiks."""
    try:
        holder = _jobs_cache().get(_SWEEP_LOCK_NAME)
        if holder is None:
            return False
        try:
            holder_pid = int(holder)
        except (TypeError, ValueError):
            return True
        return bool(holder_pid) and _pid_is_alive(holder_pid)
    except Exception:
        return False


def try_acquire_fleet_read_lock(*, ttl_sec: int = 240, label: str = "") -> bool:
    """
    Serialize background read fleet jobs (usage sampling, status sampling,
    smart-balance monitor) so they do not hammer the same routers at once.
    """
    ttl = max(60, int(ttl_sec))
    cache = _jobs_cache()
    token = f"{label or 'read'}:{os.getpid()}"
    try:
        if cache.add(_FLEET_READ_LOCK_NAME, token, timeout=ttl):
            return True
        if is_fleet_write_active():
            return False
        holder = cache.get(_FLEET_READ_LOCK_NAME)
        if isinstance(holder, str) and ":" in holder:
            try:
                holder_pid = int(holder.rsplit(":", 1)[-1])
            except ValueError:
                holder_pid = 0
            if holder_pid and not _pid_is_alive(holder_pid):
                cache.delete(_FLEET_READ_LOCK_NAME)
                return bool(cache.add(_FLEET_READ_LOCK_NAME, token, timeout=ttl))
        return False
    except Exception:
        logger.exception("fleet read lock acquire failed")
        return True


def release_fleet_read_lock() -> None:
    try:
        cache = _jobs_cache()
        holder = cache.get(_FLEET_READ_LOCK_NAME)
        token_suffix = f":{os.getpid()}"
        if isinstance(holder, str) and holder.endswith(token_suffix):
            cache.delete(_FLEET_READ_LOCK_NAME)
    except Exception:
        logger.exception("fleet read lock release failed")


def should_skip_background_router_dial() -> bool:
    """Background jobs should not dial routers during a fleet write."""
    return is_fleet_write_active()


def acquire_subscription_sweep_lock_with_retry(
    *,
    ttl_sec: int = 600,
    attempts: int = 6,
    wait_sec: float = 5.0,
) -> bool:
    """Wait briefly for the fleet lock (deploy / NAS sync)."""
    for attempt in range(max(1, int(attempts))):
        if try_acquire_subscription_sweep_lock(ttl_sec=ttl_sec):
            return True
        if attempt + 1 < attempts:
            time.sleep(max(0.5, float(wait_sec)))
    return False


def nas_access_ready(result: dict[str, Any] | None) -> bool:
    """True when the ISP NAS can let this customer surf (CPE popup may still lag)."""
    if not result or not result.get("allowed"):
        return False
    if result.get("ok"):
        return True
    provision = result.get("provision")
    if isinstance(provision, dict) and provision.get("ok") and not provision.get("skipped"):
        return True
    return False


def enqueue_customer_subscription_sync(
    customer_pk: int,
    provision: bool,
    *,
    wait_first: bool = False,
    quick: bool = False,
    reauthenticate: bool = True,
) -> dict[str, Any] | None:
    """
    Sync package access to the NAS.

    ``wait_first=True`` runs one restore on this thread (cash recharge, voucher
    redeem, pause/resume) so surfing can start immediately. ``quick=True`` skips
    extra CPE retries on that first pass; a short background follow-up finishes
    the CPE renew clear after the CPE redials.
    """
    from billing.models import Customer
    from core.mikrotik_connect import (
        cpe_renew_clear_is_pending,
        cpe_renew_enable_is_pending,
        sync_customer_subscription_access,
    )

    result: dict[str, Any] | None = None

    def _run_once(cust, *, quick_pass: bool) -> dict[str, Any]:
        return sync_customer_subscription_access(
            cust,
            provision=provision,
            reauthenticate=reauthenticate,
            quick=quick_pass,
        )

    def _bg_sync(*, delay_first: float = 0.0) -> None:
        from django.db import connection

        try:
            if delay_first:
                time.sleep(delay_first)
            cust = Customer.objects.select_related(
                "plan", "router", "organization"
            ).get(pk=customer_pk)
            delays = (0.8, 1.5, 3.0, 6.0, 12.0)
            for attempt, delay in enumerate(delays, start=1):
                sync_result = sync_customer_subscription_access(
                    cust,
                    provision=provision,
                    reauthenticate=reauthenticate,
                    quick=False,
                )
                # Restore path: keep retrying while CPE renew clear is pending.
                if sync_result.get("allowed"):
                    if sync_result.get("ok") and not sync_result.get(
                        "cpe_renew_clear_pending"
                    ):
                        break
                    if not cpe_renew_clear_is_pending(cust) and sync_result.get("ok"):
                        break
                else:
                    # Pause / expiry block: keep retrying until the CPE pay/pause
                    # popup is installed (enable-pending clears on success).
                    portal = sync_result.get("portal") or {}
                    if portal.get("ok"):
                        break
                    if sync_result.get("ok") and not cpe_renew_enable_is_pending(cust):
                        break
                if attempt < len(delays):
                    time.sleep(delay)
                cust = Customer.objects.select_related(
                    "plan", "router", "organization"
                ).get(pk=customer_pk)
        except Exception:
            pass
        finally:
            connection.close()

    if wait_first:
        try:
            cust = Customer.objects.select_related(
                "plan", "router", "organization"
            ).get(pk=customer_pk)
            result = _run_once(cust, quick_pass=quick)
            if nas_access_ready(result):
                pending_cpe = bool(
                    result.get("cpe_renew_clear_pending")
                    or cpe_renew_clear_is_pending(cust)
                )
                if pending_cpe:
                    threading.Thread(
                        target=_bg_sync,
                        kwargs={"delay_first": 0.7},
                        daemon=True,
                    ).start()
                ready = dict(result)
                ready["ok"] = True
                return ready
            # Pause/expiry: NAS may be blocked while CPE popup is still pending.
            pending_enable = bool(
                result.get("cpe_renew_enable_pending")
                or cpe_renew_enable_is_pending(cust)
            )
            if pending_enable or not (result or {}).get("ok"):
                threading.Thread(
                    target=_bg_sync,
                    kwargs={"delay_first": 0.7},
                    daemon=True,
                ).start()
                return result
        except Exception:
            result = result or {"ok": False, "allowed": False}

    threading.Thread(target=_bg_sync, daemon=True).start()
    return result
