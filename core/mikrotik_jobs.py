"""Track and run MikroTik background push jobs."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from django.core.cache import caches
from django.utils import timezone

logger = logging.getLogger(__name__)

JOB_TTL = 3600
NAS_REFRESH_JOB = "nas_refresh"
NAS_REFRESH_MAX_ATTEMPTS = 3
NAS_REFRESH_RETRY_DELAY_SEC = 4.0
NAS_REFRESH_VERIFY_ATTEMPTS = 3
NAS_REFRESH_VERIFY_DELAY_SEC = 3.0
NAS_REFRESH_POST_PUSH_SETTLE_SEC = 2.0
NAS_REFRESH_HARD_TIMEOUT_SEC = 180.0
NAS_REFRESH_STALE_SEC = 120.0
# Bond/failover/balance can flap WAN + tunnel for several minutes while reconnecting.
UPLINK_JOB_STALE_SEC = 600.0
UPLINK_JOB_TYPES = frozenset(
    {
        "uplink_bond",
        "uplink_failover",
        "uplink_balance",
        "uplink_smart_balance",
        "clean_uplink",
    }
)

JOB_TYPES = (
    "credentials",
    "wifi",
    "clean_uplink",
    "port_toggle",
    "port_role",
    "uplink_bond",
    "uplink_failover",
    "uplink_balance",
    "uplink_smart_balance",
    "pppoe_push",
    "hotspot_push",
    NAS_REFRESH_JOB,
)

_jobs_cache = caches["jobs"]


def job_cache_key(router_id: int, job_type: str) -> str:
    return f"mikrotik_job:{router_id}:{job_type}"


def _parse_job_timestamp(value: str) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timezone.is_naive(parsed):
        return timezone.make_aware(parsed)
    return parsed


def is_job_stale(job: dict[str, Any] | None, *, max_age_sec: float = NAS_REFRESH_STALE_SEC) -> bool:
    if not isinstance(job, dict):
        return True
    status = (job.get("status") or "").lower()
    if status not in {"pending", "running"}:
        return False
    stamp = _parse_job_timestamp(job.get("updated_at") or job.get("started_at") or "")
    if stamp is None:
        return True
    return (timezone.now() - stamp).total_seconds() > max_age_sec


def stale_max_age_for_job(job_type: str) -> float:
    if (job_type or "").strip() in UPLINK_JOB_TYPES:
        return UPLINK_JOB_STALE_SEC
    return NAS_REFRESH_STALE_SEC


def stale_error_for_job(job_type: str) -> tuple[str, str]:
    """Operator-facing (error, hint) when a background job stops updating."""
    kind = (job_type or "").strip()
    if kind == "uplink_bond":
        return (
            "Bond apply is taking longer than expected or the worker stopped updating. "
            "Management often flaps briefly while cables leave the LAN bridge — "
            "wait, then open MikroTik → Reconnect and retry Apply bonding if needed.",
            "Keep this page open. If the router stays offline, use Winbox on a customer LAN port.",
        )
    if kind in {"uplink_failover", "uplink_balance", "uplink_smart_balance"}:
        label = {
            "uplink_failover": "Failover",
            "uplink_balance": "Load balance",
            "uplink_smart_balance": "Multi-ISP",
        }.get(kind, "Uplink")
        return (
            f"{label} apply is taking longer than expected or the worker stopped updating. "
            "Management often flaps briefly while ISP cables leave the LAN bridge — "
            "wait, then open MikroTik → Reconnect and retry Apply if needed.",
            "Keep this page open. If the router stays offline, use Winbox on a customer LAN port.",
        )
    if kind in UPLINK_JOB_TYPES:
        return (
            "Uplink apply stopped responding. The MikroTik may still be reconnecting "
            "after changing WAN ports.",
            "Open MikroTik → Reconnect, then retry the uplink apply.",
        )
    return (
        "Billing settings push stopped responding. "
        "The MikroTik may be offline or the dev server reloaded mid-push.",
        "Open MikroTik → Reconnect, then retry onboarding or push Hotspot again.",
    )


def active_uplink_apply_job(router_id: int) -> dict[str, Any] | None:
    """Return the running uplink/bond job, if any (without marking it stale)."""
    for job_type in UPLINK_JOB_TYPES:
        payload = _jobs_cache.get(job_cache_key(router_id, job_type))
        if not isinstance(payload, dict):
            continue
        status = (payload.get("status") or "").lower()
        if status not in {"pending", "running"}:
            continue
        if is_job_stale(payload, max_age_sec=stale_max_age_for_job(job_type)):
            continue
        return {"job_type": job_type, **payload}
    return None


def set_job(
    router_id: int,
    job_type: str,
    status: str,
    *,
    message: str = "",
    error: str = "",
    hint: str = "",
    phase: str = "",
    started_at: str = "",
) -> None:
    """status: pending | running | ok | failed"""
    key = job_cache_key(router_id, job_type)
    existing = _jobs_cache.get(key)
    now = timezone.now().isoformat()
    payload = {
        "status": status,
        "message": message,
        "error": error,
        "hint": hint,
        "phase": phase,
        "updated_at": now,
        "started_at": started_at or (existing or {}).get("started_at") or now,
    }
    _jobs_cache.set(key, payload, JOB_TTL)


def summarize_mikrotik_job_error(result: dict[str, Any] | None) -> str:
    """Return the most useful operator-facing error from a MikroTik job result."""
    if not isinstance(result, dict):
        return "Could not apply settings on the MikroTik."

    explicit = (result.get("error") or "").strip()
    if explicit:
        return explicit

    for key in ("pppoe", "hotspot", "redirect"):
        sub = result.get(key)
        if isinstance(sub, dict):
            sub_err = (sub.get("error") or "").strip()
            if sub_err:
                return sub_err

    message = (result.get("message") or "").strip()
    if message:
        return message

    notes = result.get("notes") or []
    if notes:
        return "; ".join(str(note) for note in notes if note)

    return "Could not apply settings on the MikroTik."


def get_job(router_id: int, job_type: str) -> dict[str, Any] | None:
    payload = _jobs_cache.get(job_cache_key(router_id, job_type))
    if not isinstance(payload, dict):
        return None
    if is_job_stale(payload, max_age_sec=stale_max_age_for_job(job_type)):
        stale_error, stale_hint = stale_error_for_job(job_type)
        set_job(
            router_id,
            job_type,
            "failed",
            error=stale_error,
            hint=stale_hint,
            phase="stale",
        )
        return get_job(router_id, job_type)
    return payload


def get_router_jobs(router_id: int) -> dict[str, dict[str, Any]]:
    jobs: dict[str, dict[str, Any]] = {}
    for job_type in JOB_TYPES:
        payload = get_job(router_id, job_type)
        if payload:
            jobs[job_type] = payload
    return jobs


def clear_job(router_id: int, job_type: str) -> None:
    _jobs_cache.delete(job_cache_key(router_id, job_type))


def touch_job(
    router_id: int,
    job_type: str,
    *,
    message: str,
    phase: str = "",
) -> None:
    set_job(
        router_id,
        job_type,
        "running",
        message=message,
        phase=phase,
    )


def ensure_nas_refresh_job(router_pk: int) -> dict[str, Any]:
    """Start NAS refresh when the job is missing or was lost after a reload."""
    job = get_job(router_pk, NAS_REFRESH_JOB)
    if job:
        status = (job.get("status") or "").lower()
        if status in {"ok", "failed"}:
            return job
        if status in {"pending", "running"} and not is_job_stale(job):
            return job
    schedule_nas_refresh(router_pk)
    return get_job(router_pk, NAS_REFRESH_JOB) or {"status": "pending"}


def schedule_mikrotik_job(
    target: Callable[[], Any],
    *,
    name: str = "mikrotik-bg",
    router_id: int | None = None,
    job_type: str = "",
) -> None:
    """Run RouterOS work off the request thread so nginx does not 504."""

    def _runner() -> None:
        from django.db import close_old_connections, connection

        close_old_connections()
        stop_heartbeat = threading.Event()
        heartbeat: threading.Thread | None = None

        def _heartbeat_loop() -> None:
            while not stop_heartbeat.wait(25.0):
                if not router_id or not job_type:
                    return
                touch_job(
                    router_id,
                    job_type,
                    message="Still applying on the MikroTik — keep this page open…",
                    phase="working",
                )

        if router_id and job_type:
            touch_job(
                router_id,
                job_type,
                message="Starting background push…",
                phase="start",
            )
            if job_type in UPLINK_JOB_TYPES:
                heartbeat = threading.Thread(
                    target=_heartbeat_loop,
                    name=f"{name}-heartbeat",
                    daemon=True,
                )
                heartbeat.start()
        try:
            result = target()
            if router_id and job_type:
                if isinstance(result, dict) and result.get("ok") is False:
                    set_job(
                        router_id,
                        job_type,
                        "failed",
                        error=summarize_mikrotik_job_error(result),
                        hint=(result.get("hint") or "").strip(),
                        phase="failed",
                    )
                else:
                    message = ""
                    if isinstance(result, dict):
                        message = (result.get("message") or "").strip()
                    set_job(
                        router_id,
                        job_type,
                        "ok",
                        message=message or "Settings applied on the MikroTik.",
                        phase="done",
                    )
        except Exception:
            logger.exception("MikroTik background job %s failed", name)
            if router_id and job_type:
                set_job(
                    router_id,
                    job_type,
                    "failed",
                    error="Unexpected error while updating the MikroTik.",
                    phase="failed",
                )
        finally:
            stop_heartbeat.set()
            connection.close()

    threading.Thread(target=_runner, name=name, daemon=True).start()


def run_nas_refresh_with_retry(
    router,
    *,
    reauthenticate: bool = True,
    verify: bool = True,
    sync_pppoe_secrets: bool = True,
) -> dict[str, Any]:
    """Push NAS config with bounded retries and optional post-push API verification.

    Defaults to rewriting PPP secrets because this path is user-initiated
    (Reconnect / billing settings). Fleet deploy and the subscription sweep call
    ``refresh_onboarded_router_config`` directly with ``sync_pppoe_secrets=False``.
    """
    from core.mikrotik_connect import refresh_onboarded_router_config

    router_id = getattr(router, "pk", None)
    started = time.monotonic()

    def _timed_out() -> bool:
        return (time.monotonic() - started) > NAS_REFRESH_HARD_TIMEOUT_SEC

    def _progress(message: str, phase: str) -> None:
        if router_id:
            touch_job(router_id, NAS_REFRESH_JOB, message=message, phase=phase)

    last: dict[str, Any] = {"ok": False, "error": "NAS refresh did not run."}
    for attempt in range(1, NAS_REFRESH_MAX_ATTEMPTS + 1):
        if _timed_out():
            last = {
                "ok": False,
                "error": (
                    "Billing settings push timed out after "
                    f"{int(NAS_REFRESH_HARD_TIMEOUT_SEC)} seconds."
                ),
                "hint": (
                    "Check that the MikroTik is online, then use MikroTik → Reconnect "
                    "and try again."
                ),
            }
            break
        _progress(
            f"Applying billing settings (attempt {attempt}/{NAS_REFRESH_MAX_ATTEMPTS})…",
            "push",
        )
        last = refresh_onboarded_router_config(
            router,
            reauthenticate=reauthenticate,
            sync_pppoe_secrets=sync_pppoe_secrets,
        )
        if last.get("ok") or last.get("skipped"):
            break
        err = (last.get("error") or "").lower()
        if "absolute pay url" in err or "organization is required" in err:
            break
        if attempt < NAS_REFRESH_MAX_ATTEMPTS and not _timed_out():
            time.sleep(NAS_REFRESH_RETRY_DELAY_SEC)

    if verify and last.get("ok") and not last.get("skipped") and not _timed_out():
        from core.connectivity_verification import evaluate_nas_connectivity

        _progress("Verifying MikroTik management access…", "verify")
        if NAS_REFRESH_POST_PUSH_SETTLE_SEC > 0:
            time.sleep(NAS_REFRESH_POST_PUSH_SETTLE_SEC)

        notes = list(last.get("notes") or [])
        check: dict[str, Any] = {"ok": False}
        for attempt in range(1, NAS_REFRESH_VERIFY_ATTEMPTS + 1):
            if _timed_out():
                last["ok"] = False
                last["error"] = (
                    "Billing settings were pushed but verification timed out."
                )
                last["hint"] = (
                    "Wait 30 seconds, open MikroTik → Reconnect, then check status again."
                )
                break
            check = evaluate_nas_connectivity(router, timeout=4.0)
            if check.get("ok"):
                notes.append("management verified")
                last["message"] = "; ".join(notes) if notes else last.get("message", "")
                last["notes"] = notes
                break
            if attempt < NAS_REFRESH_VERIFY_ATTEMPTS:
                time.sleep(NAS_REFRESH_VERIFY_DELAY_SEC)
        else:
            last["ok"] = False
            last["error"] = (
                check.get("error") or "Post-push management verification failed."
            )
            hint = (check.get("hint") or "").strip()
            if hint:
                last["hint"] = hint
                last["error"] = f"{last['error']} {hint}".strip()
            notes.append(last["error"])
            last["notes"] = notes

    return last


def schedule_nas_refresh(
    router_pk: int,
    *,
    reauthenticate: bool = True,
    on_complete: Callable[[], None] | None = None,
) -> None:
    """Push PPPoE/Hotspot stack to one router in the background."""
    set_job(
        router_pk,
        NAS_REFRESH_JOB,
        "pending",
        message="Queued billing settings push…",
        phase="queued",
    )

    def _bg_refresh_nas() -> dict[str, Any]:
        from core.models import MikroTikRouter

        try:
            live = MikroTikRouter.objects.select_related("organization").get(pk=router_pk)
            return run_nas_refresh_with_retry(live, reauthenticate=reauthenticate)
        finally:
            if on_complete:
                on_complete()

    schedule_mikrotik_job(
        _bg_refresh_nas,
        name=f"nas-refresh-{router_pk}",
        router_id=router_pk,
        job_type=NAS_REFRESH_JOB,
    )


def schedule_post_onboard_nas_refresh(
    router,
    *,
    organization_id: int,
    user_id: int | None = None,
    tunnel: bool = False,
) -> None:
    """Keep onboarding guard active until the first NAS push finishes."""
    from core.mikrotik_status_samples import (
        clear_mikrotik_onboarding_active,
        mark_mikrotik_post_onboard_grace,
    )

    router_pk = router.pk

    def _on_complete() -> None:
        clear_mikrotik_onboarding_active(
            organization_id, user_id=user_id, org_wide=True
        )
        mark_mikrotik_post_onboard_grace(router_pk, tunnel=tunnel)
        caches["default"].delete_many(
            [
                f"mikrotik_discover:{organization_id}:quick",
                f"mikrotik_discover:{organization_id}:full",
                f"mikrotik_status:{organization_id}",
            ]
        )

    schedule_nas_refresh(router_pk, on_complete=_on_complete)
