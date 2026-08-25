"""MikroTik health sampling and trend charts for the workspace dashboard."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any

from django.core.cache import cache
from django.utils import timezone

from core.models import MikroTikRouter, MikroTikStatusSample

_STATUS_SCORE = {
    "connected": 100,
    "reachable": 70,
    "limited": 55,
    "auth_failed": 25,
    "wrong_host": 10,
    "disconnected": 0,
}
_STATUS_REASON = {
    "connected": "Router is online and API login succeeded.",
    "reachable": (
        "Management ports answer, but API login was not confirmed "
        "(API flaky, timed out, or not fully verified)."
    ),
    "limited": (
        "Router answers ping, but API port 8728 is closed. "
        "Enable IP → Services → api (Allowed From empty) or re-paste the ISPCENTRIC tunnel script."
    ),
    "auth_failed": (
        "API port 8728 is open, but RouterOS rejected the saved username/password. "
        "Update credentials on the router detail page, then Reconnect."
    ),
    "wrong_host": "A different device now answers on this address.",
    "disconnected": "Router is offline or unreachable on the management tunnel or IP.",
}
# After TCP :8728 opens, classify login errors so timeouts are not blamed on passwords.
_AUTH_FAILURE_TOKENS = (
    "invalid user",
    "cannot log in",
    "bad name",
    "wrong password",
    "authentication failed",
    "check username",
    "check the saved",
    "check saved",
    "login failed",
)
_CONNECTIVITY_FAILURE_TOKENS = (
    "timed out",
    "timeout",
    "could not reach",
    "connection timed out",
    "connection failed",
    "refused",
    "unreachable",
    "no route",
    "forcibly closed",
    "reset by peer",
    "network is unreachable",
    "broken pipe",
    "unexpected reply",
)
_LIMITED_HINT = (
    "API :8728 closed — enable RouterOS API (IP → Services → api, Allowed From empty) "
    "or re-paste the ISPCENTRIC tunnel script."
)
_REACHABLE_HINT = (
    "API :8728 closed or login not confirmed — Winbox/HTTP may still answer. "
    "Enable IP → Services → api, or check tunnel stability."
)
# Includes soft degradation (reachable) so flaky API still bypasses the healthy gate.
_OUTAGE_STATUSES = frozenset(
    {"disconnected", "auth_failed", "wrong_host", "limited", "reachable"}
)
_SAMPLE_GATE_TTL = 55  # seconds between org-wide status sample writes
_OUTAGE_SAMPLE_GATE_TTL = 12  # allow outage transitions through sooner
_OUTAGE_CONFIRM_TTL = 90  # pending first-fail before chart drop is persisted
_HOSTED_AUTH_CACHE_TTL = 20  # seconds; short so password changes surface quickly
_TREND_CACHE_TTL = 20
# Do not pretend the last score held across silent gaps longer than this.
_MAX_FORWARD_FILL_BUCKETS = 2
_CHART_COLORS = [
    "#4f8cff",
    "#2ecc71",
    "#e8a317",
    "#e74c3c",
    "#9b59b6",
    "#1abc9c",
    "#f39c12",
    "#3498db",
    "#e67e22",
    "#16a085",
]


def status_score(status: str | None) -> int:
    key = (status or "disconnected").strip().lower()
    return int(_STATUS_SCORE.get(key, 0))


def status_catalog() -> dict[str, Any]:
    """Scores + reasons for dashboard JS (single source of truth)."""
    return {
        "scores": dict(_STATUS_SCORE),
        "reasons": dict(_STATUS_REASON),
        "outage_statuses": sorted(_OUTAGE_STATUSES),
    }


def is_credential_login_failure(error: str | None) -> bool:
    """
    True when an API login failure is a bad username/password.

    Timeouts, empty detail, and socket errors after a brief :8728 accept must
    not be reported as credential failures (Health → 25% with \"check password\").
    """
    text = (error or "").strip().lower()
    if not text:
        return False
    if any(token in text for token in _CONNECTIVITY_FAILURE_TOKENS):
        return False
    if any(token in text for token in _AUTH_FAILURE_TOKENS):
        return True
    return True


def status_after_api_probe(
    login: dict[str, Any] | None,
    *,
    via: str = "api",
) -> tuple[str, bool, str]:
    """
    Map an API-port probe + login attempt to (status, auth_ok, error).

    via=api and a connectivity-style / empty login error → reachable (not auth_failed).
    """
    login = login or {}
    if login.get("ok"):
        return "connected", True, ""
    error = (login.get("error") or "").strip()
    if not error:
        return "reachable", False, "API login was not confirmed."
    if is_credential_login_failure(error):
        return "auth_failed", False, error
    # Port looked open, then dial/login failed for network reasons.
    if via == "api":
        return "reachable", False, error
    return "limited", False, error


def status_reason(status: str | None, error: str | None = None) -> str:
    """Human-readable explanation for a MikroTik health status."""
    key = (status or "disconnected").strip().lower()
    reason = _STATUS_REASON.get(key, "Router health is degraded.")
    extra = (error or "").strip()
    if not extra or key == "connected":
        return reason
    # Prefer the specific probe error when it already explains the drop.
    extra_l = extra.lower()
    reason_l = reason.lower()
    if extra_l in reason_l or reason_l in extra_l:
        return reason if len(reason) >= len(extra) else extra
    # Avoid stacking \"check password\" on top of a timeout/reachability error.
    if key == "auth_failed" and not is_credential_login_failure(extra):
        return extra
    if key in {"limited", "reachable", "disconnected"} and any(
        token in extra_l for token in _CONNECTIVITY_FAILURE_TOKENS
    ):
        return extra if len(extra) >= 24 else f"{reason} {extra}"
    if extra_l not in reason_l:
        return f"{reason} {extra}"
    return reason


def classify_mikrotik_probe(
    probe: dict[str, Any] | None,
    *,
    host: str,
    username: str,
    password: str,
    serial_number: str = "",
    software_id: str = "",
    login: dict[str, Any] | None = None,
    skip_login: bool = False,
) -> dict[str, Any]:
    """
    Map a reachability probe (+ optional login) to a status row.

    Shared by the live status endpoint and the background sampler.
    """
    from core.mikrotik_connect import test_mikrotik_api_login

    probe = probe or {"online": False, "via": "", "error": ""}
    online = bool(probe.get("online"))
    via = (probe.get("via") or "").strip()
    status = "disconnected"
    auth_ok = False
    error = ""
    serial_number = (serial_number or "").strip()
    software_id = (software_id or "").strip()
    identity_login: dict[str, Any] | None = None

    if online and via == "api":
        if skip_login:
            auth_ok = True
            status = "connected"
        else:
            if login is None:
                login = test_mikrotik_api_login(
                    host,
                    username,
                    password or "",
                    timeout=2.0,
                    include_wifi=False,
                )
            status, auth_ok, error = status_after_api_probe(login, via=via)
            if auth_ok:
                identity_login = login
                live_serial = (login.get("serial_number") or "").strip()
                live_soft = (login.get("software_id") or "").strip()
                if live_serial:
                    serial_number = live_serial
                if live_soft:
                    software_id = live_soft
    elif online and via == "ping":
        status = "limited"
        error = _LIMITED_HINT
    elif online:
        status = "reachable"
        error = (probe.get("error") or "").strip() or _REACHABLE_HINT
    elif probe.get("foreign_http"):
        status = "wrong_host"
        error = probe.get("error") or "Another device answers on this address."
    elif probe.get("error"):
        error = probe["error"]

    return {
        "online": bool(auth_ok) if via == "api" else online and via != "ping",
        "reachable": online,
        "auth_ok": auth_ok,
        "manageable": bool(auth_ok),
        "status": status,
        "via": via,
        "error": error,
        "serial_number": serial_number,
        "software_id": software_id,
        "_login": identity_login,
    }


def _last_status_cache_key(organization_id: int, router_id: int) -> str:
    return f"mikrotik_status_last:{organization_id}:{router_id}"


def _last_score_cache_key(organization_id: int, router_id: int) -> str:
    return f"mikrotik_status_last_score:{organization_id}:{router_id}"


def _pending_outage_cache_key(organization_id: int, router_id: int) -> str:
    return f"mikrotik_status_pending_outage:{organization_id}:{router_id}"


def last_recorded_score(organization_id: int, router_id: int) -> int:
    """Last persisted health score for live “Why it dropped” from→to lines."""
    cached = cache.get(_last_score_cache_key(organization_id, router_id))
    if cached is not None:
        try:
            return int(cached)
        except (TypeError, ValueError):
            pass
    previous = cache.get(_last_status_cache_key(organization_id, router_id))
    if previous:
        return status_score(previous)
    return 100


def _confirmed_status_for_sample(
    organization_id: int,
    router_id: int,
    status: str,
    previous_status: str | None,
) -> str | None:
    """
    Debounce connected→degraded chart drops: require two consecutive failing
    observations before persisting. Live UI still shows the first fail.
    Returns None to skip writing this router on this tick.
    """
    pending_key = _pending_outage_cache_key(organization_id, router_id)
    score = status_score(status)

    if status == "connected" or score >= 100:
        cache.delete(pending_key)
        return status

    prev = (previous_status or "").strip().lower() or None
    if prev and prev != "connected" and status_score(prev) < 100:
        # Already degraded in the last recorded sample — record freely.
        cache.delete(pending_key)
        return status

    pending = cache.get(pending_key)
    if isinstance(pending, dict) and pending.get("status"):
        cache.delete(pending_key)
        return status

    cache.set(pending_key, {"status": status}, _OUTAGE_CONFIRM_TTL)
    return None


def record_mikrotik_status_samples(organization, routers: list[dict[str, Any]]) -> int:
    """
    Persist one health sample per router from a mikrotik_status payload.

    Gated so dashboard polling cannot flood the database. Outages and
    per-router status transitions always bypass the healthy gate so the
    trend drops (and recovers) immediately. Connected→outage transitions
    require two consecutive fails before a sample is written.
    """
    if not organization or not routers:
        return 0

    org_id = organization.pk
    has_outage = False
    has_transition = False
    confirmed_rows: list[tuple[dict[str, Any], str]] = []

    for row in routers:
        rid = row.get("id")
        if rid is None:
            continue
        rid_int = int(rid)
        status = (row.get("status") or "disconnected").strip().lower()
        previous = cache.get(_last_status_cache_key(org_id, rid_int))
        confirmed = _confirmed_status_for_sample(org_id, rid_int, status, previous)
        if confirmed is None:
            continue
        if confirmed in _OUTAGE_STATUSES:
            has_outage = True
        if previous is not None and previous != confirmed:
            has_transition = True
        confirmed_rows.append((row, confirmed))

    if not confirmed_rows:
        return 0

    gate = f"mikrotik_status_sample_gate:{org_id}"
    # Healthy steady-state polls stay gated; outages / transitions bypass so
    # the chart does not keep forward-filling the last Connected score.
    if cache.get(gate) and not has_outage and not has_transition:
        return 0
    cache.set(
        gate,
        1,
        _OUTAGE_SAMPLE_GATE_TTL if (has_outage or has_transition) else _SAMPLE_GATE_TTL,
    )

    now = timezone.now()
    router_ids = {int(row["id"]) for row, _ in confirmed_rows if row.get("id") is not None}
    if not router_ids:
        return 0
    known = set(
        MikroTikRouter.objects.filter(
            organization=organization, pk__in=router_ids
        ).values_list("id", flat=True)
    )
    rows = []
    for row, status in confirmed_rows:
        rid = row.get("id")
        if rid is None or int(rid) not in known:
            continue
        rid_int = int(rid)
        error = (row.get("error") or "").strip()[:255]
        score = status_score(status)
        rows.append(
            MikroTikStatusSample(
                organization=organization,
                router_id=rid_int,
                sampled_at=now,
                status=status[:32],
                score=score,
                online=bool(row.get("online")) or status == "connected",
                error=error,
            )
        )
        cache.set(_last_status_cache_key(org_id, rid_int), status, 60 * 60 * 6)
        cache.set(_last_score_cache_key(org_id, rid_int), score, 60 * 60 * 6)
    if not rows:
        return 0
    MikroTikStatusSample.objects.bulk_create(rows, batch_size=100)
    # Drop history older than 7 days so the table stays lean.
    MikroTikStatusSample.objects.filter(
        organization=organization,
        sampled_at__lt=now - timedelta(days=7),
    ).delete()
    cache.delete(f"mikrotik_perf_trend:{organization.pk}:24")
    cache.delete(f"mikrotik_perf_trend:{organization.pk}:6")
    return len(rows)


def collect_organization_status_payload(organization) -> list[dict[str, Any]]:
    """
    Probe every active MikroTik for an organization and return status rows.

    Shared by the dashboard status endpoint and the background sampler so
    outages are recorded even when nobody has /app/ open.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from core.mikrotik_connect import check_mikrotik_reachable

    routers = list(
        MikroTikRouter.objects.filter(
            organization=organization,
            account_status=MikroTikRouter.AccountStatus.ACTIVE,
        ).only(
            "id",
            "host",
            "name",
            "username",
            "password",
            "serial_number",
            "software_id",
            "vpn_address",
        )
    )
    if not routers:
        return []

    unique_hosts = list(
        dict.fromkeys(
            router.api_host for router in routers if (router.api_host or "").strip()
        )
    )
    probe_by_host: dict[str, dict] = {}

    def _probe_host(host: str):
        return host, check_mikrotik_reachable(host, timeout=1.2)

    workers = min(8, max(1, len(unique_hosts)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_probe_host, host) for host in unique_hosts]
        for future in as_completed(futures):
            try:
                host, probe = future.result()
                probe_by_host[host] = probe
            except Exception:
                continue

    results: dict[int, dict[str, Any]] = {}

    def _check(router: MikroTikRouter):
        host = (router.api_host or "").strip()
        probe = probe_by_host.get(host) or {"online": False, "via": "", "error": ""}
        classified = classify_mikrotik_probe(
            probe,
            host=host,
            username=router.username or "",
            password=router.password or "",
            serial_number=(router.serial_number or "").strip(),
            software_id=(router.software_id or "").strip(),
        )
        classified.pop("_login", None)
        return router.id, {
            "id": router.id,
            "host": router.host,
            "name": router.name,
            **classified,
        }

    workers = min(8, max(1, len(routers)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check, router) for router in routers]
        for future in as_completed(futures):
            try:
                router_id, payload = future.result()
                results[router_id] = payload
            except Exception:
                continue

    payload = []
    for router in routers:
        payload.append(
            results.get(
                router.id,
                {
                    "id": router.id,
                    "host": router.host,
                    "name": router.name,
                    "online": False,
                    "status": "disconnected",
                    "via": "",
                    "serial_number": (router.serial_number or "").strip(),
                    "software_id": (router.software_id or "").strip(),
                },
            )
        )
    return payload


def sample_all_organizations() -> dict[str, int]:
    """Probe every org with MikroTiks and persist health samples."""
    from accounts.models import Organization

    orgs = (
        Organization.objects.filter(mikrotik_routers__isnull=False)
        .distinct()
        .order_by("id")
    )
    written = 0
    probed = 0
    for org in orgs:
        payload = collect_organization_status_payload(org)
        probed += len(payload)
        if not payload:
            continue
        # Background sampler always records — clear the gate so steady-state
        # healthy ticks still land about once a minute from the scheduled job.
        cache.delete(f"mikrotik_status_sample_gate:{org.pk}")
        written += record_mikrotik_status_samples(org, payload)
        cache.set(f"mikrotik_status:{org.pk}", payload, 5)
    return {"organizations": orgs.count(), "routers": probed, "samples": written}


def _bucket_seconds(hours: int) -> int:
    if hours <= 6:
        return 10 * 60
    if hours <= 24:
        return 30 * 60
    return 60 * 60


def mikrotik_performance_trend(
    organization, *, hours: int = 24, live_routers: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Multi-series Chart.js payload: one line per MikroTik health score."""
    if not organization:
        return {
            "ok": False,
            "hours": hours,
            "labels": [],
            "datasets": [],
            "routers": [],
            "average": [],
        }

    hours = max(1, min(int(hours or 24), 168))
    cache_key = f"mikrotik_perf_trend:{organization.pk}:{hours}"
    cached = cache.get(cache_key)
    if cached is not None and not live_routers:
        return cached

    now = timezone.now()
    since = now - timedelta(hours=hours)
    bucket_secs = _bucket_seconds(hours)
    window_start = int(since.timestamp() // bucket_secs) * bucket_secs
    window_end = int(now.timestamp() // bucket_secs) * bucket_secs
    bucket_keys = list(range(window_start, window_end + bucket_secs, bucket_secs))
    if not bucket_keys:
        bucket_keys = [window_start]

    routers = list(
        MikroTikRouter.objects.filter(organization=organization)
        .only("id", "name", "host")
        .order_by("name")
    )
    router_meta = {
        r.pk: {"id": r.pk, "name": r.name, "host": r.host or ""} for r in routers
    }

    samples = list(
        MikroTikStatusSample.objects.filter(
            organization=organization,
            sampled_at__gte=since,
        )
        .order_by("sampled_at")
        .values("router_id", "sampled_at", "score", "status")[:12000]
    )

    # bucket -> router_id -> last score in that bucket
    by_bucket: dict[int, dict[int, int]] = {k: {} for k in bucket_keys}
    for row in samples:
        rid = int(row["router_id"])
        stamp = row["sampled_at"]
        bucket = int(stamp.timestamp() // bucket_secs) * bucket_secs
        if bucket < window_start:
            bucket = window_start
        if bucket > window_end:
            bucket = window_end
        by_bucket.setdefault(bucket, {})[rid] = int(row["score"] or 0)

    # Seed the latest bucket with live status so the chart moves immediately.
    if live_routers:
        latest_bucket = bucket_keys[-1]
        for row in live_routers:
            rid = row.get("id")
            if rid is None:
                continue
            rid = int(rid)
            if rid not in router_meta:
                continue
            status = (row.get("status") or "disconnected").strip().lower()
            by_bucket.setdefault(latest_bucket, {})[rid] = status_score(status)

    labels: list[str] = []
    for key in bucket_keys:
        stamp = timezone.localtime(datetime.fromtimestamp(key, tz=dt_timezone.utc))
        labels.append(stamp.strftime("%H:%M" if hours <= 48 else "%b %d %H:%M"))

    datasets = []
    for idx, router in enumerate(routers):
        series = []
        last = None
        fill_age = 0
        for key in bucket_keys:
            value = by_bucket.get(key, {}).get(router.pk)
            if value is None:
                # Cap forward-fill so long silent gaps show as holes instead of
                # a fake flat "Connected" line across hours with no probes.
                if last is not None and fill_age < _MAX_FORWARD_FILL_BUCKETS:
                    series.append(last)
                    fill_age += 1
                else:
                    series.append(None)
                    if fill_age >= _MAX_FORWARD_FILL_BUCKETS:
                        last = None
            else:
                last = value
                fill_age = 0
                series.append(value)
        color = _CHART_COLORS[idx % len(_CHART_COLORS)]
        datasets.append(
            {
                "label": router.name,
                "router_id": router.pk,
                "data": series,
                "borderColor": color,
                "backgroundColor": color + "33",
                "tension": 0.3,
                "spanGaps": True,
                "pointRadius": 0 if len(bucket_keys) > 40 else 2,
                "borderWidth": 2,
            }
        )

    average = []
    for i, key in enumerate(bucket_keys):
        vals = [
            ds["data"][i]
            for ds in datasets
            if ds["data"][i] is not None
        ]
        average.append(round(sum(vals) / len(vals), 1) if vals else None)

    if datasets:
        datasets.insert(
            0,
            {
                "label": "Average",
                "router_id": None,
                "data": average,
                "borderColor": "#0b1f2a",
                "backgroundColor": "rgba(11,31,42,0.08)",
                "tension": 0.25,
                "spanGaps": True,
                "pointRadius": 0,
                "borderWidth": 2.5,
                "borderDash": [6, 4],
            },
        )

    outage_buckets = 0
    for key in bucket_keys:
        scores = by_bucket.get(key) or {}
        if any(score < 100 for score in scores.values()):
            outage_buckets += 1

    payload = {
        "ok": True,
        "hours": hours,
        "labels": labels,
        "datasets": datasets,
        "routers": list(router_meta.values()),
        "average": average,
        "sample_count": len(samples),
        "outage_buckets": outage_buckets,
    }
    cache.set(cache_key, payload, _TREND_CACHE_TTL)
    return payload


def mikrotik_performance_drops(
    organization,
    *,
    hours: int = 24,
    live_routers: list[dict[str, Any]] | None = None,
    max_events: int = 8,
) -> dict[str, Any]:
    """Explain MikroTik health drops over the window, plus any live outages."""
    empty = {"ok": False, "hours": hours, "events": [], "current_count": 0}
    if not organization:
        return empty

    hours = max(1, min(int(hours or 24), 168))
    now = timezone.now()
    since = now - timedelta(hours=hours)
    routers = {
        r.pk: {"id": r.pk, "name": r.name, "host": r.host or ""}
        for r in MikroTikRouter.objects.filter(organization=organization)
        .only("id", "name", "host")
        .order_by("name")
    }
    samples = list(
        MikroTikStatusSample.objects.filter(
            organization=organization,
            sampled_at__gte=since,
        )
        .order_by("router_id", "sampled_at")
        .values("router_id", "sampled_at", "score", "status", "error")[:12000]
    )

    previous: dict[int, dict[str, Any]] = {}
    historical: list[dict[str, Any]] = []
    for row in samples:
        rid = int(row["router_id"])
        if rid not in routers:
            continue
        score = int(row["score"] or 0)
        status = (row["status"] or "disconnected").strip().lower()
        error = (row.get("error") or "").strip()
        prev = previous.get(rid)
        if prev and score < int(prev["score"]):
            stamp = row["sampled_at"]
            # Collapse repeated drops into the same status for one router.
            if (
                historical
                and historical[-1]["router_id"] == rid
                and historical[-1]["status"] == status
            ):
                historical[-1]["to_score"] = score
                historical[-1]["at"] = timezone.localtime(stamp).strftime("%H:%M")
                historical[-1]["at_iso"] = stamp.isoformat()
                if error:
                    historical[-1]["reason"] = status_reason(status, error)
            else:
                historical.append(
                    {
                        "router_id": rid,
                        "router_name": routers[rid]["name"],
                        "host": routers[rid]["host"],
                        "at": timezone.localtime(stamp).strftime("%H:%M"),
                        "at_iso": stamp.isoformat(),
                        "from_score": int(prev["score"]),
                        "to_score": score,
                        "status": status,
                        "reason": status_reason(status, error),
                        "current": False,
                    }
                )
        previous[rid] = {"score": score, "status": status}

    current: list[dict[str, Any]] = []
    seen_current: set[int] = set()
    org_id = organization.pk
    for row in live_routers or []:
        rid = row.get("id")
        if rid is None:
            continue
        rid = int(rid)
        if rid not in routers or rid in seen_current:
            continue
        status = (row.get("status") or "disconnected").strip().lower()
        score = status_score(status)
        if score >= 100:
            continue
        seen_current.add(rid)
        from_score = last_recorded_score(org_id, rid)
        if from_score <= score:
            from_score = 100
        current.append(
            {
                "router_id": rid,
                "router_name": routers[rid]["name"],
                "host": routers[rid]["host"],
                "at": "Now",
                "at_iso": now.isoformat(),
                "from_score": from_score,
                "to_score": score,
                "status": status,
                "reason": status_reason(status, row.get("error")),
                "current": True,
            }
        )

    # Prefer live explanation when the same router is still down.
    historical = [
        event
        for event in historical
        if not (
            event["router_id"] in seen_current and event["status"]
            == next(
                (c["status"] for c in current if c["router_id"] == event["router_id"]),
                None,
            )
        )
    ]
    historical.reverse()
    events = (current + historical)[: max(1, int(max_events or 8))]
    return {
        "ok": True,
        "hours": hours,
        "events": events,
        "current_count": len(current),
    }
