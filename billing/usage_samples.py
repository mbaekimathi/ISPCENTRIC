"""Helpers for recording and aggregating customer usage samples."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any

from django.core.cache import cache
from django.utils import timezone

from billing.models import Customer, CustomerUsageSample, Payment

_UPTIME_PART = re.compile(r"(\d+)\s*([wdhms])", re.I)
_SAMPLE_MIN_INTERVAL = 25  # seconds between persisted samples per client
_OFFLINE_SAMPLE_MIN_INTERVAL = 300  # avoid flooding zeros when clients are offline
_ORG_SAMPLE_TTL = 45  # seconds between org-wide MikroTik sweeps
_ORG_PAYLOAD_TTL = 20  # seconds for aggregated chart payloads
_CLIENT_TREND_TTL = 20  # short cache for per-client chart payloads
_CLIENT_TREND_CACHE_VERSION = "v3"  # bump when payload shape changes
_CLIENT_TREND_MAX_POINTS = 48  # hard cap on chart buckets
_CLIENT_SAMPLE_CAP = 8000  # max rows scanned per client trend request
# Chart y-values for access presence: surfing / not surfing / disconnected
_SURF_STATE_SURFING = 2
_SURF_STATE_NOT_SURFING = 1
_SURF_STATE_DISCONNECTED = 0
_NETWORK_TREND_TTL = 20
_NETWORK_TREND_COLORS = [
    "#2ecc71",
    "#4f8cff",
    "#e8a317",
    "#e74c3c",
    "#9b59b6",
    "#1abc9c",
    "#f39c12",
    "#3498db",
    "#e67e22",
    "#16a085",
]
_ORG_SAMPLE_WORKERS = 4
_ORG_SAMPLE_ROUTER_TIMEOUT = 4.0
_MAX_USAGE_HOURS = 8760  # 1 year
_USAGE_RANGE_CACHE_HOURS = (6, 24, 72, 168, 720, 8760)


def clamp_usage_hours(hours, default: int = 72) -> int:
    try:
        value = int(hours if hours is not None else default)
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, _MAX_USAGE_HOURS))


def usage_range_label(hours: int) -> str:
    mapping = {
        6: "6 hours",
        24: "24 hours",
        72: "3 days",
        168: "7 days",
        720: "30 days",
        8760: "1 year",
    }
    hours = clamp_usage_hours(hours)
    if hours in mapping:
        return mapping[hours]
    if hours % 24 == 0:
        days = hours // 24
        return f"{days} day{'s' if days != 1 else ''}"
    return f"{hours} hour{'s' if hours != 1 else ''}"


def _chart_label_format(hours: int) -> str:
    if hours <= 48:
        return "%H:%M"
    if hours <= 168:
        return "%b %d %H:%M"
    if hours <= 720:
        return "%b %d"
    return "%b %Y"


def parse_uptime_seconds(raw: str | None) -> int:
    """Parse RouterOS uptime text (e.g. 1w2d3h4m5s) into seconds."""
    text = (raw or "").strip().lower()
    if not text:
        return 0
    if text.isdigit():
        return max(0, int(text))
    total = 0
    for amount, unit in _UPTIME_PART.findall(text):
        value = int(amount)
        if unit == "w":
            total += value * 7 * 24 * 3600
        elif unit == "d":
            total += value * 24 * 3600
        elif unit == "h":
            total += value * 3600
        elif unit == "m":
            total += value * 60
        else:
            total += value
    return max(0, total)


def _as_int(value, default=0) -> int:
    try:
        if value is None or value == "":
            return default
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def record_customer_usage_sample(
    customer: Customer, payload: dict[str, Any], *, force: bool = False
) -> bool:
    """
    Persist a live usage snapshot when enough time has passed since the last one.

    Returns True when a row was written. ``force=True`` bypasses write throttles
    (used when an operator opens/refreshes the analysis page).
    """
    if not customer or not customer.pk or not customer.organization_id:
        return False

    # Failed MikroTik probes must not be stored as "offline" — that poisons
    # presence charts and breaks counter continuity for real sessions.
    if payload.get("ok") is False:
        return False

    session_active = bool(payload.get("session_active"))
    bytes_in = _as_int(payload.get("bytes_in"))
    bytes_out = _as_int(payload.get("bytes_out"))
    # Skip empty offline probes — they drown real traffic history and break
    # counter continuity when treated as session resets.
    if not session_active and bytes_in == 0 and bytes_out == 0:
        throttle_key = f"usage_sample_offline:{customer.pk}"
        if not force and cache.get(throttle_key):
            return False
        # Still record a sparse offline marker for presence charts (throttled).
        interval = _OFFLINE_SAMPLE_MIN_INTERVAL
    else:
        throttle_key = f"usage_sample_throttle:{customer.pk}"
        interval = _SAMPLE_MIN_INTERVAL
        if not force and cache.get(throttle_key):
            return False

    now = timezone.now()
    uptime_seconds = parse_uptime_seconds(payload.get("uptime_raw") or "")
    if not uptime_seconds and session_active:
        uptime_seconds = parse_uptime_seconds(payload.get("uptime") or "")

    CustomerUsageSample.objects.create(
        customer=customer,
        organization_id=customer.organization_id,
        sampled_at=now,
        session_active=session_active,
        uptime_seconds=uptime_seconds if session_active else 0,
        download_bps=_as_int(payload.get("download_bps")),
        upload_bps=_as_int(payload.get("upload_bps")),
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        address=(payload.get("cpe_host") or payload.get("address") or "")[:64],
    )
    cache.set(throttle_key, 1, interval)
    if session_active:
        cache.set(f"usage_sample_offline:{customer.pk}", 1, _OFFLINE_SAMPLE_MIN_INTERVAL)
    _invalidate_client_usage_trend_cache(customer.pk)
    return True


def _invalidate_client_usage_trend_cache(customer_id: int) -> None:
    for hours in _USAGE_RANGE_CACHE_HOURS:
        cache.delete(f"client_usage_trend:{_CLIENT_TREND_CACHE_VERSION}:{customer_id}:{hours}")
        # Legacy key from before access-timeline payload.
        cache.delete(f"client_usage_trend:{customer_id}:{hours}")


def _offline_usage_payload() -> dict[str, Any]:
    """Sparse offline marker so every assigned client appears in org rankings."""
    return {
        "session_active": False,
        "bytes_in": 0,
        "bytes_out": 0,
        "download_bps": 0,
        "upload_bps": 0,
    }


def sample_organization_usage(organization, *, force: bool = False) -> dict[str, Any]:
    """
    Lightweight org-wide snapshot: one MikroTik call per router (no per-client
    monitor-traffic). Records samples for every assigned PPPoE / Hotspot client
    on reachable routers — active sessions plus throttled offline markers.

    Gated by cache so the general-usage page cannot hammer routers.
    """
    if not organization:
        return {"ok": False, "sampled": 0, "routers": 0, "skipped": True}

    gate_key = f"org_usage_sample_gate:{organization.pk}"
    if not force and cache.get(gate_key):
        return {
            "ok": True,
            "sampled": 0,
            "routers": 0,
            "skipped": True,
            "cached": True,
        }
    # Set the gate early so overlapping requests don't stampede routers.
    cache.set(gate_key, 1, _ORG_SAMPLE_TTL)

    from core.mikrotik_connect import (
        fetch_router_bulk_hotspot_usage,
        fetch_router_bulk_pppoe_usage,
    )
    from core.models import MikroTikRouter

    routers = list(
        MikroTikRouter.objects.filter(
            organization=organization,
            account_status=MikroTikRouter.AccountStatus.ACTIVE,
        ).only("id", "host", "username", "password", "account_status")
    )
    if not routers:
        return {"ok": True, "sampled": 0, "routers": 0, "skipped": False}

    customers = list(
        Customer.objects.filter(organization=organization)
        .exclude(service_type=Customer.ServiceType.STATIC)
        .select_related("router")
        .only(
            "id",
            "organization_id",
            "service_type",
            "pppoe_username",
            "hotspot_mac",
            "router_id",
        )
    )
    pppoe_by_router: dict[int, dict[str, Customer]] = {}
    hotspot_by_router: dict[int, dict[str, Customer]] = {}
    # Global MAC → customer so Hotspot gadgets are matched even when the
    # client has no assigned router, or is surfing on a different NAS.
    hotspot_by_mac: dict[str, Customer] = {}

    def _hotspot_macs(customer: Customer) -> list[str]:
        macs: list[str] = []
        primary = "".join(
            ch for ch in (customer.hotspot_mac or "") if ch.isalnum()
        ).upper()
        if len(primary) == 12:
            macs.append(primary)
        try:
            from billing.devices import hotspot_macs_for_customer

            for raw in hotspot_macs_for_customer(customer):
                compact = "".join(ch for ch in (raw or "") if ch.isalnum()).upper()
                if len(compact) == 12 and compact not in macs:
                    macs.append(compact)
        except Exception:
            pass
        return macs

    for customer in customers:
        router_id = customer.router_id
        if customer.service_type == Customer.ServiceType.PPPOE:
            if not router_id:
                continue
            key = (customer.pppoe_username or "").strip().lower()
            if key:
                bucket = pppoe_by_router.setdefault(router_id, {})
                bucket[key] = customer
                # Match NAS sessions stored with/without a leading +.
                if key.startswith("+"):
                    bucket.setdefault(key[1:], customer)
                elif key.isdigit():
                    bucket.setdefault(f"+{key}", customer)
        elif customer.service_type == Customer.ServiceType.HOTSPOT:
            macs = _hotspot_macs(customer)
            if not macs:
                continue
            for mac in macs:
                hotspot_by_mac[mac] = customer
            if router_id:
                bucket = hotspot_by_router.setdefault(router_id, {})
                for mac in macs:
                    bucket[mac] = customer

    def _probe(
        router: MikroTikRouter,
    ) -> tuple[int, bool, dict[str, dict[str, Any]], bool, dict[str, dict[str, Any]]]:
        pppoe_sessions: dict[str, dict[str, Any]] = {}
        hotspot_sessions: dict[str, dict[str, Any]] = {}
        pppoe_ok = False
        hotspot_ok = False
        pppoe_map = pppoe_by_router.get(router.pk) or {}
        if pppoe_map:
            result = fetch_router_bulk_pppoe_usage(
                router.host,
                router.username,
                router.password or "",
                timeout=_ORG_SAMPLE_ROUTER_TIMEOUT,
            )
            pppoe_ok = bool(result.get("ok"))
            if pppoe_ok:
                pppoe_sessions = result.get("sessions") or {}
        # Always probe Hotspot on every reachable router so unassigned / roaming
        # gadgets are still captured for usage trends.
        if hotspot_by_mac:
            result = fetch_router_bulk_hotspot_usage(
                router.host,
                router.username,
                router.password or "",
                timeout=_ORG_SAMPLE_ROUTER_TIMEOUT,
            )
            hotspot_ok = bool(result.get("ok"))
            if hotspot_ok:
                hotspot_sessions = result.get("sessions") or {}
        return router.pk, pppoe_ok, pppoe_sessions, hotspot_ok, hotspot_sessions

    sampled = 0
    matched_hotspot: set[int] = set()
    # Aggregate multi-MAC Hotspot clients (sum counters / max rates).
    hotspot_agg: dict[int, dict[str, Any]] = {}
    reachable_hotspot_routers: set[int] = set()
    workers = min(_ORG_SAMPLE_WORKERS, len(routers))
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(_probe, router) for router in routers]
        for future in as_completed(futures):
            try:
                router_id, pppoe_ok, pppoe_sessions, hotspot_ok, hotspot_sessions = (
                    future.result()
                )
            except Exception:
                continue

            if pppoe_ok:
                pppoe_map = pppoe_by_router.get(router_id) or {}
                matched: set[int] = set()
                for username, payload in pppoe_sessions.items():
                    customer = pppoe_map.get((username or "").strip().lower())
                    if not customer:
                        continue
                    try:
                        if record_customer_usage_sample(customer, payload):
                            sampled += 1
                    except Exception:
                        pass
                    matched.add(customer.pk)
                offline = _offline_usage_payload()
                for customer in pppoe_map.values():
                    if customer.pk in matched:
                        continue
                    try:
                        if record_customer_usage_sample(customer, offline):
                            sampled += 1
                    except Exception:
                        pass

            if hotspot_ok:
                reachable_hotspot_routers.add(router_id)
                for mac, payload in hotspot_sessions.items():
                    customer = hotspot_by_mac.get((mac or "").strip().upper())
                    if not customer:
                        continue
                    matched_hotspot.add(customer.pk)
                    total = int(payload.get("bytes_in") or 0) + int(
                        payload.get("bytes_out") or 0
                    )
                    stats = hotspot_agg.get(customer.pk)
                    # Keep the busiest gadget session so byte deltas stay stable.
                    if stats is None or total >= int(stats.get("total") or 0):
                        hotspot_agg[customer.pk] = {
                            "customer": customer,
                            "total": total,
                            "session_active": True,
                            "bytes_in": int(payload.get("bytes_in") or 0),
                            "bytes_out": int(payload.get("bytes_out") or 0),
                            "download_bps": int(payload.get("download_bps") or 0),
                            "upload_bps": int(payload.get("upload_bps") or 0),
                            "address": payload.get("address") or "",
                            "uptime_raw": payload.get("uptime_raw") or "",
                        }
                    else:
                        stats["download_bps"] = max(
                            int(stats["download_bps"] or 0),
                            int(payload.get("download_bps") or 0),
                        )
                        stats["upload_bps"] = max(
                            int(stats["upload_bps"] or 0),
                            int(payload.get("upload_bps") or 0),
                        )

    for stats in hotspot_agg.values():
        customer = stats["customer"]
        payload = {
            "ok": True,
            "session_active": True,
            "bytes_in": stats["bytes_in"],
            "bytes_out": stats["bytes_out"],
            "download_bps": stats["download_bps"] or None,
            "upload_bps": stats["upload_bps"] or None,
            "address": stats["address"],
            "uptime_raw": stats["uptime_raw"],
        }
        try:
            if record_customer_usage_sample(customer, payload):
                sampled += 1
        except Exception:
            pass

    # Offline markers only for Hotspot clients assigned to a router we reached —
    # unassigned clients simply stay silent when offline (no false presence).
    if reachable_hotspot_routers:
        offline = _offline_usage_payload()
        for router_id, cmap in hotspot_by_router.items():
            if router_id not in reachable_hotspot_routers:
                continue
            for customer in cmap.values():
                if customer.pk in matched_hotspot:
                    continue
                try:
                    if record_customer_usage_sample(customer, offline):
                        sampled += 1
                except Exception:
                    pass

    # Invalidate payload caches so the next read includes fresh samples.
    router_keys = ["all", "none"]
    if organization:
        router_keys.extend(
            str(rid)
            for rid in MikroTikRouter.objects.filter(organization=organization).values_list(
                "pk", flat=True
            )
        )
    for hours in _USAGE_RANGE_CACHE_HOURS:
        for top_n in (0, 25, 100, 200, 300):
            for service in ("all", "pppoe", "hotspot"):
                for router_key in router_keys:
                    cache.delete(
                        f"org_usage_payload:v4:{organization.pk}:{hours}:{top_n}:{service}:{router_key}"
                    )
                cache.delete(
                    f"org_usage_payload:v3:{organization.pk}:{hours}:{top_n}:{service}"
                )
            cache.delete(f"org_usage_payload:v2:{organization.pk}:{hours}:{top_n}")
            cache.delete(f"org_usage_payload:{organization.pk}:{hours}")
        cache.delete(f"router_network_trend:{organization.pk}:{hours}")

    return {
        "ok": True,
        "sampled": sampled,
        "routers": len(routers),
        "skipped": False,
    }


def _human_duration(seconds: float | int) -> str:
    total = max(0, int(seconds or 0))
    if total < 60:
        return f"{total}s"
    if total < 3600:
        mins = total // 60
        return f"{mins} min"
    hours = total // 3600
    mins = (total % 3600) // 60
    if mins:
        return f"{hours}h {mins}m"
    return f"{hours}h"


def _access_stamp_label(stamp, hours: int) -> str:
    local = timezone.localtime(stamp)
    if hours <= 48:
        return local.strftime("%b %d · %H:%M")
    if hours <= 720:
        return local.strftime("%b %d · %H:%M")
    return local.strftime("%b %d, %Y · %H:%M")


def _aware_local(stamp):
    if stamp is None:
        return None
    if timezone.is_naive(stamp):
        return timezone.make_aware(stamp, timezone.get_current_timezone())
    return stamp


def _normalize_package_start(start, plan) -> datetime | None:
    """Align calendar-package starts to local midnight (matches live access rules)."""
    from billing.services import plan_uses_clock_time

    start = _aware_local(start)
    if start is None:
        return None
    if plan_uses_clock_time(plan):
        return start
    start_day = timezone.localtime(start).date()
    return timezone.make_aware(
        datetime.combine(start_day, datetime.min.time()),
        timezone.get_current_timezone(),
    )


def _access_deadline_for_end(package_end, plan) -> datetime | None:
    """Exclusive cut-off for a stored package_end + plan (calendar vs clock)."""
    from billing.services import plan_uses_clock_time

    end = _aware_local(package_end)
    if end is None:
        return None
    if plan_uses_clock_time(plan):
        return end
    end_day = timezone.localtime(end).date()
    return timezone.make_aware(
        datetime.combine(end_day + timedelta(days=1), datetime.min.time()),
        timezone.get_current_timezone(),
    )


def _payment_plan_for_replay(payment, customer):
    """Prefer the STK plan that was paid for; fall back to the client's plan."""
    stks = getattr(payment, "stk_push_requests", None)
    if stks is not None:
        for stk in stks.all():
            plan = getattr(stk, "plan", None)
            if plan is not None:
                return plan
    return getattr(customer, "plan", None)


def _replay_one_subscription_payment(
    *,
    paid_at,
    plan,
    current_start,
    current_end,
) -> dict[str, Any] | None:
    """
    One ``apply_subscription_renewal`` step without saving.

    Stacks onto an active window; otherwise starts a fresh period from payment time.
    """
    from billing.services import compute_package_end

    paid_at = _aware_local(paid_at)
    if paid_at is None or plan is None:
        return None
    active_until = _access_deadline_for_end(current_end, plan)
    if active_until is not None and active_until > paid_at:
        calculation_start = current_end or active_until
        access_start = (
            current_start
            if current_start is not None and current_start <= paid_at
            else paid_at
        )
        fresh = False
    else:
        calculation_start = paid_at
        access_start = paid_at
        fresh = True
    package_end = compute_package_end(calculation_start, plan)
    if package_end is None:
        return None
    deadline = _access_deadline_for_end(package_end, plan)
    return {
        "start": _normalize_package_start(access_start, plan),
        "package_end": package_end,
        "deadline": deadline,
        "payment_at": paid_at,
        "fresh_start": fresh,
        "plan": plan,
    }


def _merge_access_windows(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge overlapping / contiguous prepaid intervals."""
    cleaned: list[dict[str, Any]] = []
    for win in windows:
        start = win.get("start")
        deadline = win.get("deadline")
        if start is None or deadline is None or deadline <= start:
            continue
        cleaned.append(
            {
                "start": start,
                "deadline": deadline,
                "package_end": win.get("package_end"),
                "fresh_start": bool(win.get("fresh_start")),
                "payment_at": win.get("payment_at"),
            }
        )
    if not cleaned:
        return []
    cleaned.sort(key=lambda w: (w["start"], w["deadline"]))
    merged = [dict(cleaned[0])]
    for win in cleaned[1:]:
        last = merged[-1]
        if win["start"] <= last["deadline"]:
            if win["deadline"] > last["deadline"]:
                last["deadline"] = win["deadline"]
                last["package_end"] = win.get("package_end") or last.get("package_end")
            # Keep earliest start / first fresh flag for the continuous block.
            continue
        merged.append(dict(win))
    return merged


def _subscription_windows_from_payments(
    customer: Customer, *, lookback_since, until
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Reconstruct prepaid windows from every successful payment.

    Returns ``(merged_windows, payment_steps)`` where ``payment_steps`` retains
    each pay-to-start / extension for the timeline.
    """
    org_id = getattr(customer, "organization_id", None)
    if not org_id:
        return [], []
    rows = list(
        Payment.objects.filter(
            organization_id=org_id,
            invoice__customer=customer,
            received_at__gte=lookback_since,
            received_at__lte=until,
        )
        .select_related("invoice")
        .prefetch_related("stk_push_requests__plan")
        .order_by("received_at", "pk")[:80]
    )
    current_start = None
    current_end = None
    steps: list[dict[str, Any]] = []
    for pay in rows:
        plan = _payment_plan_for_replay(pay, customer)
        step = _replay_one_subscription_payment(
            paid_at=pay.received_at,
            plan=plan,
            current_start=current_start,
            current_end=current_end,
        )
        if step is None:
            continue
        current_start = step["start"]
        current_end = step["package_end"]
        steps.append(step)
    return _merge_access_windows(steps), steps


def _package_access_bounds(customer) -> dict[str, Any]:
    """
    Package windows used to classify surfing vs blocked over time.

    Includes the live package on the customer plus historical windows rebuilt
    from each successful payment (expire → pay again, or stack while active).
    """
    from billing.services import subscription_access_deadline

    plan = getattr(customer, "plan", None)
    raw_start = getattr(customer, "package_start", None)
    raw_end = getattr(customer, "package_end", None)
    paused_at = _aware_local(getattr(customer, "package_paused_at", None))
    deadline = subscription_access_deadline(customer)
    start = _normalize_package_start(raw_start, plan)
    raw_end = _aware_local(raw_end)
    deadline = _aware_local(deadline)

    # Look far enough back that a 30-day usage chart still sees prior periods.
    until = timezone.now()
    lookback_since = until - timedelta(days=400)
    windows, payment_steps = _subscription_windows_from_payments(
        customer, lookback_since=lookback_since, until=until
    )
    if start is not None and deadline is not None:
        windows = _merge_access_windows(
            [
                *windows,
                {
                    "start": start,
                    "deadline": deadline,
                    "package_end": raw_end,
                    "fresh_start": True,
                },
            ]
        )
    elif start is not None or deadline is not None:
        # Incomplete live window — still expose for timeline labels.
        windows = _merge_access_windows(
            [
                *windows,
                {
                    "start": start or deadline,
                    "deadline": deadline or start,
                    "package_end": raw_end,
                    "fresh_start": True,
                },
            ]
        )

    return {
        "package_start": start,
        "package_end": raw_end,
        "access_deadline": deadline,
        "package_paused_at": paused_at,
        "has_package_end": raw_end is not None or bool(windows),
        "windows": windows,
        "payment_steps": payment_steps,
    }


def _surf_allowed_at(
    stamp,
    *,
    bounds: dict[str, Any],
    service_type: str,
) -> bool:
    """Whether any prepaid window would allow surfing at ``stamp``."""
    paused_at = bounds.get("package_paused_at")
    if paused_at is not None and stamp >= paused_at:
        return False
    windows = bounds.get("windows") or []
    if windows:
        for win in windows:
            start = win.get("start")
            deadline = win.get("deadline")
            if start is not None and stamp < start:
                continue
            if deadline is not None and stamp >= deadline:
                continue
            return True
        return False
    if service_type in {
        Customer.ServiceType.HOTSPOT,
        Customer.ServiceType.PPPOE,
    } and not bounds.get("has_package_end"):
        return False
    start = bounds.get("package_start")
    if start is not None and stamp < start:
        return False
    deadline = bounds.get("access_deadline")
    if deadline is not None and stamp >= deadline:
        return False
    if start is None and deadline is None:
        return True
    return True


def _classify_access_state(*, session_active: bool, surf_allowed: bool) -> str:
    """
    Support-facing presence:
    - surfing: dialed in and package allows internet
    - not_surfing: package blocks internet (expired / paused / unpaid)
    - disconnected: package allows surfing but no live session
    """
    if session_active and surf_allowed:
        return "surfing"
    if not surf_allowed:
        return "not_surfing"
    return "disconnected"


def _access_state_labels(state: str) -> tuple[str, str]:
    mapping = {
        "surfing": ("Surfing", "Connected with internet"),
        "not_surfing": ("Not surfing", "Blocked — cannot browse"),
        "disconnected": ("Disconnected", "Package active, no session"),
        "waiting": ("Waiting", "No readings yet"),
    }
    return mapping.get(state, ("—", "Current connection"))


def _surf_state_value(state: str | None) -> int | None:
    if state == "surfing":
        return _SURF_STATE_SURFING
    if state == "not_surfing":
        return _SURF_STATE_NOT_SURFING
    if state == "disconnected":
        return _SURF_STATE_DISCONNECTED
    return None


def _client_payment_events(customer: Customer, *, since, until, hours: int) -> list[dict[str, Any]]:
    """Successful payments that land in (or just before) the usage window."""
    org_id = getattr(customer, "organization_id", None)
    if not org_id:
        return []
    lookback = since - timedelta(days=2)
    rows = list(
        Payment.objects.filter(
            organization_id=org_id,
            invoice__customer=customer,
            received_at__gte=lookback,
            received_at__lte=until,
        )
        .select_related("invoice")
        .order_by("received_at")[:20]
    )
    events: list[dict[str, Any]] = []
    for pay in rows:
        stamp = pay.received_at
        if stamp is None:
            continue
        if timezone.is_naive(stamp):
            stamp = timezone.make_aware(stamp, timezone.get_current_timezone())
        in_window = stamp >= since
        amount = pay.amount
        amount_label = f"KES {amount}" if amount is not None else "Payment"
        method = (pay.get_method_display() if hasattr(pay, "get_method_display") else "") or "Payment"
        ref = (pay.reference or "").strip()
        events.append(
            {
                "kind": "payment",
                "label": "Payment received",
                "detail": f"{amount_label} · {method}"
                + (f" · {ref}" if ref else ""),
                "at": timezone.localtime(stamp).isoformat(),
                "at_label": _access_stamp_label(stamp, hours),
                "in_window": in_window,
                "tone": "payment",
            }
        )
    return events


def build_client_access_timeline(
    customer: Customer,
    *,
    hours: int,
    samples: list[dict[str, Any]] | None = None,
    now=None,
) -> dict[str, Any]:
    """
    Payment / subscription / block timeline for support on the usage page.

    Reconstructs surfing vs blocked across *every* prepaid window created by
    successful payments (including expire → pay again). Flags when the client
    dropped while a package was still active.
    """
    from billing.services import (
        customer_package_is_paused,
        customer_receives_internet,
        customer_subscription_expired,
    )

    hours = clamp_usage_hours(hours, default=24)
    now = now or timezone.now()
    if timezone.is_naive(now):
        now = timezone.make_aware(now, timezone.get_current_timezone())
    since = now - timedelta(hours=hours)
    bounds = _package_access_bounds(customer)
    service_type = (getattr(customer, "service_type", "") or "").strip()

    events = _client_payment_events(customer, since=since, until=now, hours=hours)

    package_start = bounds.get("package_start")
    package_end = bounds.get("package_end")
    deadline = bounds.get("access_deadline")
    paused_at = bounds.get("package_paused_at")
    windows = bounds.get("windows") or []
    payment_steps = bounds.get("payment_steps") or []

    # Prefer payment-step starts so each pay-to-start shows on the timeline;
    # fall back to merged windows when payments are missing.
    start_stamps: list = []
    seen_starts: set[str] = set()
    for step in payment_steps:
        if not step.get("fresh_start"):
            # Stacked top-up: package kept surfing; note the extension.
            stamp = step.get("payment_at")
            if stamp is None:
                continue
            if since <= stamp <= now:
                events.append(
                    {
                        "kind": "subscription_started",
                        "label": "Subscription extended",
                        "detail": (
                            "Another payment stacked onto the active package — "
                            "surfing continued without a gap."
                        ),
                        "at": timezone.localtime(stamp).isoformat(),
                        "at_label": _access_stamp_label(stamp, hours),
                        "in_window": True,
                        "tone": "start",
                        "extended": True,
                    }
                )
            continue
        stamp = step.get("start") or step.get("payment_at")
        if stamp is None:
            continue
        # Show starts that land in the chart, or that open a window still overlapping it.
        step_deadline = step.get("deadline")
        overlaps = since <= stamp <= now or (
            stamp < since and step_deadline is not None and step_deadline > since
        )
        if not overlaps:
            continue
        key = timezone.localtime(stamp).isoformat()
        if key in seen_starts:
            continue
        seen_starts.add(key)
        start_stamps.append(stamp)

    if not start_stamps:
        for win in windows:
            stamp = win.get("start")
            win_deadline = win.get("deadline")
            if stamp is None:
                continue
            overlaps = since <= stamp <= now or (
                stamp < since and win_deadline is not None and win_deadline > since
            )
            if not overlaps:
                continue
            key = timezone.localtime(stamp).isoformat()
            if key in seen_starts:
                continue
            seen_starts.add(key)
            start_stamps.append(stamp)

    for idx, stamp in enumerate(start_stamps):
        multi = len(start_stamps) > 1
        events.append(
            {
                "kind": "subscription_started",
                "label": (
                    f"Subscription started ({idx + 1} of {len(start_stamps)})"
                    if multi
                    else "Subscription started"
                ),
                "detail": (
                    "Package window began after payment — surfing allowed after this point."
                    if multi
                    else "Package window began — surfing allowed after this point."
                ),
                "at": timezone.localtime(stamp).isoformat(),
                "at_label": _access_stamp_label(stamp, hours),
                "in_window": since <= stamp <= now,
                "tone": "start",
            }
        )

    if paused_at is not None:
        before_end = bool(
            any(win.get("deadline") and paused_at < win["deadline"] for win in windows)
            or (deadline and paused_at < deadline)
        )
        events.append(
            {
                "kind": "blocked",
                "label": "Blocked (package paused)",
                "detail": (
                    "Staff paused the package — surfing stopped while time left was preserved."
                    if before_end
                    else "Package paused; surfing blocked."
                ),
                "at": timezone.localtime(paused_at).isoformat(),
                "at_label": _access_stamp_label(paused_at, hours),
                "in_window": since <= paused_at <= now,
                "tone": "blocked",
                "before_subscription_end": before_end,
            }
        )

    end_stamps: list = []
    seen_ends: set[str] = set()
    for win in windows:
        stamp = win.get("deadline")
        start = win.get("start")
        if stamp is None:
            continue
        # Keep ends for windows that overlap the chart, plus the live/upcoming cut-off.
        overlaps_chart = (start is None or start <= now) and stamp >= since
        if not overlaps_chart and not (stamp > now):
            continue
        key = timezone.localtime(stamp).isoformat()
        if key in seen_ends:
            continue
        seen_ends.add(key)
        end_stamps.append(stamp)

    if not end_stamps and deadline is not None:
        end_stamps.append(deadline)
    elif not end_stamps and package_end is not None:
        end_stamps.append(package_end)

    for idx, stamp in enumerate(end_stamps):
        ended = now >= stamp
        multi = len(end_stamps) > 1
        events.append(
            {
                "kind": "subscription_ended",
                "label": (
                    (
                        f"Subscription ended ({idx + 1} of {len(end_stamps)})"
                        if ended
                        else f"Subscription ends ({idx + 1} of {len(end_stamps)})"
                    )
                    if multi
                    else ("Subscription ended" if ended else "Subscription ends")
                ),
                "detail": (
                    "Access cut-off — surfing should stop at this time."
                    if ended
                    else "Scheduled access cut-off for this package period."
                ),
                "at": timezone.localtime(stamp).isoformat(),
                "at_label": _access_stamp_label(stamp, hours),
                "in_window": since <= stamp <= now or (not ended and stamp > now),
                "tone": "end",
                "future": not ended,
            }
        )

    early_offline = None
    blocked_while_connected = None
    if samples:
        prev_active: bool | None = None
        for row in samples:
            stamp = row.get("sampled_at")
            if stamp is None:
                continue
            if timezone.is_naive(stamp):
                stamp = timezone.make_aware(stamp, timezone.get_current_timezone())
            active = bool(row.get("session_active"))
            allowed = _surf_allowed_at(
                stamp, bounds=bounds, service_type=service_type
            )
            if active and not allowed and blocked_while_connected is None:
                blocked_while_connected = stamp
            if prev_active is True and not active and allowed and early_offline is None:
                # Dropped while a paid window still allowed surfing.
                early_offline = stamp
            prev_active = active

    if early_offline is not None:
        events.append(
            {
                "kind": "early_offline",
                "label": "Went offline while package active",
                "detail": (
                    "Session dropped before the subscription ended — useful when "
                    "the client says they were blocked early."
                ),
                "at": timezone.localtime(early_offline).isoformat(),
                "at_label": _access_stamp_label(early_offline, hours),
                "in_window": True,
                "tone": "warn",
                "before_subscription_end": True,
            }
        )
    if blocked_while_connected is not None:
        events.append(
            {
                "kind": "blocked_connected",
                "label": "Connected but unable to surf",
                "detail": (
                    "Session was up while billing blocked internet "
                    "(expired, paused, or unpaid)."
                ),
                "at": timezone.localtime(blocked_while_connected).isoformat(),
                "at_label": _access_stamp_label(blocked_while_connected, hours),
                "in_window": True,
                "tone": "blocked",
                "before_subscription_end": bool(
                    any(
                        win.get("deadline")
                        and blocked_while_connected < win["deadline"]
                        for win in windows
                    )
                    and not customer_subscription_expired(customer)
                ),
            }
        )

    def _sort_key(ev: dict[str, Any]):
        try:
            return datetime.fromisoformat(ev["at"])
        except Exception:
            return now

    events.sort(key=_sort_key)

    billing_allows = bool(customer_receives_internet(customer))
    paused = bool(customer_package_is_paused(customer))
    expired = bool(customer_subscription_expired(customer))
    latest_active = bool(samples[-1].get("session_active")) if samples else False
    current_state = (
        _classify_access_state(session_active=latest_active, surf_allowed=billing_allows)
        if samples
        else "waiting"
    )
    status, status_hint = _access_state_labels(current_state)

    alert = ""
    if early_offline is not None:
        alert = (
            f"Client went offline at {_access_stamp_label(early_offline, hours)} "
            "while the package was still active."
        )
    elif paused and paused_at and (
        any(win.get("deadline") and paused_at < win["deadline"] for win in windows)
        or (deadline and paused_at < deadline)
    ):
        alert = (
            f"Surfing was blocked by pause at {_access_stamp_label(paused_at, hours)}, "
            "before the subscription end."
        )
    elif blocked_while_connected is not None and not expired and not paused:
        alert = (
            "Client stayed connected while surfing was blocked — check router "
            "profile sync."
        )

    overlapping_periods = [
        w
        for w in windows
        if w.get("start") is not None
        and w.get("deadline") is not None
        and w["start"] <= now
        and w["deadline"] > since
    ]
    period_count = max(len(start_stamps), len(overlapping_periods), 1 if package_start else 0)
    return {
        "current_state": current_state,
        "status": status,
        "status_hint": status_hint,
        "billing_allows": billing_allows,
        "paused": paused,
        "expired": expired,
        "period_count": period_count,
        "package_start": (
            timezone.localtime(package_start).isoformat() if package_start else ""
        ),
        "package_end": (
            timezone.localtime(package_end).isoformat() if package_end else ""
        ),
        "access_deadline": (
            timezone.localtime(deadline).isoformat() if deadline else ""
        ),
        "package_paused_at": (
            timezone.localtime(paused_at).isoformat() if paused_at else ""
        ),
        "package_start_label": (
            _access_stamp_label(package_start, hours) if package_start else ""
        ),
        "package_end_label": (
            _access_stamp_label(package_end, hours) if package_end else ""
        ),
        "access_deadline_label": (
            _access_stamp_label(deadline, hours) if deadline else ""
        ),
        "alert": alert,
        "events": events,
        "bounds": bounds,
    }


def _client_usage_story(
    *,
    hours: int,
    sample_count: int,
    latest_active: bool,
    online_ratio: float,
    data_used_bytes: int,
    peak_download_bps: int,
    stopped_count: int,
    access_state: str = "",
    access_alert: str = "",
) -> dict[str, Any]:
    """Plain-language status for the usage analysis page."""
    if sample_count <= 0:
        return {
            "tracking": "empty",
            "status": "Waiting",
            "status_hint": "No readings yet",
            "insight": "Usage history is still empty. The app collects it automatically in the background.",
            "access_state": "waiting",
        }
    status, status_hint = _access_state_labels(access_state or (
        "surfing" if latest_active else "disconnected"
    ))
    if sample_count < 3 and data_used_bytes <= 0 and peak_download_bps <= 0:
        return {
            "tracking": "warming",
            "status": status,
            "status_hint": "Building history…",
            "insight": "First readings are in. A clearer trend will appear after a few more minutes.",
            "access_state": access_state or ("surfing" if latest_active else "disconnected"),
        }

    bits: list[str] = [status]
    if access_alert:
        bits.append(access_alert.rstrip("."))
    if data_used_bytes > 0:
        if data_used_bytes >= 1024 * 1024 * 1024:
            bits.append(f"used {data_used_bytes / (1024 * 1024 * 1024):.2f} GB")
        elif data_used_bytes >= 1024 * 1024:
            bits.append(f"used {data_used_bytes / (1024 * 1024):.1f} MB")
        else:
            bits.append(f"used {max(1, data_used_bytes // 1024)} KB")
    if peak_download_bps >= 1_000_000:
        bits.append(f"peak {peak_download_bps / 1_000_000:.1f} Mbps down")
    elif peak_download_bps >= 1000:
        bits.append(f"peak {peak_download_bps / 1000:.0f} Kbps down")
    if online_ratio >= 80:
        bits.append("mostly surfing")
    elif online_ratio <= 20 and sample_count >= 4:
        bits.append("mostly offline")
    if stopped_count >= 2:
        bits.append(f"dropped {stopped_count} times")

    return {
        "tracking": "ready",
        "status": status,
        "status_hint": status_hint or f"Last {usage_range_label(hours)}",
        "insight": " · ".join(bits),
        "access_state": access_state or ("surfing" if latest_active else "disconnected"),
    }


def _usage_point(
    stamp, hours: int, *, download_bps: int = 0, upload_bps: int = 0, index: int | None = None
) -> dict[str, Any]:
    down = max(0, int(download_bps or 0))
    up = max(0, int(upload_bps or 0))
    return {
        "at_label": timezone.localtime(stamp).strftime(_chart_label_format(hours)),
        "download_bps": down,
        "upload_bps": up,
        "combined_bps": down + up,
        "index": index,
    }


def _client_bucket_seconds(hours: int) -> int:
    """Bucket size that spans the filter without exceeding the chart point cap."""
    base = _bucket_seconds(hours)
    window = max(1, hours) * 3600
    needed = max(base, int((window + _CLIENT_TREND_MAX_POINTS - 1) // _CLIENT_TREND_MAX_POINTS))
    return max(60, needed)


def usage_trend_payload(
    customer: Customer, *, hours: int = 24, use_cache: bool = True
) -> dict[str, Any]:
    """
    Build chart-ready series for one client.

    Bucketed across the selected filter (capped point count), with a short
    cache so refreshes stay cheap.
    """
    hours = clamp_usage_hours(hours, default=24)
    cache_key = f"client_usage_trend:{_CLIENT_TREND_CACHE_VERSION}:{customer.pk}:{hours}"
    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    now = timezone.now()
    since = now - timedelta(hours=hours)
    bucket_secs = _client_bucket_seconds(hours)
    window_start = int(since.timestamp() // bucket_secs) * bucket_secs
    window_end = int(now.timestamp() // bucket_secs) * bucket_secs
    chart_keys = list(range(window_start, window_end + bucket_secs, bucket_secs))
    if not chart_keys:
        chart_keys = [window_start]
    # Hard safety if clock skew or tiny buckets slip through.
    if len(chart_keys) > _CLIENT_TREND_MAX_POINTS:
        step = max(1, len(chart_keys) // _CLIENT_TREND_MAX_POINTS)
        chart_keys = chart_keys[::step][:_CLIENT_TREND_MAX_POINTS]

    samples = list(
        CustomerUsageSample.objects.filter(customer=customer, sampled_at__gte=since)
        .order_by("sampled_at")
        .values(
            "sampled_at",
            "session_active",
            "uptime_seconds",
            "download_bps",
            "upload_bps",
            "bytes_in",
            "bytes_out",
        )
    )
    # Keep the full window: when dense, pick evenly spaced points so long
    # ranges (7d/30d) are not truncated to only the newest samples.
    if len(samples) > _CLIENT_SAMPLE_CAP:
        step = len(samples) / float(_CLIENT_SAMPLE_CAP)
        samples = [samples[min(len(samples) - 1, int(i * step))] for i in range(_CLIENT_SAMPLE_CAP)]

    access = build_client_access_timeline(
        customer, hours=hours, samples=samples, now=now
    )
    access_bounds = access.get("bounds") or _package_access_bounds(customer)
    service_type = (getattr(customer, "service_type", "") or "").strip()
    # Drop non-JSON helper before caching / responding.
    access_public = {k: v for k, v in access.items() if k != "bounds"}

    online_by_bucket: dict[int, bool] = {}
    surf_state_by_bucket: dict[int, int] = {}
    seen_by_bucket: dict[int, bool] = {}
    down_by_bucket: dict[int, float] = {}
    up_by_bucket: dict[int, float] = {}
    data_by_bucket: dict[int, float] = {}

    previous_total = None
    previous_bi = None
    previous_bo = None
    previous_at = None
    previous_active: bool | None = None
    total_bytes_delta = 0
    online_samples = 0
    surfing_samples = 0
    peak_down = 0
    peak_up = 0
    prime_sample: dict[str, Any] | None = None
    lowest_sample: dict[str, Any] | None = None
    prime_bucket: int | None = None
    lowest_bucket: int | None = None
    stop_buckets: set[int] = set()
    last_stopped_stamp = None
    stopped_count = 0

    for row in samples:
        stamp = row["sampled_at"]
        bucket = int(stamp.timestamp() // bucket_secs) * bucket_secs
        if bucket < window_start:
            bucket = window_start
        elif bucket > window_end:
            bucket = window_end

        active = bool(row["session_active"])
        allowed = _surf_allowed_at(
            stamp, bounds=access_bounds, service_type=service_type
        )
        state = _classify_access_state(session_active=active, surf_allowed=allowed)
        state_val = _surf_state_value(state)
        bi = int(row["bytes_in"] or 0)
        bo = int(row["bytes_out"] or 0)
        total = bi + bo
        down = int(row["download_bps"] or 0)
        up = int(row["upload_bps"] or 0)
        seen_by_bucket[bucket] = True
        if state_val is not None:
            # Prefer the "most online" state in a bucket: surfing > not surfing > disconnected
            prev_state = surf_state_by_bucket.get(bucket)
            if prev_state is None or state_val > prev_state:
                surf_state_by_bucket[bucket] = state_val

        if previous_active is True and not active:
            stopped_count += 1
            last_stopped_stamp = stamp
            stop_buckets.add(bucket)

        if not active and total == 0:
            previous_active = False
            continue

        delta = _bytes_delta(previous_total, total)
        if previous_at is not None:
            dt = max(0.0, (stamp - previous_at).total_seconds())
            if dt >= 1 and down <= 0 and previous_bo is not None and bo >= previous_bo:
                down = int(((bo - previous_bo) * 8) / dt)
            if dt >= 1 and up <= 0 and previous_bi is not None and bi >= previous_bi:
                up = int(((bi - previous_bi) * 8) / dt)

        previous_total = total
        previous_bi = bi
        previous_bo = bo
        previous_at = stamp
        total_bytes_delta += delta
        if delta:
            data_by_bucket[bucket] = data_by_bucket.get(bucket, 0.0) + float(delta)

        if active:
            previous_active = True
            online_samples += 1
            online_by_bucket[bucket] = True
            if allowed:
                surfing_samples += 1
            peak_down = max(peak_down, down)
            peak_up = max(peak_up, up)
            down_by_bucket[bucket] = max(down_by_bucket.get(bucket, 0.0), float(down))
            up_by_bucket[bucket] = max(up_by_bucket.get(bucket, 0.0), float(up))
            combined = down + up
            candidate = {
                "stamp": stamp,
                "download_bps": down,
                "upload_bps": up,
                "combined_bps": combined,
            }
            if prime_sample is None or combined > int(prime_sample["combined_bps"]):
                prime_sample = candidate
                prime_bucket = bucket
            if lowest_sample is None or combined < int(lowest_sample["combined_bps"]):
                lowest_sample = candidate
                lowest_bucket = bucket
        else:
            previous_active = False

    labels: list[str] = []
    download_kbps: list[float | None] = []
    upload_kbps: list[float | None] = []
    download_mbps: list[float | None] = []
    upload_mbps: list[float | None] = []
    data_used_mb: list[float | None] = []
    online_flags: list[int | None] = []
    surf_states: list[int | None] = []
    prime_index: int | None = None
    lowest_index: int | None = None
    stop_indexes: list[int] = []
    event_indexes: dict[str, list[int]] = {
        "payment": [],
        "subscription_started": [],
        "blocked": [],
        "subscription_ended": [],
        "early_offline": [],
        "blocked_connected": [],
    }
    fmt = _chart_label_format(hours)
    online_bucket_count = 0
    surfing_bucket_count = 0
    seen_bucket_count = 0

    for idx, key in enumerate(chart_keys):
        labels.append(
            timezone.localtime(datetime.fromtimestamp(key, tz=dt_timezone.utc)).strftime(
                fmt
            )
        )
        has_signal = key in seen_by_bucket or key in data_by_bucket
        if not has_signal:
            online_flags.append(None)
            surf_states.append(None)
            download_kbps.append(None)
            upload_kbps.append(None)
            download_mbps.append(None)
            upload_mbps.append(None)
            data_used_mb.append(None)
            continue

        seen_bucket_count += 1
        is_online = bool(online_by_bucket.get(key))
        if is_online:
            online_bucket_count += 1
        online_flags.append(1 if is_online else 0)
        state_val = surf_state_by_bucket.get(key)
        if state_val is None:
            bucket_stamp = datetime.fromtimestamp(key, tz=dt_timezone.utc)
            allowed = _surf_allowed_at(
                bucket_stamp, bounds=access_bounds, service_type=service_type
            )
            state_val = _surf_state_value(
                _classify_access_state(session_active=is_online, surf_allowed=allowed)
            )
        surf_states.append(state_val)
        if state_val == _SURF_STATE_SURFING:
            surfing_bucket_count += 1
        down_k = round(down_by_bucket.get(key, 0.0) / 1000.0, 2) if is_online else 0
        up_k = round(up_by_bucket.get(key, 0.0) / 1000.0, 2) if is_online else 0
        download_kbps.append(down_k)
        upload_kbps.append(up_k)
        download_mbps.append(round(down_k / 1000.0, 3) if is_online else 0)
        upload_mbps.append(round(up_k / 1000.0, 3) if is_online else 0)
        data_used_mb.append(round(data_by_bucket.get(key, 0.0) / (1024 * 1024), 3))
        if prime_bucket == key:
            prime_index = idx
        if lowest_bucket == key:
            lowest_index = idx
        if key in stop_buckets and idx > 0 and online_flags[idx - 1] == 1:
            stop_indexes.append(idx)

    # Map access events onto the nearest chart bucket for marker overlays.
    for ev in access_public.get("events") or []:
        kind = ev.get("kind") or ""
        if kind not in event_indexes:
            continue
        try:
            stamp = datetime.fromisoformat(ev["at"])
        except Exception:
            continue
        if timezone.is_naive(stamp):
            stamp = timezone.make_aware(stamp, timezone.get_current_timezone())
        key = int(stamp.timestamp() // bucket_secs) * bucket_secs
        if key < window_start or key > window_end:
            # Still allow future subscription-end markers just outside the window.
            if not (kind == "subscription_ended" and key > window_end):
                continue
            key = window_end
        best_idx = None
        best_dist = None
        for idx, chart_key in enumerate(chart_keys):
            dist = abs(chart_key - key)
            if best_dist is None or dist < best_dist:
                best_dist = dist
                best_idx = idx
        if best_idx is not None and best_idx not in event_indexes[kind]:
            event_indexes[kind].append(best_idx)

    latest = samples[-1] if samples else None
    current_session_bytes = 0
    if latest and latest.get("session_active"):
        current_session_bytes = int(latest.get("bytes_in") or 0) + int(
            latest.get("bytes_out") or 0
        )

    online_ratio = (
        round((online_bucket_count / seen_bucket_count) * 100, 1)
        if seen_bucket_count
        else (
            round((online_samples / len(samples)) * 100, 1) if samples else 0
        )
    )
    surfing_ratio = (
        round((surfing_bucket_count / seen_bucket_count) * 100, 1)
        if seen_bucket_count
        else (
            round((surfing_samples / len(samples)) * 100, 1) if samples else 0
        )
    )
    approx_online_seconds = online_bucket_count * bucket_secs
    latest_active = bool(latest and latest.get("session_active"))
    story = _client_usage_story(
        hours=hours,
        sample_count=len(samples),
        latest_active=latest_active,
        online_ratio=online_ratio,
        data_used_bytes=total_bytes_delta,
        peak_download_bps=peak_down,
        stopped_count=stopped_count,
        access_state=access_public.get("current_state") or "",
        access_alert=access_public.get("alert") or "",
    )

    payload = {
        "ok": True,
        "hours": hours,
        "range_label": usage_range_label(hours),
        "sample_count": len(samples),
        "labels": labels,
        "series": {
            "download_kbps": download_kbps,
            "upload_kbps": upload_kbps,
            "download_mbps": download_mbps,
            "upload_mbps": upload_mbps,
            "data_used_mb": data_used_mb,
            "online": online_flags,
            "surf_state": surf_states,
        },
        "markers": {
            "peak_index": prime_index,
            "low_index": lowest_index,
            "stop_indexes": stop_indexes[:6],
            "event_indexes": event_indexes,
        },
        "access": access_public,
        "summary": {
            "online_ratio": online_ratio,
            "surfing_ratio": surfing_ratio,
            "online_time_label": _human_duration(approx_online_seconds),
            "online_time_seconds": approx_online_seconds,
            "peak_download_bps": peak_down,
            "peak_upload_bps": peak_up,
            "data_used_bytes": total_bytes_delta,
            "current_session_bytes": current_session_bytes,
            "latest_active": latest_active,
            "access_state": story.get("access_state") or access_public.get("current_state"),
            "status": story["status"],
            "status_hint": story["status_hint"],
            "tracking": story["tracking"],
            "insight": story["insight"],
            "access_alert": access_public.get("alert") or "",
            "prime_point": (
                _usage_point(
                    prime_sample["stamp"],
                    hours,
                    download_bps=prime_sample["download_bps"],
                    upload_bps=prime_sample["upload_bps"],
                    index=prime_index,
                )
                if prime_sample
                else None
            ),
            "lowest_point": (
                _usage_point(
                    lowest_sample["stamp"],
                    hours,
                    download_bps=lowest_sample["download_bps"],
                    upload_bps=lowest_sample["upload_bps"],
                    index=lowest_index,
                )
                if lowest_sample
                else None
            ),
            "last_stopped": (
                _usage_point(last_stopped_stamp, hours)
                if last_stopped_stamp is not None
                else None
            ),
            "stopped_count": stopped_count,
        },
    }
    if use_cache:
        cache.set(cache_key, payload, _CLIENT_TREND_TTL)
    return payload


def _bucket_seconds(hours: int) -> int:
    if hours <= 6:
        return 10 * 60
    if hours <= 24:
        return 30 * 60
    if hours <= 72:
        return 60 * 60
    if hours <= 168:
        return 3 * 60 * 60
    if hours <= 720:
        return 12 * 60 * 60
    return 7 * 24 * 60 * 60


def _bytes_delta(previous_total: int | None, total: int) -> int:
    if previous_total is None:
        return 0
    if total >= previous_total:
        return total - previous_total
    # Counter reset (reconnect / new session) — do not count the new absolute
    # total as data used; that created huge false spikes on the trend chart.
    return 0


def _empty_org_payload(hours: int, *, error: str = "", service: str = "") -> dict[str, Any]:
    return {
        "ok": not bool(error),
        "hours": hours,
        "requested_hours": hours,
        "auto_widened": False,
        "service": service or "all",
        "sample_count": 0,
        "labels": [],
        "series": {
            "online_clients": [],
            "download_kbps": [],
            "upload_kbps": [],
            "data_used_mb": [],
        },
        "summary": {},
        "top_users": [],
        "top_chart": {"labels": [], "data_used_mb": []},
        "error": error,
    }


def _normalize_usage_service(service) -> str:
    value = (service or "").strip().lower()
    if value in {Customer.ServiceType.PPPOE, "pppoe"}:
        return Customer.ServiceType.PPPOE
    if value in {Customer.ServiceType.HOTSPOT, "hotspot"}:
        return Customer.ServiceType.HOTSPOT
    return ""


def _usage_level_label(*, data_used_bytes: int, peak_download_bps: int, latest_active: bool) -> str:
    if data_used_bytes >= 500 * 1024 * 1024 or peak_download_bps >= 5_000_000:
        return "High"
    if data_used_bytes >= 50 * 1024 * 1024 or peak_download_bps >= 1_000_000:
        return "Medium"
    if data_used_bytes > 0 or peak_download_bps > 0 or latest_active:
        return "Low"
    return "Idle"


def _usage_router_cache_key(*, router_id: int | None = None, unassigned_only: bool = False) -> str:
    if unassigned_only:
        return "none"
    if router_id:
        return str(int(router_id))
    return "all"


def _build_org_usage_payload(
    organization,
    *,
    hours: int = 24,
    top_n: int = 0,
    service: str = "",
    router_id: int | None = None,
    unassigned_only: bool = False,
) -> dict[str, Any]:
    hours = clamp_usage_hours(hours)
    top_n = max(0, min(int(top_n if top_n is not None else 0), 5000))
    service = _normalize_usage_service(service)
    now = timezone.now()
    since = now - timedelta(hours=hours)
    bucket_secs = _bucket_seconds(hours)
    window_start = int(since.timestamp() // bucket_secs) * bucket_secs
    window_end = int(now.timestamp() // bucket_secs) * bucket_secs
    bucket_keys = list(range(window_start, window_end + bucket_secs, bucket_secs))
    if not bucket_keys:
        bucket_keys = [window_start]
    label_fmt = _chart_label_format(hours)

    customers_qs = Customer.objects.filter(organization=organization).exclude(
        service_type=Customer.ServiceType.STATIC
    )
    if service:
        customers_qs = customers_qs.filter(service_type=service)
    if unassigned_only:
        customers_qs = customers_qs.filter(router__isnull=True)
    elif router_id:
        customers_qs = customers_qs.filter(router_id=router_id)
    customers = {
        c.pk: c
        for c in customers_qs.select_related("plan", "router").order_by(
            "full_name", "account_number"
        )
    }
    customer_ids = list(customers.keys())

    sample_cap = 8000 if hours <= 168 else (16000 if hours <= 720 else 24000)
    samples_qs = CustomerUsageSample.objects.filter(
        organization=organization,
        sampled_at__gte=since,
    )
    if customer_ids:
        samples_qs = samples_qs.filter(customer_id__in=customer_ids)
    elif service:
        samples_qs = samples_qs.none()
    samples = list(
        samples_qs.order_by("customer_id", "sampled_at").values(
            "customer_id",
            "sampled_at",
            "session_active",
            "download_bps",
            "upload_bps",
            "bytes_in",
            "bytes_out",
        )[:sample_cap]
    )

    online_by_bucket: dict[int, set[int]] = {k: set() for k in bucket_keys}
    down_by_bucket: dict[int, dict[int, float]] = {k: {} for k in bucket_keys}
    up_by_bucket: dict[int, dict[int, float]] = {k: {} for k in bucket_keys}
    data_sum: dict[int, float] = {k: 0.0 for k in bucket_keys}

    per_customer: dict[int, dict[str, Any]] = {}
    previous_total: dict[int, int] = {}
    previous_bi: dict[int, int] = {}
    previous_bo: dict[int, int] = {}
    previous_at: dict[int, Any] = {}
    previous_active: dict[int, bool] = {}
    total_bytes_delta = 0
    online_samples = 0
    meaningful_samples = 0
    peak_down = 0
    peak_up = 0

    for row in samples:
        cid = int(row["customer_id"])
        stamp = row["sampled_at"]
        bucket = int(stamp.timestamp() // bucket_secs) * bucket_secs
        if bucket < window_start:
            bucket = window_start
        if bucket > window_end:
            bucket = window_end

        stats = per_customer.setdefault(
            cid,
            {
                "customer_id": cid,
                "sample_count": 0,
                "online_samples": 0,
                "data_used_bytes": 0,
                "peak_download_bps": 0,
                "peak_upload_bps": 0,
                "peak_session_bytes": 0,
                "latest_active": False,
                "downtime_count": 0,
                "prime_combined": -1,
                "prime_at": None,
                "prime_download_bps": 0,
                "prime_upload_bps": 0,
                "lowest_combined": None,
                "lowest_at": None,
                "lowest_download_bps": 0,
                "lowest_upload_bps": 0,
            },
        )
        stats["sample_count"] += 1
        active = bool(row["session_active"])
        stats["latest_active"] = active
        bi = int(row["bytes_in"] or 0)
        bo = int(row["bytes_out"] or 0)
        total = bi + bo
        down = int(row["download_bps"] or 0)
        up = int(row["upload_bps"] or 0)

        was_active = previous_active.get(cid)
        if was_active is True and not active:
            stats["downtime_count"] += 1
        previous_active[cid] = active

        # Offline zeros are presence noise — keep counter continuity.
        if not active and total == 0:
            continue

        meaningful_samples += 1
        delta = _bytes_delta(previous_total.get(cid), total)

        prev_at = previous_at.get(cid)
        if prev_at is not None:
            dt = max(0.0, (stamp - prev_at).total_seconds())
            if dt >= 1:
                prev_bo = previous_bo.get(cid)
                prev_bi = previous_bi.get(cid)
                if down <= 0 and prev_bo is not None and bo >= prev_bo:
                    down = int(((bo - prev_bo) * 8) / dt)
                if up <= 0 and prev_bi is not None and bi >= prev_bi:
                    up = int(((bi - prev_bi) * 8) / dt)

        previous_total[cid] = total
        previous_bi[cid] = bi
        previous_bo[cid] = bo
        previous_at[cid] = stamp

        if delta:
            stats["data_used_bytes"] += delta
            total_bytes_delta += delta
            data_sum[bucket] = data_sum.get(bucket, 0.0) + delta

        if active:
            online_samples += 1
            stats["online_samples"] += 1
            stats["peak_session_bytes"] = max(stats["peak_session_bytes"], total)
            stats["peak_download_bps"] = max(stats["peak_download_bps"], down)
            stats["peak_upload_bps"] = max(stats["peak_upload_bps"], up)
            peak_down = max(peak_down, down)
            peak_up = max(peak_up, up)
            online_by_bucket.setdefault(bucket, set()).add(cid)
            down_map = down_by_bucket.setdefault(bucket, {})
            up_map = up_by_bucket.setdefault(bucket, {})
            down_map[cid] = max(down_map.get(cid, 0.0), float(down))
            up_map[cid] = max(up_map.get(cid, 0.0), float(up))

            combined = down + up
            if combined > int(stats["prime_combined"]):
                stats["prime_combined"] = combined
                stats["prime_at"] = stamp
                stats["prime_download_bps"] = down
                stats["prime_upload_bps"] = up
            if stats["lowest_combined"] is None or combined < int(stats["lowest_combined"]):
                stats["lowest_combined"] = combined
                stats["lowest_at"] = stamp
                stats["lowest_download_bps"] = down
                stats["lowest_upload_bps"] = up

    # Recently seen Hotspot gadgets (no live MikroTik fan-out).
    gadget_counts: dict[int, int] = {}
    if customers:
        from django.db.models import Count

        from billing.models import CustomerDevice

        recent_cut = now - timedelta(minutes=15)
        for row in (
            CustomerDevice.objects.filter(
                organization=organization,
                customer_id__in=customers.keys(),
                last_seen_at__gte=recent_cut,
            )
            .values("customer_id")
            .annotate(n=Count("id"))
        ):
            gadget_counts[int(row["customer_id"])] = int(row["n"] or 0)

    def _empty_stats(customer_id: int) -> dict[str, Any]:
        return {
            "customer_id": customer_id,
            "sample_count": 0,
            "online_samples": 0,
            "data_used_bytes": 0,
            "peak_download_bps": 0,
            "peak_upload_bps": 0,
            "peak_session_bytes": 0,
            "latest_active": False,
            "downtime_count": 0,
            "prime_at": None,
            "prime_download_bps": 0,
            "lowest_at": None,
            "lowest_download_bps": 0,
        }

    # Highest data first; numeric ties fall through to peak session / rate / online.
    # Name stays A–Z (do not reverse the string key with reverse=True).
    ranked = sorted(
        (
            per_customer.get(cid) or _empty_stats(cid)
            for cid in customers.keys()
        ),
        key=lambda item: (
            -int(item["data_used_bytes"] or 0),
            -int(item["peak_session_bytes"] or 0),
            -int(item["peak_download_bps"] or 0),
            -int(item["online_samples"] or 0),
            (
                customers.get(item["customer_id"]).full_name
                if customers.get(item["customer_id"])
                else ""
            ).casefold(),
        ),
    )
    top_users: list[dict[str, Any]] = []
    user_limit = len(ranked) if top_n <= 0 else min(top_n, len(ranked))
    for item in ranked[:user_limit]:
        customer = customers.get(item["customer_id"])
        if not customer:
            continue
        sample_count = item["sample_count"] or 1
        gadgets = gadget_counts.get(item["customer_id"], 0)
        if gadgets <= 0 and item["latest_active"]:
            gadgets = 1
        prime_at = item.get("prime_at")
        lowest_at = item.get("lowest_at")
        top_users.append(
            {
                "rank": len(top_users) + 1,
                "customer_id": customer.pk,
                "full_name": customer.full_name,
                "account_number": customer.account_number,
                "phone": customer.phone,
                "service_type": customer.service_type,
                "service_type_label": customer.get_service_type_display(),
                "plan_name": customer.plan.name if customer.plan_id else "",
                "router_name": customer.router.name if customer.router_id else "",
                "data_used_bytes": item["data_used_bytes"],
                "peak_session_bytes": item["peak_session_bytes"],
                "peak_download_bps": item["peak_download_bps"],
                "peak_upload_bps": item["peak_upload_bps"],
                "online_ratio": round((item["online_samples"] / sample_count) * 100, 1),
                "sample_count": item["sample_count"],
                "latest_active": item["latest_active"],
                "usage_level": _usage_level_label(
                    data_used_bytes=item["data_used_bytes"],
                    peak_download_bps=item["peak_download_bps"],
                    latest_active=item["latest_active"],
                ),
                "prime_at_label": (
                    timezone.localtime(prime_at).strftime(label_fmt) if prime_at else ""
                ),
                "prime_download_bps": item.get("prime_download_bps") or 0,
                "lowest_at_label": (
                    timezone.localtime(lowest_at).strftime(label_fmt) if lowest_at else ""
                ),
                "lowest_download_bps": item.get("lowest_download_bps") or 0,
                "downtime_count": int(item.get("downtime_count") or 0),
                "gadgets_connected": gadgets,
            }
        )

    active_keys = [
        key
        for key in bucket_keys
        if data_sum.get(key)
        or online_by_bucket.get(key)
        or down_by_bucket.get(key)
        or up_by_bucket.get(key)
    ]
    if active_keys and len(active_keys) < max(4, int(len(bucket_keys) * 0.2)):
        chart_keys = active_keys
    else:
        chart_keys = list(bucket_keys)
        while chart_keys and chart_keys[0] not in active_keys and active_keys:
            chart_keys.pop(0)
        while chart_keys and chart_keys[-1] not in active_keys and active_keys:
            chart_keys.pop()
        if not chart_keys:
            chart_keys = bucket_keys[-min(12, len(bucket_keys)) :]

    labels: list[str] = []
    online_series: list[int] = []
    download_kbps: list[float] = []
    upload_kbps: list[float] = []
    data_used_mb: list[float] = []
    for key in chart_keys:
        stamp = timezone.localtime(datetime.fromtimestamp(key, tz=dt_timezone.utc))
        labels.append(stamp.strftime(label_fmt))
        online_series.append(len(online_by_bucket.get(key, set())))
        download_kbps.append(
            round(sum((down_by_bucket.get(key) or {}).values()) / 1000.0, 2)
        )
        upload_kbps.append(
            round(sum((up_by_bucket.get(key) or {}).values()) / 1000.0, 2)
        )
        data_used_mb.append(round(data_sum.get(key, 0.0) / (1024 * 1024), 3))

    clients_with_samples = len(per_customer)
    clients_total = len(customers)
    # Prefer latest sample status; fall back to empty (offline) for never-sampled.
    online_now = sum(
        1
        for cid in customers
        if (per_customer.get(cid) or {}).get("latest_active")
    )
    gadgets_online = sum(int(u.get("gadgets_connected") or 0) for u in top_users)
    router_filter = _usage_router_cache_key(
        router_id=router_id, unassigned_only=unassigned_only
    )
    router_label = ""
    if unassigned_only:
        router_label = "No router assigned"
    elif router_id:
        matched = next((c.router for c in customers.values() if c.router_id == router_id), None)
        if matched:
            router_label = matched.name
        else:
            from core.models import MikroTikRouter

            router_label = (
                MikroTikRouter.objects.filter(pk=router_id, organization=organization)
                .values_list("name", flat=True)
                .first()
                or ""
            )
    return {
        "ok": True,
        "hours": hours,
        "requested_hours": hours,
        "auto_widened": False,
        "service": service or "all",
        "router_filter": router_filter if router_filter != "all" else "",
        "router_id": router_id,
        "router_name": router_label,
        "sample_count": len(samples),
        "meaningful_samples": meaningful_samples,
        "labels": labels,
        "series": {
            "online_clients": online_series,
            "download_kbps": download_kbps,
            "upload_kbps": upload_kbps,
            "data_used_mb": data_used_mb,
        },
        "top_users": top_users,
        "top_chart": {
            "labels": [u["full_name"] for u in top_users[:10]],
            "data_used_mb": [
                round(
                    (
                        u["data_used_bytes"]
                        if u["data_used_bytes"]
                        else u.get("peak_session_bytes") or 0
                    )
                    / (1024 * 1024),
                    3,
                )
                for u in top_users[:10]
            ],
        },
        "summary": {
            "clients_tracked": clients_with_samples,
            "clients_total": clients_total,
            "clients_online": online_now,
            "gadgets_online": gadgets_online,
            "online_ratio": (
                round((online_samples / meaningful_samples) * 100, 1)
                if meaningful_samples
                else 0
            ),
            "peak_download_bps": peak_down,
            "peak_upload_bps": peak_up,
            "data_used_bytes": total_bytes_delta,
            "top_user_name": top_users[0]["full_name"] if top_users else "",
            "top_user_bytes": (
                top_users[0]["data_used_bytes"]
                or top_users[0].get("peak_session_bytes")
                or 0
            )
            if top_users
            else 0,
        },
    }


def router_network_performance_trend(
    organization, *, hours: int = 24, use_cache: bool = True
) -> dict[str, Any]:
    """Per-router network activity: online clients on each MikroTik over time."""
    empty = {
        "ok": False,
        "hours": hours,
        "labels": [],
        "datasets": [],
        "routers": [],
        "summary": {"clients_online": 0, "peak_download_bps": 0},
    }
    if not organization:
        return empty

    hours = clamp_usage_hours(hours, default=24)
    cache_key = f"router_network_trend:{organization.pk}:{hours}"
    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    from core.models import MikroTikRouter

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

    customer_router = {
        row["pk"]: row["router_id"]
        for row in Customer.objects.filter(organization=organization)
        .exclude(router_id__isnull=True)
        .values("pk", "router_id")
    }

    samples = list(
        CustomerUsageSample.objects.filter(
            organization=organization,
            sampled_at__gte=since,
            session_active=True,
        )
        .order_by("sampled_at")
        .values("customer_id", "sampled_at", "download_bps")[:12000]
    )

    online_by_bucket: dict[int, dict[int, set[int]]] = {k: {} for k in bucket_keys}
    down_by_bucket: dict[int, dict[int, float]] = {k: {} for k in bucket_keys}
    latest_online: dict[int, set[int]] = {}

    for row in samples:
        cid = int(row["customer_id"])
        router_id = customer_router.get(cid)
        if not router_id or router_id not in router_meta:
            continue
        stamp = row["sampled_at"]
        bucket = int(stamp.timestamp() // bucket_secs) * bucket_secs
        if bucket < window_start:
            bucket = window_start
        if bucket > window_end:
            bucket = window_end
        online_by_bucket.setdefault(bucket, {}).setdefault(router_id, set()).add(cid)
        down = float(int(row["download_bps"] or 0))
        down_map = down_by_bucket.setdefault(bucket, {}).setdefault(router_id, 0.0)
        down_by_bucket[bucket][router_id] = max(down_map, down)
        latest_online.setdefault(router_id, set()).add(cid)

    labels: list[str] = []
    for key in bucket_keys:
        stamp = timezone.localtime(datetime.fromtimestamp(key, tz=dt_timezone.utc))
        labels.append(stamp.strftime(_chart_label_format(hours)))

    datasets = []
    for idx, router in enumerate(routers):
        series = []
        for key in bucket_keys:
            series.append(len(online_by_bucket.get(key, {}).get(router.pk, set())))
        color = _NETWORK_TREND_COLORS[idx % len(_NETWORK_TREND_COLORS)]
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
        vals = [ds["data"][i] for ds in datasets if ds["data"][i] is not None]
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

    clients_online = sum(len(s) for s in latest_online.values())
    peak_download = 0
    for bucket_down in down_by_bucket.values():
        peak_download = max(peak_download, int(sum(bucket_down.values())))

    payload = {
        "ok": True,
        "hours": hours,
        "labels": labels,
        "datasets": datasets,
        "routers": list(router_meta.values()),
        "average": average,
        "sample_count": len(samples),
        "summary": {
            "clients_online": clients_online,
            "peak_download_bps": peak_download,
            "routers_tracked": len(routers),
        },
    }
    if use_cache:
        cache.set(cache_key, payload, _NETWORK_TREND_TTL)
    return payload


def _wifi_drop_reason(
    *,
    lost: int,
    hotspot_lost: int,
    pppoe_lost: int,
    expired_count: int,
    router_status: str = "",
    router_error: str = "",
) -> str:
    from core.mikrotik_status_samples import status_reason

    parts: list[str] = []
    status = (router_status or "").strip().lower()
    if status and status != "connected":
        parts.append(
            "MikroTik "
            + status_reason(status, router_error).rstrip(".")
            + ", so Wi‑Fi and client sessions dropped."
        )
    if expired_count:
        noun = "package" if expired_count == 1 else "packages"
        parts.append(f"{expired_count} client {noun} expired.")
    if parts:
        return " ".join(parts)

    bits: list[str] = []
    if hotspot_lost:
        noun = "client" if hotspot_lost == 1 else "clients"
        bits.append(f"{hotspot_lost} Wi‑Fi/Hotspot {noun}")
    if pppoe_lost:
        noun = "session" if pppoe_lost == 1 else "sessions"
        bits.append(f"{pppoe_lost} PPPoE {noun}")
    if bits:
        return (
            " and ".join(bits)
            + " left the network while the MikroTik stayed connected."
        )
    noun = "client" if lost == 1 else "clients"
    return f"{lost} {noun} went offline."


def _is_significant_client_drop(previous: int, current: int) -> bool:
    lost = previous - current
    if lost < 1 or previous < 1:
        return False
    if current == 0:
        return True
    if lost >= 2:
        return True
    return (lost / previous) >= 0.3


def network_performance_drops(
    organization, *, hours: int = 24, max_events: int = 8
) -> dict[str, Any]:
    """Explain Wi‑Fi / online-client drops on each MikroTik over the window."""
    empty = {"ok": False, "hours": hours, "events": [], "current_count": 0}
    if not organization:
        return empty

    from core.models import MikroTikRouter, MikroTikStatusSample

    hours = clamp_usage_hours(hours, default=24)
    now = timezone.now()
    since = now - timedelta(hours=hours)
    bucket_secs = _bucket_seconds(hours)
    window_start = int(since.timestamp() // bucket_secs) * bucket_secs
    window_end = int(now.timestamp() // bucket_secs) * bucket_secs
    bucket_keys = list(range(window_start, window_end + bucket_secs, bucket_secs))
    if not bucket_keys:
        bucket_keys = [window_start]

    routers = {
        r.pk: {"id": r.pk, "name": r.name, "host": r.host or ""}
        for r in MikroTikRouter.objects.filter(organization=organization)
        .only("id", "name", "host")
        .order_by("name")
    }
    customers = {
        row["pk"]: {
            "router_id": row["router_id"],
            "service_type": (row["service_type"] or "").strip().lower(),
            "package_end": row["package_end"],
        }
        for row in Customer.objects.filter(organization=organization)
        .exclude(router_id__isnull=True)
        .values("pk", "router_id", "service_type", "package_end")
    }

    samples = list(
        CustomerUsageSample.objects.filter(
            organization=organization,
            sampled_at__gte=since,
            session_active=True,
        )
        .order_by("sampled_at")
        .values("customer_id", "sampled_at")[:12000]
    )
    online_by_bucket: dict[int, dict[int, set[int]]] = {k: {} for k in bucket_keys}
    for row in samples:
        cid = int(row["customer_id"])
        meta = customers.get(cid)
        if not meta:
            continue
        router_id = meta["router_id"]
        if router_id not in routers:
            continue
        stamp = row["sampled_at"]
        bucket = int(stamp.timestamp() // bucket_secs) * bucket_secs
        if bucket < window_start:
            bucket = window_start
        if bucket > window_end:
            bucket = window_end
        online_by_bucket.setdefault(bucket, {}).setdefault(router_id, set()).add(cid)

    mt_status_by_bucket: dict[int, dict[int, str]] = {k: {} for k in bucket_keys}
    for row in MikroTikStatusSample.objects.filter(
        organization=organization,
        sampled_at__gte=since,
    ).order_by("sampled_at").values("router_id", "sampled_at", "status")[:12000]:
        rid = int(row["router_id"])
        if rid not in routers:
            continue
        stamp = row["sampled_at"]
        bucket = int(stamp.timestamp() // bucket_secs) * bucket_secs
        if bucket < window_start:
            bucket = window_start
        if bucket > window_end:
            bucket = window_end
        mt_status_by_bucket.setdefault(bucket, {})[rid] = (
            row["status"] or "disconnected"
        ).strip().lower()

    events: list[dict[str, Any]] = []
    for router_id, meta in routers.items():
        prev_ids: set[int] = set()
        prev_key = None
        for key in bucket_keys:
            current_ids = set(online_by_bucket.get(key, {}).get(router_id, set()))
            if prev_key is not None and _is_significant_client_drop(
                len(prev_ids), len(current_ids)
            ):
                left = prev_ids - current_ids
                hotspot_lost = sum(
                    1
                    for cid in left
                    if customers.get(cid, {}).get("service_type") == Customer.ServiceType.HOTSPOT
                )
                pppoe_lost = len(left) - hotspot_lost
                drop_start = datetime.fromtimestamp(prev_key, tz=dt_timezone.utc)
                drop_end = datetime.fromtimestamp(key, tz=dt_timezone.utc)
                expired_count = 0
                for cid in left:
                    ended = customers.get(cid, {}).get("package_end")
                    if ended and drop_start <= ended <= drop_end:
                        expired_count += 1
                nearby_keys = [prev_key, key, key + bucket_secs]
                router_status = ""
                for probe_key in nearby_keys:
                    status = (mt_status_by_bucket.get(probe_key) or {}).get(
                        router_id
                    ) or ""
                    if status and status != "connected":
                        router_status = status
                        break
                stamp = timezone.localtime(drop_end)
                events.append(
                    {
                        "router_id": router_id,
                        "router_name": meta["name"],
                        "host": meta["host"],
                        "at": stamp.strftime("%H:%M" if hours <= 48 else "%b %d %H:%M"),
                        "at_iso": drop_end.isoformat(),
                        "from_online": len(prev_ids),
                        "to_online": len(current_ids),
                        "status": router_status,
                        "reason": _wifi_drop_reason(
                            lost=len(left),
                            hotspot_lost=hotspot_lost,
                            pppoe_lost=pppoe_lost,
                            expired_count=expired_count,
                            router_status=router_status,
                        ),
                        "current": key == bucket_keys[-1],
                    }
                )
            prev_ids = current_ids
            prev_key = key

    events.sort(key=lambda row: row.get("at_iso") or "", reverse=True)
    current_count = sum(1 for row in events if row.get("current"))
    return {
        "ok": True,
        "hours": hours,
        "events": events[: max(1, int(max_events or 8))],
        "current_count": current_count,
    }


def org_usage_payload(
    organization,
    *,
    hours: int = 24,
    top_n: int = 0,
    service: str = "",
    router_id: int | None = None,
    unassigned_only: bool = False,
    auto_widen: bool = True,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Build org-wide usage charts and a per-user ranking."""
    if not organization:
        return _empty_org_payload(hours, error="No organization.")

    hours = clamp_usage_hours(hours, default=24)
    top_n = max(0, min(int(top_n or 0), 5000))
    service = _normalize_usage_service(service)
    router_key = _usage_router_cache_key(
        router_id=router_id, unassigned_only=unassigned_only
    )
    cache_key = (
        f"org_usage_payload:v4:{organization.pk}:{hours}:{top_n}:{service or 'all'}:{router_key}"
    )
    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    payload = _build_org_usage_payload(
        organization,
        hours=hours,
        top_n=top_n,
        service=service,
        router_id=router_id,
        unassigned_only=unassigned_only,
    )
    # Roster always lists every customer (empty stats). Signal = real samples.
    summary = payload.get("summary") or {}
    has_signal = bool(
        summary.get("data_used_bytes")
        or summary.get("peak_download_bps")
        or summary.get("clients_online")
        or summary.get("clients_tracked")
        or payload.get("sample_count")
    )
    if auto_widen and not has_signal and hours < _MAX_USAGE_HOURS:
        for candidate in (72, 168, 720, 8760):
            if candidate <= hours:
                continue
            wider = _build_org_usage_payload(
                organization,
                hours=candidate,
                top_n=top_n,
                service=service,
                router_id=router_id,
                unassigned_only=unassigned_only,
            )
            wider_summary = wider.get("summary") or {}
            wider_signal = bool(
                wider_summary.get("data_used_bytes")
                or wider_summary.get("peak_download_bps")
                or wider_summary.get("clients_online")
                or wider_summary.get("clients_tracked")
                or wider.get("sample_count")
            )
            if wider_signal:
                wider["requested_hours"] = hours
                wider["auto_widened"] = True
                payload = wider
                break

    payload["range_label"] = usage_range_label(payload.get("hours") or hours)
    payload["requested_range_label"] = usage_range_label(
        payload.get("requested_hours") or hours
    )
    payload["service"] = service or "all"

    if use_cache:
        cache.set(cache_key, payload, _ORG_PAYLOAD_TTL)
    return payload
