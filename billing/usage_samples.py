"""Helpers for recording and aggregating customer usage samples."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any

from django.core.cache import cache
from django.utils import timezone

from billing.models import Customer, CustomerUsageSample

_UPTIME_PART = re.compile(r"(\d+)\s*([wdhms])", re.I)
_SAMPLE_MIN_INTERVAL = 25  # seconds between persisted samples per client
_OFFLINE_SAMPLE_MIN_INTERVAL = 300  # avoid flooding zeros when clients are offline
_ORG_SAMPLE_TTL = 45  # seconds between org-wide MikroTik sweeps
_ORG_PAYLOAD_TTL = 20  # seconds for aggregated chart payloads
_CLIENT_TREND_TTL = 20  # short cache for per-client chart payloads
_CLIENT_TREND_MAX_POINTS = 48  # hard cap on chart buckets
_CLIENT_SAMPLE_CAP = 1200  # max rows scanned per client trend request
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


def record_customer_usage_sample(customer: Customer, payload: dict[str, Any]) -> bool:
    """
    Persist a live usage snapshot when enough time has passed since the last one.

    Returns True when a row was written.
    """
    if not customer or not customer.pk or not customer.organization_id:
        return False

    session_active = bool(payload.get("session_active"))
    bytes_in = _as_int(payload.get("bytes_in"))
    bytes_out = _as_int(payload.get("bytes_out"))
    # Skip empty offline probes — they drown real traffic history and break
    # counter continuity when treated as session resets.
    if not session_active and bytes_in == 0 and bytes_out == 0:
        throttle_key = f"usage_sample_offline:{customer.pk}"
        if cache.get(throttle_key):
            return False
        # Still record a sparse offline marker for presence charts (throttled).
        interval = _OFFLINE_SAMPLE_MIN_INTERVAL
    else:
        throttle_key = f"usage_sample_throttle:{customer.pk}"
        interval = _SAMPLE_MIN_INTERVAL
        if cache.get(throttle_key):
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
        cache.delete(f"client_usage_trend:{customer_id}:{hours}")


def sample_organization_usage(organization, *, force: bool = False) -> dict[str, Any]:
    """
    Lightweight org-wide snapshot: one MikroTik call per router (no per-client
    monitor-traffic). Records samples for matched PPPoE / Hotspot clients.

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
    for customer in customers:
        router_id = customer.router_id
        if not router_id:
            continue
        if customer.service_type == Customer.ServiceType.PPPOE:
            key = (customer.pppoe_username or "").strip().lower()
            if key:
                pppoe_by_router.setdefault(router_id, {})[key] = customer
        elif customer.service_type == Customer.ServiceType.HOTSPOT:
            mac = "".join(
                ch for ch in (customer.hotspot_mac or "") if ch.isalnum()
            ).upper()
            if len(mac) == 12:
                hotspot_by_router.setdefault(router_id, {})[mac] = customer

    def _probe(router: MikroTikRouter) -> tuple[int, list[tuple[Customer, dict[str, Any]]]]:
        hits: list[tuple[Customer, dict[str, Any]]] = []
        pppoe_map = pppoe_by_router.get(router.pk) or {}
        hotspot_map = hotspot_by_router.get(router.pk) or {}
        if pppoe_map:
            result = fetch_router_bulk_pppoe_usage(
                router.host,
                router.username,
                router.password or "",
                timeout=_ORG_SAMPLE_ROUTER_TIMEOUT,
            )
            for username, payload in (result.get("sessions") or {}).items():
                customer = pppoe_map.get(username)
                if customer:
                    hits.append((customer, payload))
        if hotspot_map:
            result = fetch_router_bulk_hotspot_usage(
                router.host,
                router.username,
                router.password or "",
                timeout=_ORG_SAMPLE_ROUTER_TIMEOUT,
            )
            for mac, payload in (result.get("sessions") or {}).items():
                customer = hotspot_map.get(mac)
                if customer:
                    hits.append((customer, payload))
        return router.pk, hits

    sampled = 0
    workers = min(_ORG_SAMPLE_WORKERS, len(routers))
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(_probe, router) for router in routers]
        for future in as_completed(futures):
            try:
                _router_id, hits = future.result()
            except Exception:
                continue
            for customer, payload in hits:
                try:
                    if record_customer_usage_sample(customer, payload):
                        sampled += 1
                except Exception:
                    continue

    # Invalidate payload caches so the next read includes fresh samples.
    for hours in _USAGE_RANGE_CACHE_HOURS:
        for top_n in (0, 25, 100, 200, 300):
            for service in ("all", "pppoe", "hotspot"):
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
    cache_key = f"client_usage_trend:{customer.pk}:{hours}"
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
        .order_by("-sampled_at")
        .values(
            "sampled_at",
            "session_active",
            "uptime_seconds",
            "download_bps",
            "upload_bps",
            "bytes_in",
            "bytes_out",
        )[:_CLIENT_SAMPLE_CAP]
    )
    samples.reverse()  # chronological for byte-delta math

    online_by_bucket: dict[int, bool] = {}
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
        bi = int(row["bytes_in"] or 0)
        bo = int(row["bytes_out"] or 0)
        total = bi + bo
        down = int(row["download_bps"] or 0)
        up = int(row["upload_bps"] or 0)
        seen_by_bucket[bucket] = True

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
    data_used_mb: list[float | None] = []
    online_flags: list[int | None] = []
    prime_index: int | None = None
    lowest_index: int | None = None
    stop_indexes: list[int] = []
    fmt = _chart_label_format(hours)

    for idx, key in enumerate(chart_keys):
        labels.append(
            timezone.localtime(datetime.fromtimestamp(key, tz=dt_timezone.utc)).strftime(
                fmt
            )
        )
        has_signal = key in seen_by_bucket or key in data_by_bucket
        if not has_signal:
            online_flags.append(None)
            download_kbps.append(None)
            upload_kbps.append(None)
            data_used_mb.append(None)
            continue

        is_online = bool(online_by_bucket.get(key))
        online_flags.append(1 if is_online else 0)
        download_kbps.append(
            round(down_by_bucket.get(key, 0.0) / 1000.0, 2) if is_online else 0
        )
        upload_kbps.append(
            round(up_by_bucket.get(key, 0.0) / 1000.0, 2) if is_online else 0
        )
        data_used_mb.append(round(data_by_bucket.get(key, 0.0) / (1024 * 1024), 3))
        if prime_bucket == key:
            prime_index = idx
        if lowest_bucket == key:
            lowest_index = idx
        if key in stop_buckets and idx > 0 and online_flags[idx - 1] == 1:
            stop_indexes.append(idx)

    latest = samples[-1] if samples else None
    current_session_bytes = 0
    if latest and latest.get("session_active"):
        current_session_bytes = int(latest.get("bytes_in") or 0) + int(
            latest.get("bytes_out") or 0
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
            "data_used_mb": data_used_mb,
            "online": online_flags,
        },
        "markers": {
            "peak_index": prime_index,
            "low_index": lowest_index,
            "stop_indexes": stop_indexes[:6],
        },
        "summary": {
            "online_ratio": (
                round((online_samples / len(samples)) * 100, 1) if samples else 0
            ),
            "peak_download_bps": peak_down,
            "peak_upload_bps": peak_up,
            "data_used_bytes": total_bytes_delta,
            "current_session_bytes": current_session_bytes,
            "latest_active": bool(latest and latest.get("session_active")),
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
    return total


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


def _build_org_usage_payload(
    organization, *, hours: int = 24, top_n: int = 0, service: str = ""
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

    ranked = sorted(
        (
            per_customer.get(cid) or _empty_stats(cid)
            for cid in customers.keys()
        ),
        key=lambda item: (
            item["data_used_bytes"],
            item["peak_session_bytes"],
            item["peak_download_bps"],
            item["online_samples"],
            customers.get(item["customer_id"]).full_name if customers.get(item["customer_id"]) else "",
        ),
        reverse=True,
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
    online_now = sum(1 for item in per_customer.values() if item["latest_active"])
    gadgets_online = sum(int(u.get("gadgets_connected") or 0) for u in top_users)
    return {
        "ok": True,
        "hours": hours,
        "requested_hours": hours,
        "auto_widened": False,
        "service": service or "all",
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
    auto_widen: bool = True,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Build org-wide usage charts and a per-user ranking."""
    if not organization:
        return _empty_org_payload(hours, error="No organization.")

    hours = clamp_usage_hours(hours, default=24)
    top_n = max(0, min(int(top_n or 0), 5000))
    service = _normalize_usage_service(service)
    cache_key = (
        f"org_usage_payload:v3:{organization.pk}:{hours}:{top_n}:{service or 'all'}"
    )
    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    payload = _build_org_usage_payload(
        organization, hours=hours, top_n=top_n, service=service
    )
    has_signal = bool(
        payload.get("summary", {}).get("data_used_bytes")
        or payload.get("summary", {}).get("peak_download_bps")
        or payload.get("summary", {}).get("clients_online")
        or (payload.get("top_users") or [])
    )
    if auto_widen and not has_signal and hours < _MAX_USAGE_HOURS:
        for candidate in (72, 168, 720, 8760):
            if candidate <= hours:
                continue
            wider = _build_org_usage_payload(
                organization, hours=candidate, top_n=top_n, service=service
            )
            wider_signal = bool(
                wider.get("summary", {}).get("data_used_bytes")
                or wider.get("summary", {}).get("peak_download_bps")
                or (wider.get("top_users") or [])
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
