"""Helpers for recording and aggregating customer usage samples."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any

from django.core.cache import cache
from django.utils import timezone

from billing.models import Customer, CustomerUsageSample

_UPTIME_PART = re.compile(r"(\d+)\s*([wdhms])", re.I)
_SAMPLE_MIN_INTERVAL = 25  # seconds between persisted samples per client


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


def record_customer_usage_sample(customer: Customer, payload: dict[str, Any]) -> bool:
    """
    Persist a live usage snapshot when enough time has passed since the last one.

    Returns True when a row was written.
    """
    if not customer or not customer.pk or not customer.organization_id:
        return False

    throttle_key = f"usage_sample_throttle:{customer.pk}"
    if cache.get(throttle_key):
        return False

    now = timezone.now()
    session_active = bool(payload.get("session_active"))
    uptime_seconds = parse_uptime_seconds(payload.get("uptime_raw") or "")
    if not uptime_seconds and session_active:
        # Fallback when only a human label is present.
        uptime_seconds = parse_uptime_seconds(payload.get("uptime") or "")

    def _int(value, default=0):
        try:
            if value is None or value == "":
                return default
            return max(0, int(value))
        except (TypeError, ValueError):
            return default

    CustomerUsageSample.objects.create(
        customer=customer,
        organization_id=customer.organization_id,
        sampled_at=now,
        session_active=session_active,
        uptime_seconds=uptime_seconds if session_active else 0,
        download_bps=_int(payload.get("download_bps")),
        upload_bps=_int(payload.get("upload_bps")),
        bytes_in=_int(payload.get("bytes_in")),
        bytes_out=_int(payload.get("bytes_out")),
        address=(payload.get("cpe_host") or payload.get("address") or "")[:64],
    )
    cache.set(throttle_key, 1, _SAMPLE_MIN_INTERVAL)
    return True


def usage_trend_payload(customer: Customer, *, hours: int = 24) -> dict[str, Any]:
    """Build chart-ready series for uptime, throughput and data used."""
    hours = max(1, min(int(hours or 24), 168))
    since = timezone.now() - timedelta(hours=hours)
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

    labels: list[str] = []
    uptime: list[float | None] = []
    download_kbps: list[float | None] = []
    upload_kbps: list[float | None] = []
    data_used_mb: list[float | None] = []

    previous_total = None
    total_bytes_delta = 0
    online_samples = 0
    peak_down = 0
    peak_up = 0
    max_uptime = 0

    for row in samples:
        stamp = timezone.localtime(row["sampled_at"])
        labels.append(stamp.strftime("%H:%M" if hours <= 48 else "%b %d %H:%M"))
        active = bool(row["session_active"])
        if active:
            online_samples += 1
            max_uptime = max(max_uptime, int(row["uptime_seconds"] or 0))
            down = int(row["download_bps"] or 0)
            up = int(row["upload_bps"] or 0)
            peak_down = max(peak_down, down)
            peak_up = max(peak_up, up)
            uptime.append(round((row["uptime_seconds"] or 0) / 60.0, 2))
            download_kbps.append(round(down / 1000.0, 2))
            upload_kbps.append(round(up / 1000.0, 2))
        else:
            uptime.append(0)
            download_kbps.append(0)
            upload_kbps.append(0)

        total = int(row["bytes_in"] or 0) + int(row["bytes_out"] or 0)
        delta = 0
        if previous_total is not None and total >= previous_total:
            delta = total - previous_total
        elif previous_total is not None and total < previous_total:
            # Session counters reset — count the new absolute total as usage.
            delta = total
        previous_total = total
        total_bytes_delta += delta
        data_used_mb.append(round(delta / (1024 * 1024), 3) if delta else 0)

    latest = samples[-1] if samples else None
    current_session_bytes = 0
    if latest and latest.get("session_active"):
        current_session_bytes = int(latest.get("bytes_in") or 0) + int(
            latest.get("bytes_out") or 0
        )

    return {
        "ok": True,
        "hours": hours,
        "sample_count": len(samples),
        "labels": labels,
        "series": {
            "uptime_minutes": uptime,
            "download_kbps": download_kbps,
            "upload_kbps": upload_kbps,
            "data_used_mb": data_used_mb,
        },
        "summary": {
            "online_ratio": round((online_samples / len(samples)) * 100, 1) if samples else 0,
            "max_uptime_seconds": max_uptime,
            "peak_download_bps": peak_down,
            "peak_upload_bps": peak_up,
            "data_used_bytes": total_bytes_delta,
            "current_session_bytes": current_session_bytes,
            "latest_active": bool(latest and latest.get("session_active")),
        },
    }


def _bucket_seconds(hours: int) -> int:
    if hours <= 6:
        return 10 * 60
    if hours <= 24:
        return 30 * 60
    if hours <= 72:
        return 60 * 60
    return 3 * 60 * 60


def _bytes_delta(previous_total: int | None, total: int) -> int:
    if previous_total is None:
        return 0
    if total >= previous_total:
        return total - previous_total
    # Session counters reset — count the new absolute total as usage.
    return total


def org_usage_payload(organization, *, hours: int = 24, top_n: int = 25) -> dict[str, Any]:
    """Build org-wide usage charts and a highest-users ranking."""
    if not organization:
        return {
            "ok": False,
            "hours": hours,
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
            "error": "No organization.",
        }

    hours = max(1, min(int(hours or 24), 168))
    top_n = max(1, min(int(top_n or 25), 100))
    now = timezone.now()
    since = now - timedelta(hours=hours)
    bucket_secs = _bucket_seconds(hours)
    window_start = int(since.timestamp() // bucket_secs) * bucket_secs
    window_end = int(now.timestamp() // bucket_secs) * bucket_secs
    bucket_keys = list(range(window_start, window_end + bucket_secs, bucket_secs))
    if not bucket_keys:
        bucket_keys = [window_start]

    samples = list(
        CustomerUsageSample.objects.filter(
            organization=organization,
            sampled_at__gte=since,
        )
        .order_by("customer_id", "sampled_at")
        .values(
            "customer_id",
            "sampled_at",
            "session_active",
            "download_bps",
            "upload_bps",
            "bytes_in",
            "bytes_out",
        )
    )

    # Per-bucket aggregates: online set, rate sums, data deltas.
    online_by_bucket: dict[int, set[int]] = {k: set() for k in bucket_keys}
    down_sum: dict[int, float] = {k: 0.0 for k in bucket_keys}
    up_sum: dict[int, float] = {k: 0.0 for k in bucket_keys}
    data_sum: dict[int, float] = {k: 0.0 for k in bucket_keys}

    # Per-customer ranking stats.
    per_customer: dict[int, dict[str, Any]] = {}
    previous_total: dict[int, int] = {}
    total_bytes_delta = 0
    online_samples = 0
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
                "latest_active": False,
            },
        )
        stats["sample_count"] += 1
        active = bool(row["session_active"])
        stats["latest_active"] = active
        down = int(row["download_bps"] or 0)
        up = int(row["upload_bps"] or 0)

        if active:
            online_samples += 1
            stats["online_samples"] += 1
            stats["peak_download_bps"] = max(stats["peak_download_bps"], down)
            stats["peak_upload_bps"] = max(stats["peak_upload_bps"], up)
            peak_down = max(peak_down, down)
            peak_up = max(peak_up, up)
            online_by_bucket.setdefault(bucket, set()).add(cid)
            down_sum[bucket] = down_sum.get(bucket, 0.0) + down
            up_sum[bucket] = up_sum.get(bucket, 0.0) + up

        total = int(row["bytes_in"] or 0) + int(row["bytes_out"] or 0)
        delta = _bytes_delta(previous_total.get(cid), total)
        previous_total[cid] = total
        if delta:
            stats["data_used_bytes"] += delta
            total_bytes_delta += delta
            data_sum[bucket] = data_sum.get(bucket, 0.0) + delta

    customers = {
        c.pk: c
        for c in Customer.objects.filter(
            organization=organization, pk__in=per_customer.keys()
        ).select_related("plan", "router")
    }

    ranked = sorted(
        per_customer.values(),
        key=lambda item: (item["data_used_bytes"], item["peak_download_bps"]),
        reverse=True,
    )
    top_users: list[dict[str, Any]] = []
    for rank, item in enumerate(ranked[:top_n], start=1):
        customer = customers.get(item["customer_id"])
        if not customer:
            continue
        sample_count = item["sample_count"] or 1
        top_users.append(
            {
                "rank": rank,
                "customer_id": customer.pk,
                "full_name": customer.full_name,
                "account_number": customer.account_number,
                "phone": customer.phone,
                "service_type": customer.service_type,
                "service_type_label": customer.get_service_type_display(),
                "plan_name": customer.plan.name if customer.plan_id else "",
                "router_name": customer.router.name if customer.router_id else "",
                "data_used_bytes": item["data_used_bytes"],
                "peak_download_bps": item["peak_download_bps"],
                "peak_upload_bps": item["peak_upload_bps"],
                "online_ratio": round((item["online_samples"] / sample_count) * 100, 1),
                "sample_count": item["sample_count"],
                "latest_active": item["latest_active"],
            }
        )

    labels: list[str] = []
    online_series: list[int] = []
    download_kbps: list[float] = []
    upload_kbps: list[float] = []
    data_used_mb: list[float] = []
    for key in bucket_keys:
        stamp = timezone.localtime(datetime.fromtimestamp(key, tz=dt_timezone.utc))
        labels.append(stamp.strftime("%H:%M" if hours <= 48 else "%b %d %H:%M"))
        online_series.append(len(online_by_bucket.get(key, set())))
        download_kbps.append(round(down_sum.get(key, 0.0) / 1000.0, 2))
        upload_kbps.append(round(up_sum.get(key, 0.0) / 1000.0, 2))
        data_used_mb.append(round(data_sum.get(key, 0.0) / (1024 * 1024), 3))

    clients_with_samples = len(per_customer)
    return {
        "ok": True,
        "hours": hours,
        "sample_count": len(samples),
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
                round(u["data_used_bytes"] / (1024 * 1024), 3) for u in top_users[:10]
            ],
        },
        "summary": {
            "clients_tracked": clients_with_samples,
            "online_ratio": round((online_samples / len(samples)) * 100, 1) if samples else 0,
            "peak_download_bps": peak_down,
            "peak_upload_bps": peak_up,
            "data_used_bytes": total_bytes_delta,
            "top_user_name": top_users[0]["full_name"] if top_users else "",
            "top_user_bytes": top_users[0]["data_used_bytes"] if top_users else 0,
        },
    }
