"""Helpers for recording and aggregating customer usage samples."""

from __future__ import annotations

import re
from datetime import timedelta
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
