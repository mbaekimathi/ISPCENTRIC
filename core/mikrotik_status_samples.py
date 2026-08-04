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
_OUTAGE_STATUSES = frozenset(
    {"disconnected", "auth_failed", "wrong_host", "limited"}
)
_SAMPLE_GATE_TTL = 55  # seconds between org-wide status sample writes
_OUTAGE_SAMPLE_GATE_TTL = 12  # allow outage transitions through sooner
_TREND_CACHE_TTL = 20
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


def record_mikrotik_status_samples(organization, routers: list[dict[str, Any]]) -> int:
    """
    Persist one health sample per router from a mikrotik_status payload.

    Gated so dashboard polling cannot flood the database.
    """
    if not organization or not routers:
        return 0
    has_outage = any(
        (row.get("status") or "").strip().lower() in _OUTAGE_STATUSES
        for row in routers
    )
    gate = f"mikrotik_status_sample_gate:{organization.pk}"
    # Healthy polls stay gated; outages bypass so the trend drops immediately
    # instead of forward-filling the last Connected score for up to ~55s.
    if cache.get(gate) and not has_outage:
        return 0
    cache.set(gate, 1, _OUTAGE_SAMPLE_GATE_TTL if has_outage else _SAMPLE_GATE_TTL)

    now = timezone.now()
    router_ids = {
        int(row["id"])
        for row in routers
        if row.get("id") is not None
    }
    if not router_ids:
        return 0
    known = set(
        MikroTikRouter.objects.filter(
            organization=organization, pk__in=router_ids
        ).values_list("id", flat=True)
    )
    rows = []
    for row in routers:
        rid = row.get("id")
        if rid is None or int(rid) not in known:
            continue
        status = (row.get("status") or "disconnected").strip().lower()
        rows.append(
            MikroTikStatusSample(
                organization=organization,
                router_id=int(rid),
                sampled_at=now,
                status=status[:32],
                score=status_score(status),
                online=bool(row.get("online")) or status == "connected",
            )
        )
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
        for key in bucket_keys:
            value = by_bucket.get(key, {}).get(router.pk)
            if value is None:
                series.append(last)
            else:
                last = value
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

    payload = {
        "ok": True,
        "hours": hours,
        "labels": labels,
        "datasets": datasets,
        "routers": list(router_meta.values()),
        "average": average,
        "sample_count": len(samples),
    }
    cache.set(cache_key, payload, _TREND_CACHE_TTL)
    return payload
