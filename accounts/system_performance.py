"""Platform-wide system performance board for IT Support."""

from __future__ import annotations

import platform
import socket
import time
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any

from django.core.cache import cache
from django.db.models import Count, Q, Sum
from django.utils import timezone

from accounts.models import Organization
from billing.models import Customer, CustomerUsageSample, Payment, StkPushRequest
from core.mikrotik_status_samples import _OUTAGE_STATUSES, _STATUS_SCORE, status_reason
from core.models import MikroTikRouter, MikroTikStatusSample

_HOST_TREND_CACHE = "it_support:host_metrics_trend:v1"
_HOST_TREND_MAX = 48  # ~20 min at ~25s sample interval


def _mikrotik_status_cache_ttl(all_connected: bool) -> int:
    from django.conf import settings

    if getattr(settings, "HOSTED", False):
        return 45 if all_connected else 25
    return 12 if all_connected else 8


def _probe_org_mikrotik(org: Organization, *, force: bool = False) -> list[dict[str, Any]]:
    """Live MikroTik probe for one ISP — same pipeline as core:mikrotik_status."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from core.mikrotik_status_samples import (
        build_router_probe_plan,
        classify_router_status_row,
        pick_best_probe_for_router,
        probe_mikrotik_hosts,
        record_mikrotik_status_samples,
        stabilize_live_status_rows,
    )

    cache_key = f"mikrotik_status:{org.pk}"
    if not force:
        cached = cache.get(cache_key)
        if isinstance(cached, list):
            try:
                from core.mikrotik_auto_restore import attach_auto_restore_to_rows

                attach_auto_restore_to_rows(cached)
            except Exception:
                pass
            return cached

    routers = list(
        MikroTikRouter.objects.filter(organization=org).only(
            "id",
            "host",
            "name",
            "username",
            "password",
            "serial_number",
            "software_id",
            "vpn_address",
            "vpn_public_key",
        )
    )
    if not routers:
        cache.set(cache_key, [], _mikrotik_status_cache_ttl(True))
        return []

    router_candidates, unique_hosts, tunnel_by_router, off_lan_tunnel_by_router = (
        build_router_probe_plan(routers)
    )
    probe_by_host = probe_mikrotik_hosts(unique_hosts)
    results: dict[int, dict[str, Any]] = {}

    def _check(router):
        host, probe = pick_best_probe_for_router(
            router,
            router_candidates.get(router.id) or [],
            probe_by_host,
        )
        item = classify_router_status_row(
            router,
            host=host,
            probe=probe,
            skip_login=False,
        )
        return router.id, item

    workers = min(8, max(1, len(routers)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check, router) for router in routers]
        for future in as_completed(futures):
            try:
                router_id, payload = future.result()
                results[router_id] = payload
            except Exception:
                continue

    payload: list[dict[str, Any]] = []
    for router in routers:
        item = results.get(
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
        payload.append(dict(item))

    probe_payload = [dict(row) for row in payload]
    payload = stabilize_live_status_rows(
        org.pk,
        payload,
        force=force,
        tunnel_by_router=tunnel_by_router,
        off_lan_tunnel_by_router=off_lan_tunnel_by_router,
    )
    try:
        from core.mikrotik_auto_restore import attach_auto_restore_to_rows

        attach_auto_restore_to_rows(payload)
    except Exception:
        pass

    all_connected = bool(payload) and all(
        (item.get("status") or "") == "connected" for item in payload
    )
    cache.set(cache_key, payload, _mikrotik_status_cache_ttl(all_connected))
    try:
        record_mikrotik_status_samples(org, probe_payload)
    except Exception:
        pass
    return payload


def _load_mikrotik_live_rows(*, force: bool = False) -> tuple[dict[int, list[dict]], bool]:
    """Return org_id -> live status rows; probe when forced or cache is missing."""
    orgs_with_routers = list(
        Organization.objects.filter(mikrotik_routers__isnull=False)
        .distinct()
        .only("id", "name")
    )
    live_by_org: dict[int, list[dict[str, Any]]] = {}
    probed = False
    for org in orgs_with_routers:
        cache_key = f"mikrotik_status:{org.pk}"
        if force or cache.get(cache_key) is None:
            live_by_org[org.pk] = _probe_org_mikrotik(org, force=force)
            probed = True
        else:
            rows = cache.get(cache_key)
            live_by_org[org.pk] = rows if isinstance(rows, list) else []
            try:
                from core.mikrotik_auto_restore import attach_auto_restore_to_rows

                attach_auto_restore_to_rows(live_by_org[org.pk])
            except Exception:
                pass
    return live_by_org, probed


def _router_customer_counts() -> dict[int, dict[str, int]]:
    """Actual subscriber counts per MikroTik from the billing database."""
    rows = (
        Customer.objects.filter(router_id__isnull=False)
        .values("router_id")
        .annotate(
            customer_count=Count("id"),
            active_customers=Count(
                "id", filter=Q(status=Customer.Status.ACTIVE)
            ),
        )
    )
    return {
        int(row["router_id"]): {
            "customer_count": int(row["customer_count"] or 0),
            "active_customers": int(row["active_customers"] or 0),
        }
        for row in rows
    }


def _fleet_score_from_samples(*, since) -> float | None:
    """Fallback fleet score from persisted MikroTik health samples."""
    samples = list(
        MikroTikStatusSample.objects.filter(sampled_at__gte=since)
        .order_by("-sampled_at")
        .values("router_id", "score")[:5000]
    )
    latest: dict[int, int] = {}
    for row in samples:
        rid = int(row["router_id"])
        if rid not in latest:
            latest[rid] = int(row["score"] or 0)
    if not latest:
        return None
    return round(sum(latest.values()) / len(latest), 1)


def _local_day_bounds():
    now = timezone.localtime()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return day_start, day_start + timedelta(days=1), now.date()


def _router_tone(status: str) -> str:
    key = (status or "disconnected").strip().lower()
    if key == "connected":
        return "online"
    if key == "disconnected":
        return "down"
    if key in _OUTAGE_STATUSES:
        return "degraded"
    return "unknown"


def _fleet_label(score: float | None, *, total: int) -> str:
    if total <= 0 or score is None:
        return "No routers"
    if score >= 90:
        return "Healthy"
    if score >= 70:
        return "Fair"
    if score >= 40:
        return "Degraded"
    return "Critical"


def _fmt_bytes(num: float | int | None) -> str:
    if num is None:
        return "—"
    n = float(num)
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    return f"{n:.1f} {units[i]}"


def _usage_tone(pct: float | None) -> str:
    if pct is None:
        return "unknown"
    if pct >= 90:
        return "critical"
    if pct >= 75:
        return "warn"
    return "ok"


def _collect_host_metrics() -> dict[str, Any]:
    """CPU, RAM, disk, and uptime for the application host."""
    empty = {
        "ok": False,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_percent": None,
        "cpu_count": None,
        "ram_percent": None,
        "ram_used": None,
        "ram_total": None,
        "ram_used_label": "—",
        "ram_total_label": "—",
        "disk_percent": None,
        "disk_used": None,
        "disk_total": None,
        "disk_free": None,
        "disk_used_label": "—",
        "disk_total_label": "—",
        "disk_free_label": "—",
        "disk_path": "",
        "boot_time": None,
        "uptime_seconds": None,
        "uptime_label": "—",
        "load_avg": None,
        "process_count": None,
        "cpu_tone": "unknown",
        "ram_tone": "unknown",
        "disk_tone": "unknown",
        "error": "psutil not available",
    }
    try:
        import psutil
    except ImportError:
        return empty

    try:
        # Non-blocking sample; seed once so the first dashboard hit is not always 0.0.
        psutil.cpu_percent(interval=None)
        cpu_percent = float(psutil.cpu_percent(interval=0.05))
        cpu_count = psutil.cpu_count(logical=True) or 0
        mem = psutil.virtual_memory()
        disk_path = str(Path(__file__).resolve().anchor or "/")
        if platform.system() == "Windows":
            disk_path = str(Path(__file__).resolve().drive) + "\\"
        else:
            disk_path = "/"
        disk = psutil.disk_usage(disk_path)
        boot = psutil.boot_time()
        uptime = max(0, int(time.time() - boot))
        hours, rem = divmod(uptime, 3600)
        minutes = rem // 60
        if hours >= 48:
            uptime_label = f"{hours // 24}d {hours % 24}h"
        elif hours >= 1:
            uptime_label = f"{hours}h {minutes}m"
        else:
            uptime_label = f"{minutes}m"

        load_avg = None
        try:
            load_avg = [round(x, 2) for x in psutil.getloadavg()]
        except (AttributeError, OSError):
            load_avg = None

        from datetime import datetime

        boot_dt = datetime.fromtimestamp(boot, tz=timezone.get_current_timezone())
        return {
            "ok": True,
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_percent": round(cpu_percent, 1),
            "cpu_count": cpu_count,
            "ram_percent": round(float(mem.percent), 1),
            "ram_used": int(mem.used),
            "ram_total": int(mem.total),
            "ram_used_label": _fmt_bytes(mem.used),
            "ram_total_label": _fmt_bytes(mem.total),
            "disk_percent": round(float(disk.percent), 1),
            "disk_used": int(disk.used),
            "disk_total": int(disk.total),
            "disk_free": int(disk.free),
            "disk_used_label": _fmt_bytes(disk.used),
            "disk_total_label": _fmt_bytes(disk.total),
            "disk_free_label": _fmt_bytes(disk.free),
            "disk_path": disk_path,
            "boot_time": timezone.localtime(boot_dt).isoformat(),
            "uptime_seconds": uptime,
            "uptime_label": uptime_label,
            "load_avg": load_avg,
            "process_count": len(psutil.pids()),
            "cpu_tone": _usage_tone(cpu_percent),
            "ram_tone": _usage_tone(mem.percent),
            "disk_tone": _usage_tone(disk.percent),
            "error": "",
        }
    except Exception as exc:  # noqa: BLE001 — host probe must never break the page
        empty["error"] = str(exc)[:200]
        return empty


def _append_host_trend(host: dict[str, Any]) -> dict[str, Any]:
    """Keep a short rolling host metric history in cache for sparkline charts."""
    now = timezone.localtime()
    gate_key = f"{_HOST_TREND_CACHE}:gate"
    history = cache.get(_HOST_TREND_CACHE) or []
    if not isinstance(history, list):
        history = []

    # Sample at most once every ~25s so rapid page loads do not flood the series.
    if cache.add(gate_key, 1, 25) or not history:
        history.append(
            {
                "t": now.strftime("%H:%M:%S"),
                "cpu": host.get("cpu_percent"),
                "ram": host.get("ram_percent"),
                "disk": host.get("disk_percent"),
            }
        )
        history = history[-_HOST_TREND_MAX:]
        cache.set(_HOST_TREND_CACHE, history, 60 * 60)

    return {
        "labels": [p.get("t") or "" for p in history],
        "cpu": [p.get("cpu") for p in history],
        "ram": [p.get("ram") for p in history],
        "disk": [p.get("disk") for p in history],
    }


def _build_trends(*, now, day_start) -> dict[str, Any]:
    """Platform trend series for charts (fleet 24h, payments/STK 7d, sessions 24h)."""
    from datetime import datetime, timezone as dt_timezone

    # --- Fleet score (hourly, last 24h) ---
    fleet_since = now - timedelta(hours=24)
    fleet_samples = list(
        MikroTikStatusSample.objects.filter(sampled_at__gte=fleet_since)
        .order_by("sampled_at")
        .values("sampled_at", "score", "online")[:20000]
    )
    fleet_buckets: dict[int, list[int]] = defaultdict(list)
    online_buckets: dict[int, list[int]] = defaultdict(list)
    for row in fleet_samples:
        stamp = row["sampled_at"]
        hour_key = int(stamp.timestamp() // 3600) * 3600
        fleet_buckets[hour_key].append(int(row["score"] or 0))
        online_buckets[hour_key].append(1 if row["online"] else 0)

    fleet_labels: list[str] = []
    fleet_scores: list[float | None] = []
    fleet_online_pct: list[float | None] = []
    start_hour = int(fleet_since.timestamp() // 3600) * 3600
    end_hour = int(now.timestamp() // 3600) * 3600
    for key in range(start_hour, end_hour + 3600, 3600):
        local = timezone.localtime(datetime.fromtimestamp(key, tz=dt_timezone.utc))
        fleet_labels.append(local.strftime("%H:%M"))
        scores = fleet_buckets.get(key)
        onlines = online_buckets.get(key)
        fleet_scores.append(
            round(sum(scores) / len(scores), 1) if scores else None
        )
        fleet_online_pct.append(
            round((sum(onlines) / len(onlines)) * 100, 1) if onlines else None
        )

    # --- Payments + STK (daily, last 7 days; bucket in Python for SQLite) ---
    pay_since = day_start - timedelta(days=6)
    pay_by_day: dict[str, dict[str, float | int]] = defaultdict(
        lambda: {"total": 0.0, "count": 0}
    )
    for row in Payment.objects.filter(received_at__gte=pay_since).values(
        "received_at", "amount"
    ):
        local = timezone.localtime(row["received_at"])
        key = local.date().isoformat()
        pay_by_day[key]["total"] = float(pay_by_day[key]["total"]) + float(
            row["amount"] or 0
        )
        pay_by_day[key]["count"] = int(pay_by_day[key]["count"]) + 1

    stk_by_day: dict[str, dict[str, int]] = defaultdict(
        lambda: {"success": 0, "failed": 0, "total": 0}
    )
    for row in StkPushRequest.objects.filter(created_at__gte=pay_since).values(
        "created_at", "status"
    ):
        local = timezone.localtime(row["created_at"])
        key = local.date().isoformat()
        stk_by_day[key]["total"] += 1
        if row["status"] == StkPushRequest.Status.SUCCESS:
            stk_by_day[key]["success"] += 1
        elif row["status"] == StkPushRequest.Status.FAILED:
            stk_by_day[key]["failed"] += 1

    day_labels: list[str] = []
    pay_totals: list[float] = []
    pay_counts: list[int] = []
    stk_success: list[int] = []
    stk_failed: list[int] = []
    today_date = day_start.date()
    for i in range(7):
        d = today_date - timedelta(days=6 - i)
        key = d.isoformat()
        day_labels.append(d.strftime("%a %d"))
        pay = pay_by_day.get(key, {})
        stk = stk_by_day.get(key, {})
        pay_totals.append(float(pay.get("total") or 0))
        pay_counts.append(int(pay.get("count") or 0))
        stk_success.append(int(stk.get("success") or 0))
        stk_failed.append(int(stk.get("failed") or 0))

    # --- Sessions (hourly unique active customers, last 24h) ---
    session_samples = list(
        CustomerUsageSample.objects.filter(
            sampled_at__gte=fleet_since,
            session_active=True,
        )
        .order_by("sampled_at")
        .values("sampled_at", "customer_id")[:30000]
    )
    session_buckets: dict[int, set[int]] = defaultdict(set)
    for row in session_samples:
        stamp = row["sampled_at"]
        hour_key = int(stamp.timestamp() // 3600) * 3600
        session_buckets[hour_key].add(int(row["customer_id"]))

    session_counts: list[int | None] = []
    for key in range(start_hour, end_hour + 3600, 3600):
        ids = session_buckets.get(key)
        session_counts.append(len(ids) if ids else None)

    return {
        "fleet_24h": {
            "labels": fleet_labels,
            "score": fleet_scores,
            "online_pct": fleet_online_pct,
        },
        "payments_7d": {
            "labels": day_labels,
            "collected": pay_totals,
            "count": pay_counts,
        },
        "stk_7d": {
            "labels": day_labels,
            "success": stk_success,
            "failed": stk_failed,
        },
        "sessions_24h": {
            "labels": fleet_labels,
            "active": session_counts,
        },
    }


def build_system_performance_board(*, force: bool = False) -> dict[str, Any]:
    """Aggregate MikroTik, client, and payment health across all ISP accounts."""
    day_start, day_end, today = _local_day_bounds()
    now = timezone.now()
    usage_cutoff = now - timedelta(minutes=30)

    orgs = list(
        Organization.objects.annotate(
            router_count=Count("mikrotik_routers", distinct=True),
            customer_count=Count("customers", distinct=True),
            active_customer_count=Count(
                "customers",
                filter=Q(customers__status=Customer.Status.ACTIVE),
                distinct=True,
            ),
        )
        .order_by("name")
        .values(
            "id",
            "name",
            "status",
            "router_count",
            "customer_count",
            "active_customer_count",
        )
    )

    db_routers = list(
        MikroTikRouter.objects.select_related("organization")
        .order_by("organization__name", "name")
        .values(
            "id",
            "name",
            "host",
            "location",
            "organization_id",
            "organization__name",
        )
    )
    customer_by_router = _router_customer_counts()
    live_by_org, probed_now = _load_mikrotik_live_rows(force=force)

    router_rows: list[dict[str, Any]] = []
    status_counts: dict[str, int] = defaultdict(int)
    org_router_status: dict[int, dict[str, int]] = defaultdict(
        lambda: {"online": 0, "degraded": 0, "down": 0, "unknown": 0, "total": 0}
    )
    scores: list[int] = []
    has_live_cache = False

    for db in db_routers:
        org_id = db["organization_id"]
        rid = db["id"]
        live_rows = live_by_org.get(org_id) or []
        live = next(
            (row for row in live_rows if isinstance(row, dict) and row.get("id") == rid),
            {},
        )
        counts = customer_by_router.get(rid, {})
        customer_count = counts.get("customer_count", 0)
        active_customers = counts.get("active_customers", 0)

        if live:
            has_live_cache = True
            status = (live.get("status") or "disconnected").strip().lower()
        elif live_rows:
            status = "disconnected"
        else:
            status = "unknown"

        tone = _router_tone(status) if status != "unknown" else "unknown"
        status_counts[tone] += 1
        org_router_status[org_id][tone] += 1
        org_router_status[org_id]["total"] += 1

        score = None
        if status != "unknown":
            score = int(_STATUS_SCORE.get(status, 0))
            scores.append(score)

        router_rows.append(
            {
                "id": rid,
                "name": live.get("name") or db.get("name") or "MikroTik",
                "host": live.get("host") or db.get("host") or "",
                "location": db.get("location") or "",
                "organization_id": org_id,
                "organization_name": db["organization__name"],
                "status": status,
                "tone": tone,
                "score": score,
                "error": live.get("error") or "",
                "reason": status_reason(status, live.get("error"))
                if status != "unknown"
                else "Waiting for first health probe…",
                "customer_count": customer_count,
                "active_customers": active_customers,
                "sessions": int(live.get("sessions") or live.get("active_sessions") or 0),
                "online": bool(live.get("online")) if live else False,
            }
        )

    total_routers = len(db_routers)
    online = status_counts.get("online", 0)
    degraded = status_counts.get("degraded", 0)
    down = status_counts.get("down", 0)
    unknown = status_counts.get("unknown", 0)
    avg_score = round(sum(scores) / len(scores), 1) if scores else None
    if avg_score is None and total_routers:
        avg_score = _fleet_score_from_samples(since=now - timedelta(hours=6))

    customer_stats = Customer.objects.aggregate(
        total=Count("id"),
        active=Count("id", filter=Q(status=Customer.Status.ACTIVE)),
        suspended=Count("id", filter=Q(status=Customer.Status.SUSPENDED)),
        pppoe=Count("id", filter=Q(service_type=Customer.ServiceType.PPPOE)),
        hotspot=Count("id", filter=Q(service_type=Customer.ServiceType.HOTSPOT)),
        static=Count("id", filter=Q(service_type=Customer.ServiceType.STATIC)),
    )

    active_sessions = (
        CustomerUsageSample.objects.filter(
            sampled_at__gte=usage_cutoff,
            session_active=True,
        )
        .values("customer_id")
        .distinct()
        .count()
    )

    pay_today = Payment.objects.filter(
        received_at__gte=day_start,
        received_at__lt=day_end,
    ).aggregate(total=Sum("amount"), count=Count("id"))

    stk_today = StkPushRequest.objects.filter(
        created_at__gte=day_start,
        created_at__lt=day_end,
    ).aggregate(
        total=Count("id"),
        success=Count("id", filter=Q(status=StkPushRequest.Status.SUCCESS)),
        failed=Count("id", filter=Q(status=StkPushRequest.Status.FAILED)),
        pending=Count("id", filter=Q(status=StkPushRequest.Status.PENDING)),
        cancelled=Count("id", filter=Q(status=StkPushRequest.Status.CANCELLED)),
    )

    stk_by_purpose = [
        {
            "purpose": row["purpose"],
            "total": row["total"] or 0,
            "success": row["success"] or 0,
            "failed": row["failed"] or 0,
        }
        for row in StkPushRequest.objects.filter(
            created_at__gte=day_start,
            created_at__lt=day_end,
        )
        .values("purpose")
        .annotate(
            total=Count("id"),
            success=Count("id", filter=Q(status=StkPushRequest.Status.SUCCESS)),
            failed=Count("id", filter=Q(status=StkPushRequest.Status.FAILED)),
        )
        .order_by("-total")
    ]

    recent_payments = list(
        Payment.objects.filter(
            received_at__gte=day_start,
            received_at__lt=day_end,
        )
        .select_related("organization")
        .order_by("-received_at")[:25]
        .values(
            "id",
            "amount",
            "method",
            "reference",
            "phone",
            "received_at",
            "organization__name",
        )
    )

    recent_stk = list(
        StkPushRequest.objects.filter(
            created_at__gte=day_start,
            created_at__lt=day_end,
        )
        .select_related("organization")
        .order_by("-created_at")[:25]
        .values(
            "id",
            "purpose",
            "amount",
            "phone",
            "status",
            "result_desc",
            "created_at",
            "organization__name",
        )
    )

    org_summaries = []
    for org in orgs:
        rs = org_router_status.get(org["id"], {})
        org_summaries.append(
            {
                "id": org["id"],
                "name": org["name"],
                "status": org["status"],
                "router_count": org["router_count"],
                "customer_count": org["customer_count"],
                "active_customer_count": org["active_customer_count"],
                "routers_online": rs.get("online", 0),
                "routers_degraded": rs.get("degraded", 0),
                "routers_down": rs.get("down", 0),
                "routers_unknown": rs.get("unknown", 0),
            }
        )

    board = {
        "ok": True,
        "generated_at": now.isoformat(),
        "day": today.isoformat(),
        "data_sources": {
            "mikrotik": "live_probe" if probed_now else ("cache" if has_live_cache else "database"),
            "customers": "database",
            "payments": "database",
            "stk": "database",
            "sessions": "usage_samples",
            "fleet_trend": "status_samples",
            "host": "psutil",
        },
        "summary": {
            "organizations_total": len(orgs),
            "organizations_active": sum(
                1 for org in orgs if org["status"] == Organization.Status.ACTIVE
            ),
            "routers_total": total_routers,
            "routers_online": online,
            "routers_degraded": degraded,
            "routers_down": down,
            "routers_unknown": unknown,
            "fleet_score": avg_score,
            "fleet_label": _fleet_label(avg_score, total=total_routers),
            "has_live_cache": has_live_cache or probed_now,
            "customers_total": customer_stats["total"] or 0,
            "customers_active": customer_stats["active"] or 0,
            "customers_suspended": customer_stats["suspended"] or 0,
            "active_sessions": active_sessions,
            "collected_today": float(pay_today["total"] or 0),
            "payments_today": pay_today["count"] or 0,
            "stk_total_today": stk_today["total"] or 0,
            "stk_success_today": stk_today["success"] or 0,
            "stk_failed_today": stk_today["failed"] or 0,
            "stk_pending_today": stk_today["pending"] or 0,
        },
        "trends": _build_trends(now=now, day_start=day_start),
        "host": {},
        "mikrotik": {
            "status_breakdown": {
                "online": online,
                "degraded": degraded,
                "down": down,
                "unknown": unknown,
            },
            "routers": router_rows,
            "organizations": org_summaries,
        },
        "communications": {
            "active_sessions": active_sessions,
            "customers_active": customer_stats["active"] or 0,
            "customers_by_service": {
                "pppoe": customer_stats["pppoe"] or 0,
                "hotspot": customer_stats["hotspot"] or 0,
                "static": customer_stats["static"] or 0,
            },
        },
        "payments": {
            "collected_today": float(pay_today["total"] or 0),
            "payments_count": pay_today["count"] or 0,
            "stk": {
                "total": stk_today["total"] or 0,
                "success": stk_today["success"] or 0,
                "failed": stk_today["failed"] or 0,
                "pending": stk_today["pending"] or 0,
                "cancelled": stk_today["cancelled"] or 0,
            },
            "by_purpose": stk_by_purpose,
            "recent_payments": [
                {
                    "id": row["id"],
                    "organization": row["organization__name"],
                    "amount": float(row["amount"]),
                    "method": row["method"],
                    "reference": row["reference"],
                    "phone": row["phone"],
                    "received_at": row["received_at"].isoformat()
                    if row["received_at"]
                    else "",
                }
                for row in recent_payments
            ],
            "recent_stk": [
                {
                    "id": row["id"],
                    "organization": row["organization__name"],
                    "purpose": row["purpose"],
                    "amount": float(row["amount"]),
                    "phone": row["phone"],
                    "status": row["status"],
                    "result_desc": row["result_desc"],
                    "created_at": row["created_at"].isoformat()
                    if row["created_at"]
                    else "",
                }
                for row in recent_stk
            ],
        },
    }

    host = _collect_host_metrics()
    board["host"] = host
    board["trends"]["host"] = _append_host_trend(host)

    return board
