"""NOC ops console — alarms, severity, site matrix, timeline, inspector data."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from django.core.cache import cache
from django.db.models import Count, Q
from django.urls import reverse
from django.utils import timezone

from core.mikrotik_status_samples import (
    mikrotik_performance_drops,
    status_catalog,
    status_reason,
    status_score,
)
from core.models import MikroTikRouter, MikroTikStatusSample


_OUTAGE_STATUSES = frozenset(status_catalog().get("outage_statuses") or [])
_SEVERITY_RANK = {"critical": 0, "major": 1, "minor": 2, "info": 3, "ok": 4}

# Client quality thresholds (usage samples vs plan Mbps).
_PERF_LOOKBACK_MINUTES = 30
_PERF_MIN_SAMPLES = 3
_PERF_MIN_UPTIME_SEC = 180
_PERF_IDLE_BPS = 12_000  # ~12 kbps — effectively no useful traffic
_PERF_UNDERPERFORM_RATIO = 0.15  # peak < 15% of plan → underperforming
_PERF_FAIR_RATIO = 0.40
_PERF_CLIENT_LIMIT = 80
_PERF_IMPROVE_LIMIT = 12
# Sold package Mbps vs real uplink: warn / act thresholds.
_OVERSUB_WARN_RATIO = 3.0
_OVERSUB_CRITICAL_RATIO = 5.0


def router_uplink_capacity_mbps(router) -> int | None:
    """Resolve NAS uplink capacity; prefer model helper when available."""
    if router is None:
        return None
    resolver = getattr(router, "resolved_uplink_capacity_mbps", None)
    if callable(resolver):
        return resolver()
    explicit = int(getattr(router, "uplink_capacity_mbps", 0) or 0)
    if explicit > 0:
        return explicit
    weights = getattr(router, "uplink_weights", None)
    if isinstance(weights, dict) and weights:
        total = 0
        for value in weights.values():
            try:
                mbps = int(value or 0)
            except (TypeError, ValueError):
                continue
            if mbps > 0:
                total += mbps
        if total > 0:
            return total
    return None


def _empty_board() -> dict[str, Any]:
    return {
        "ok": False,
        "generated_at": timezone.now().isoformat(),
        "summary": {
            "routers_total": 0,
            "routers_online": 0,
            "routers_degraded": 0,
            "routers_down": 0,
            "customers_total": 0,
            "customers_at_risk": 0,
            "customers_on_down": 0,
            "customers_on_degraded": 0,
            "problem_health_score": None,
            "outage_count": 0,
            "faults_open": 0,
            "faults_status_open": 0,
            "faults_assigned": 0,
            "faults_in_progress": 0,
            "faults_unassigned": 0,
            "alarms_open": 0,
            "alarms_critical": 0,
            "alarms_major": 0,
            "alarms_minor": 0,
            "sites_total": 0,
            "health_score": None,
            "health_label": "No routers",
            "has_live_cache": False,
            "sessions_active": 0,
            "clients_underperforming": 0,
            "clients_idle": 0,
            "clients_non_optimal": 0,
            "fleet_throughput_mbps": 0.0,
            "performance_score": None,
            "performance_label": "No data",
            "has_usage_samples": False,
        },
        "routers": [],
        "alarms": [],
        "sites": [],
        "timeline": [],
        "drops": {"ok": False, "events": [], "current_count": 0},
        "faults": [],
        "non_optimal_clients": [],
        "improvements": [],
        "status_catalog": status_catalog(),
    }


def _classify_tone(status: str) -> str:
    key = (status or "disconnected").strip().lower() or "disconnected"
    if key == "connected":
        return "online"
    if key == "disconnected":
        return "down"
    if key in _OUTAGE_STATUSES:
        return "degraded"
    return "degraded"


def _severity_for_router(*, status: str, tone: str, customer_count: int) -> str:
    key = (status or "").strip().lower()
    if tone == "online" or key == "connected":
        return "ok"
    if key == "unknown":
        return "info"
    if key == "disconnected":
        return "critical" if customer_count > 0 else "major"
    if key in {"auth_failed", "wrong_host"}:
        return "critical" if customer_count > 0 else "major"
    if key in {"limited", "reachable"}:
        return "major" if customer_count > 0 else "minor"
    return "minor"


def _health_label(score: int | None, *, total: int) -> str:
    if total <= 0 or score is None:
        return "No routers"
    if score >= 90:
        return "Healthy"
    if score >= 70:
        return "Fair"
    if score >= 40:
        return "Degraded"
    return "Critical"


def _site_key(location: str) -> str:
    text = (location or "").strip()
    return text.lower() if text else "__unassigned__"


def _site_label(location: str) -> str:
    text = (location or "").strip()
    return text or "Unassigned site"


def build_noc_board(organization, *, fault_limit: int = 60) -> dict[str, Any]:
    """
    Build a detailed NOC console payload for one organization.

    Uses cached mikrotik_status when present (no fresh probes here).
    """
    if not organization:
        return _empty_board()

    live_rows = cache.get(f"mikrotik_status:{organization.pk}")
    if not isinstance(live_rows, list):
        live_rows = []

    try:
        from core.mikrotik_auto_restore import attach_auto_restore_to_rows

        attach_auto_restore_to_rows(live_rows)
    except Exception:
        pass

    live_by_id = {
        int(row["id"]): row
        for row in live_rows
        if isinstance(row, dict) and row.get("id") is not None
    }

    routers_qs = list(
        MikroTikRouter.objects.filter(organization=organization)
        .annotate(
            customer_count=Count("customers"),
            active_customers=Count(
                "customers",
                filter=Q(customers__status="active"),
            ),
            suspended_customers=Count(
                "customers",
                filter=Q(customers__status="suspended"),
            ),
        )
        .only(
            "id",
            "name",
            "host",
            "location",
            "location_lat",
            "location_lng",
            "account_status",
            "model",
            "vpn_address",
            "serial_number",
            "uplink_capacity_mbps",
            "uplink_weights",
        )
        .order_by("name", "id")
    )

    sparklines = _router_sparklines(organization, [r.pk for r in routers_qs])
    last_changes = _router_last_changes(organization, [r.pk for r in routers_qs])

    routers: list[dict[str, Any]] = []
    online = degraded = down = 0
    score_sum = 0
    scored = 0
    customers_total = 0
    customers_at_risk = 0

    for router in routers_qs:
        live = live_by_id.get(router.pk) or {}
        status = (live.get("status") or "").strip().lower()
        if not status:
            status = "disconnected" if live_rows else "unknown"
        if status == "unknown":
            tone = "unknown"
            score = None
            reason = "Waiting for first health probe…"
        else:
            tone = _classify_tone(status)
            score = status_score(status)
            reason = status_reason(status, live.get("error"))
            score_sum += score
            scored += 1
            if tone == "online":
                online += 1
            elif tone == "down":
                down += 1
            else:
                degraded += 1

        customer_count = int(router.customer_count or 0)
        active_customers = int(router.active_customers or 0)
        customers_total += customer_count
        severity = _severity_for_router(
            status=status, tone=tone, customer_count=customer_count
        )
        if severity in {"critical", "major"}:
            customers_at_risk += customer_count

        auto_restore = live.get("auto_restore") if isinstance(live, dict) else None
        spark = sparklines.get(router.pk) or {"scores": [], "labels": []}
        change = last_changes.get(router.pk) or {}

        lat = router.location_lat
        lng = getattr(router, "location_lng", None)
        routers.append(
            {
                "id": router.pk,
                "name": router.name or f"Router {router.pk}",
                "host": (live.get("host") or router.host or "").strip(),
                "vpn_address": (router.vpn_address or "").strip(),
                "serial_number": (
                    (live.get("serial_number") or router.serial_number or "")
                ).strip(),
                "model": router.get_model_display() if router.model else "",
                "location": (router.location or "").strip(),
                "site_key": _site_key(router.location or ""),
                "site_label": _site_label(router.location or ""),
                "lat": float(lat) if lat is not None else None,
                "lng": float(lng) if lng is not None else None,
                "account_status": router.account_status,
                "customer_count": customer_count,
                "active_customers": active_customers,
                "suspended_customers": int(router.suspended_customers or 0),
                "uplink_capacity_mbps": router_uplink_capacity_mbps(router),
                "status": status,
                "tone": tone,
                "severity": severity,
                "score": score,
                "reason": reason,
                "via": (live.get("via") or "").strip(),
                "online": bool(live.get("online")) if live else False,
                "management_deferred": bool(live.get("management_deferred")),
                "auto_restore": auto_restore if isinstance(auto_restore, dict) else None,
                "sparkline": spark.get("scores") or [],
                "sparkline_labels": spark.get("labels") or [],
                "last_change_at": change.get("at") or "",
                "last_change_from": change.get("from_status") or "",
                "last_change_to": change.get("to_status") or status,
                "detail_url": reverse(
                    "core:mikrotik_detail", kwargs={"router_id": router.pk}
                ),
                "reconnect_url": reverse(
                    "core:mikrotik_reconnect", kwargs={"router_id": router.pk}
                ),
                "reboot_url": reverse(
                    "core:mikrotik_reboot", kwargs={"router_id": router.pk}
                ),
                "clients_url": (
                    f"{reverse('core:my_clients')}?tab=pppoe&router={router.pk}"
                ),
            }
        )

    tone_rank = {"down": 0, "degraded": 1, "unknown": 2, "online": 3}
    routers.sort(
        key=lambda row: (
            _SEVERITY_RANK.get(row.get("severity") or "ok", 9),
            tone_rank.get(row.get("tone") or "unknown", 9),
            -(row.get("customer_count") or 0),
            (row.get("name") or "").lower(),
            row.get("id") or 0,
        )
    )

    try:
        drops = mikrotik_performance_drops(
            organization, hours=24, live_routers=live_rows, max_events=24
        )
    except Exception:
        drops = {"ok": False, "events": [], "current_count": 0}

    faults = _open_faults(organization, limit=fault_limit)
    alarms = _build_alarms(routers, drops, faults)
    sites = _build_sites(routers)
    timeline = _build_timeline(drops, faults, routers)

    total = len(routers)
    avg_score = round(score_sum / scored) if scored else None
    outage_count = int(drops.get("current_count") or 0) if drops.get("ok") else (
        degraded + down
    )
    alarm_counts = {"critical": 0, "major": 0, "minor": 0, "info": 0}
    for alarm in alarms:
        sev = alarm.get("severity") or "info"
        if sev in alarm_counts:
            alarm_counts[sev] += 1

    fault_open = sum(1 for f in faults if f.get("status") == "open")
    fault_assigned = sum(1 for f in faults if f.get("status") == "assigned")
    fault_progress = sum(1 for f in faults if f.get("status") == "in_progress")
    fault_unassigned = sum(
        1 for f in faults if (f.get("technician") or "Unassigned") == "Unassigned"
    )
    down_customers = sum(
        int(r.get("customer_count") or 0)
        for r in routers
        if r.get("tone") == "down"
    )
    degraded_customers = sum(
        int(r.get("customer_count") or 0)
        for r in routers
        if r.get("tone") == "degraded"
    )
    problem_routers = [r for r in routers if r.get("severity") != "ok"]
    problem_scores = [int(r["score"]) for r in problem_routers if r.get("score") is not None]
    problem_avg = round(sum(problem_scores) / len(problem_scores)) if problem_scores else None

    performance = _build_performance(organization, routers)
    for row in routers:
        perf = performance["by_router"].get(int(row["id"])) or _empty_router_performance()
        row["performance"] = perf

    return {
        "ok": True,
        "generated_at": timezone.now().isoformat(),
        "summary": {
            "routers_total": total,
            "routers_online": online,
            "routers_degraded": degraded,
            "routers_down": down,
            "customers_total": customers_total,
            "customers_at_risk": customers_at_risk,
            "customers_on_down": down_customers,
            "customers_on_degraded": degraded_customers,
            "problem_health_score": problem_avg,
            "outage_count": outage_count,
            "faults_open": len(faults),
            "faults_status_open": fault_open,
            "faults_assigned": fault_assigned,
            "faults_in_progress": fault_progress,
            "faults_unassigned": fault_unassigned,
            "alarms_open": len(alarms),
            "alarms_critical": alarm_counts["critical"],
            "alarms_major": alarm_counts["major"],
            "alarms_minor": alarm_counts["minor"],
            "sites_total": len(sites),
            "health_score": avg_score,
            "health_label": _health_label(avg_score, total=total),
            "has_live_cache": bool(live_rows),
            "sessions_active": performance["summary"]["sessions_active"],
            "clients_underperforming": performance["summary"]["clients_underperforming"],
            "clients_idle": performance["summary"]["clients_idle"],
            "clients_non_optimal": performance["summary"]["clients_non_optimal"],
            "fleet_throughput_mbps": performance["summary"]["fleet_throughput_mbps"],
            "performance_score": performance["summary"]["performance_score"],
            "performance_label": performance["summary"]["performance_label"],
            "has_usage_samples": performance["summary"]["has_usage_samples"],
            "sold_download_mbps": performance["summary"].get("sold_download_mbps", 0),
            "uplink_capacity_mbps": performance["summary"].get("uplink_capacity_mbps"),
            "oversubscription_ratio": performance["summary"].get(
                "oversubscription_ratio"
            ),
            "routers_oversubscribed": performance["summary"].get(
                "routers_oversubscribed", 0
            ),
            "routers_missing_capacity": performance["summary"].get(
                "routers_missing_capacity", 0
            ),
        },
        "routers": routers,
        "alarms": alarms,
        "sites": sites,
        "timeline": timeline,
        "drops": drops,
        "faults": faults,
        "non_optimal_clients": performance["non_optimal_clients"],
        "improvements": performance["improvements"],
        "status_catalog": status_catalog(),
    }


def _router_sparklines(
    organization, router_ids: list[int], *, points: int = 24
) -> dict[int, dict[str, list]]:
    if not organization or not router_ids:
        return {}
    since = timezone.now() - timedelta(hours=24)
    rows = list(
        MikroTikStatusSample.objects.filter(
            organization=organization,
            router_id__in=router_ids,
            sampled_at__gte=since,
        )
        .order_by("router_id", "-sampled_at")
        .values("router_id", "sampled_at", "score")[
            : max(1, len(router_ids) * points * 2)
        ]
    )
    by_router: dict[int, list[tuple[Any, int]]] = defaultdict(list)
    for row in rows:
        rid = int(row["router_id"])
        if len(by_router[rid]) >= points:
            continue
        by_router[rid].append((row["sampled_at"], int(row["score"] or 0)))

    out: dict[int, dict[str, list]] = {}
    for rid, pairs in by_router.items():
        pairs.reverse()
        out[rid] = {
            "scores": [score for _, score in pairs],
            "labels": [
                timezone.localtime(stamp).strftime("%H:%M") for stamp, _ in pairs
            ],
        }
    return out


def _router_last_changes(
    organization, router_ids: list[int]
) -> dict[int, dict[str, str]]:
    if not organization or not router_ids:
        return {}
    since = timezone.now() - timedelta(hours=48)
    rows = list(
        MikroTikStatusSample.objects.filter(
            organization=organization,
            router_id__in=router_ids,
            sampled_at__gte=since,
        )
        .order_by("router_id", "sampled_at")
        .values("router_id", "sampled_at", "status")[
            : max(1, min(len(router_ids) * 200, 4000))
        ]
    )
    previous: dict[int, str] = {}
    last_change: dict[int, dict[str, str]] = {}
    for row in rows:
        rid = int(row["router_id"])
        status = (row["status"] or "disconnected").strip().lower()
        prev = previous.get(rid)
        if prev and prev != status:
            last_change[rid] = {
                "from_status": prev,
                "to_status": status,
                "at": timezone.localtime(row["sampled_at"]).strftime("%d %b %H:%M"),
            }
        previous[rid] = status
    return last_change


def _build_alarms(
    routers: list[dict[str, Any]],
    drops: dict[str, Any],
    faults: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    alarms: list[dict[str, Any]] = []
    for row in routers:
        severity = row.get("severity") or "ok"
        if severity == "ok":
            continue
        alarms.append(
            {
                "id": f"router-{row['id']}",
                "kind": "router",
                "severity": severity,
                "title": (
                    f"{row['name']} is "
                    f"{str(row.get('status') or 'unknown').replace('_', ' ')}"
                ),
                "detail": row.get("reason") or "",
                "router_id": row["id"],
                "router_name": row["name"],
                "site_label": row.get("site_label") or "",
                "customers": row.get("customer_count") or 0,
                "score": row.get("score"),
                "status": row.get("status") or "",
                "at": row.get("last_change_at") or "",
                "source": "fleet",
            }
        )

    for event in drops.get("events") or []:
        if not event.get("current"):
            continue
        rid = event.get("router_id")
        if any(a.get("router_id") == rid and a.get("kind") == "router" for a in alarms):
            continue
        score = event.get("to_score")
        severity = "critical" if int(score or 0) <= 10 else "major"
        alarms.append(
            {
                "id": f"drop-{rid}-{event.get('at_iso') or event.get('at')}",
                "kind": "drop",
                "severity": severity,
                "title": f"{event.get('router_name') or 'Router'} health drop",
                "detail": event.get("reason") or "",
                "router_id": rid,
                "router_name": event.get("router_name") or "",
                "site_label": "",
                "customers": 0,
                "score": score,
                "status": event.get("status") or "",
                "at": event.get("at") or "",
                "source": "health",
            }
        )

    for fault in faults:
        severity = "major" if fault.get("issue") == "no_connectivity" else "minor"
        alarms.append(
            {
                "id": f"fault-{fault['id']}",
                "kind": "fault",
                "severity": severity,
                "title": f"{fault.get('ticket_number')} · {fault.get('issue_label')}",
                "detail": fault.get("notes")
                or f"{fault.get('customer_name')} — {fault.get('status_label')}",
                "router_id": fault.get("router_id"),
                "router_name": fault.get("router_name") or "",
                "site_label": "",
                "customers": 1,
                "score": None,
                "status": fault.get("status") or "",
                "at": fault.get("created_at") or "",
                "source": "fault",
                "customer_url": fault.get("customer_url") or "",
                "customer_name": fault.get("customer_name") or "",
                "technician": fault.get("technician") or "",
            }
        )

    alarms.sort(
        key=lambda row: (
            _SEVERITY_RANK.get(row.get("severity") or "info", 9),
            -(row.get("customers") or 0),
            (row.get("title") or "").lower(),
        )
    )
    return alarms


def _build_sites(routers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in routers:
        key = row.get("site_key") or "__unassigned__"
        bucket = grouped.get(key)
        if bucket is None:
            bucket = {
                "key": key,
                "label": row.get("site_label") or "Unassigned site",
                "routers_total": 0,
                "routers_online": 0,
                "routers_down": 0,
                "routers_degraded": 0,
                "customers": 0,
                "customers_at_risk": 0,
                "worst_severity": "ok",
                "router_ids": [],
            }
            grouped[key] = bucket
        bucket["routers_total"] += 1
        bucket["customers"] += int(row.get("customer_count") or 0)
        bucket["router_ids"].append(row["id"])
        tone = row.get("tone")
        if tone == "online":
            bucket["routers_online"] += 1
        elif tone == "down":
            bucket["routers_down"] += 1
        else:
            bucket["routers_degraded"] += 1
        if row.get("severity") in {"critical", "major"}:
            bucket["customers_at_risk"] += int(row.get("customer_count") or 0)
        sev = row.get("severity") or "ok"
        if _SEVERITY_RANK.get(sev, 9) < _SEVERITY_RANK.get(
            bucket["worst_severity"], 9
        ):
            bucket["worst_severity"] = sev

    sites = list(grouped.values())
    sites.sort(
        key=lambda row: (
            _SEVERITY_RANK.get(row.get("worst_severity") or "ok", 9),
            -(row.get("customers_at_risk") or 0),
            (row.get("label") or "").lower(),
        )
    )
    return sites


def _build_timeline(
    drops: dict[str, Any],
    faults: list[dict[str, Any]],
    routers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for event in drops.get("events") or []:
        events.append(
            {
                "id": (
                    f"tl-drop-{event.get('router_id')}-"
                    f"{event.get('at_iso') or event.get('at')}"
                ),
                "kind": "drop",
                "severity": (
                    "critical" if int(event.get("to_score") or 0) <= 10 else "major"
                ),
                "title": (
                    f"{event.get('router_name')}: "
                    f"{event.get('from_score')}% → {event.get('to_score')}%"
                ),
                "detail": event.get("reason") or "",
                "at": event.get("at") or "",
                "at_iso": event.get("at_iso") or "",
                "router_id": event.get("router_id"),
                "current": bool(event.get("current")),
            }
        )
    for fault in faults:
        events.append(
            {
                "id": f"tl-fault-{fault['id']}",
                "kind": "fault",
                "severity": (
                    "major" if fault.get("issue") == "no_connectivity" else "minor"
                ),
                "title": f"{fault.get('ticket_number')} raised",
                "detail": f"{fault.get('customer_name')} · {fault.get('issue_label')}",
                "at": fault.get("created_at") or "",
                "at_iso": fault.get("created_at_iso") or "",
                "router_id": fault.get("router_id"),
                "current": True,
            }
        )
    for row in routers:
        restore = row.get("auto_restore")
        if not isinstance(restore, dict):
            continue
        if not restore.get("ok") and not restore.get("message"):
            continue
        events.append(
            {
                "id": f"tl-restore-{row['id']}",
                "kind": "auto_restore",
                "severity": "info",
                "title": f"Auto-restore · {row['name']}",
                "detail": restore.get("message") or restore.get("restore_kind") or "",
                "at": restore.get("at") or "",
                "at_iso": restore.get("at_iso") or "",
                "router_id": row["id"],
                "current": True,
            }
        )

    events.sort(
        key=lambda row: (
            row.get("at_iso") or row.get("at") or "",
            row.get("id") or "",
        ),
        reverse=True,
    )
    return events[:40]


def _open_faults(organization, *, limit: int = 60) -> list[dict[str, Any]]:
    from accounts.models import FaultTicket

    qs = (
        FaultTicket.objects.filter(organization=organization)
        .exclude(
            status__in=[FaultTicket.Status.RESOLVED, FaultTicket.Status.CLOSED]
        )
        .select_related(
            "customer",
            "customer__router",
            "assigned_technician",
            "assigned_technician__user",
        )
        .order_by("-created_at", "-id")[: max(1, min(int(limit or 60), 120))]
    )
    rows: list[dict[str, Any]] = []
    for ticket in qs:
        customer = ticket.customer
        tech = ticket.assigned_technician
        tech_name = ""
        if tech is not None:
            user = getattr(tech, "user", None)
            tech_name = (
                (getattr(user, "get_full_name", lambda: "")() or "").strip()
                or (getattr(user, "username", None) or "").strip()
                or f"Tech #{tech.pk}"
            )
        customer_url = ""
        router_id = None
        router_name = ""
        if customer is not None:
            try:
                customer_url = reverse(
                    "core:client_detail", kwargs={"customer_id": customer.pk}
                )
            except Exception:
                customer_url = ""
            if customer.router_id:
                router_id = customer.router_id
                router_name = getattr(customer.router, "name", "") or ""
        rows.append(
            {
                "id": ticket.pk,
                "ticket_number": ticket.ticket_number,
                "issue": ticket.issue,
                "issue_label": ticket.get_issue_display(),
                "status": ticket.status,
                "status_label": ticket.get_status_display(),
                "notes": (ticket.notes or "").strip(),
                "customer_id": customer.pk if customer else None,
                "customer_name": (
                    (customer.full_name or customer.account_number or f"#{customer.pk}")
                    if customer
                    else "—"
                ),
                "customer_url": customer_url,
                "router_id": router_id,
                "router_name": router_name,
                "technician": tech_name or "Unassigned",
                "created_at": timezone.localtime(ticket.created_at).strftime(
                    "%d %b %H:%M"
                ),
                "created_at_iso": ticket.created_at.isoformat(),
            }
        )
    return rows


def _empty_router_performance() -> dict[str, Any]:
    return {
        "sessions_active": 0,
        "download_mbps": 0.0,
        "upload_mbps": 0.0,
        "underperforming_count": 0,
        "idle_count": 0,
        "non_optimal_count": 0,
        "avg_attainment_pct": None,
        "sold_download_mbps": 0,
        "uplink_capacity_mbps": None,
        "oversubscription_ratio": None,
        "capacity_known": False,
        "oversubscribed": False,
        "score": None,
        "label": "No data",
        "tone": "unknown",
    }


def _bps_to_mbps(bps: int | float | None) -> float:
    return round(max(0.0, float(bps or 0) / 1_000_000.0), 2)


def _plan_download_bps(plan_mbps: int | None) -> int:
    mbps = int(plan_mbps or 0)
    if mbps <= 0:
        return 0
    return mbps * 1_000_000


def _attainment_pct(peak_bps: int, plan_bps: int) -> int | None:
    if plan_bps <= 0:
        return None
    return max(0, min(100, int(round((peak_bps / plan_bps) * 100))))


def _performance_label(score: int | None, *, has_data: bool) -> str:
    if not has_data or score is None:
        return "No data"
    if score >= 85:
        return "Strong"
    if score >= 70:
        return "Good"
    if score >= 50:
        return "Fair"
    if score >= 30:
        return "Weak"
    return "Critical"


def _performance_tone(score: int | None, *, has_data: bool) -> str:
    if not has_data or score is None:
        return "unknown"
    if score >= 70:
        return "ok"
    if score >= 40:
        return "warn"
    return "bad"


def _classify_client_quality(
    *,
    session_active: bool,
    sample_count: int,
    peak_down: int,
    avg_down: int,
    uptime_seconds: int,
    plan_bps: int,
) -> tuple[str, str]:
    """
    Return (kind, reason) for a dialed client.

    kind: ok | underperforming | idle | unknown
    """
    if not session_active:
        return "unknown", "Not dialed on NAS right now"
    if sample_count < _PERF_MIN_SAMPLES and uptime_seconds < _PERF_MIN_UPTIME_SEC:
        return "unknown", "Not enough samples yet"
    if peak_down <= _PERF_IDLE_BPS and avg_down <= _PERF_IDLE_BPS:
        if uptime_seconds >= _PERF_MIN_UPTIME_SEC or sample_count >= _PERF_MIN_SAMPLES:
            return (
                "idle",
                "Dialed session with almost no traffic — CPE, RF, or LAN may be idle/broken",
            )
        return "unknown", "Waiting for traffic samples"
    if plan_bps > 0:
        floor = max(_PERF_IDLE_BPS * 4, int(plan_bps * _PERF_UNDERPERFORM_RATIO))
        if peak_down < floor and (
            uptime_seconds >= _PERF_MIN_UPTIME_SEC or sample_count >= _PERF_MIN_SAMPLES
        ):
            pct = _attainment_pct(peak_down, plan_bps) or 0
            return (
                "underperforming",
                f"Peak download only ~{pct}% of plan — check RF, CPE, or uplink congestion",
            )
    return "ok", "Session carrying traffic within expected range"


def _build_performance(
    organization, routers: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    Score MikroTik client experience from recent usage samples + live cache.

    Uses peak download over the lookback vs package Mbps to flag idle and
    underperforming dialed clients — the ops board alone cannot see this.
    """
    empty = {
        "summary": {
            "sessions_active": 0,
            "clients_underperforming": 0,
            "clients_idle": 0,
            "clients_non_optimal": 0,
            "fleet_throughput_mbps": 0.0,
            "performance_score": None,
            "performance_label": "No data",
            "has_usage_samples": False,
            "sold_download_mbps": 0,
            "uplink_capacity_mbps": None,
            "oversubscription_ratio": None,
            "routers_oversubscribed": 0,
            "routers_missing_capacity": 0,
        },
        "by_router": {},
        "non_optimal_clients": [],
        "improvements": [],
    }
    if not organization:
        return empty

    from billing.models import Customer, CustomerUsageSample
    from billing.usage_samples import get_org_live_usage

    router_meta = {
        int(row["id"]): row for row in routers if row.get("id") is not None
    }
    by_router: dict[int, dict[str, Any]] = {
        rid: _empty_router_performance() for rid in router_meta
    }
    for rid, bucket in by_router.items():
        bucket["_attain_sum"] = 0
        bucket["_attain_n"] = 0
        bucket["_health_score"] = router_meta[rid].get("score")
        capacity = router_meta[rid].get("uplink_capacity_mbps")
        if capacity is not None and int(capacity) > 0:
            bucket["uplink_capacity_mbps"] = int(capacity)
            bucket["capacity_known"] = True
        else:
            bucket["uplink_capacity_mbps"] = None
            bucket["capacity_known"] = False

    customers = list(
        Customer.objects.filter(
            organization=organization,
            status=Customer.Status.ACTIVE,
            service_type=Customer.ServiceType.PPPOE,
        )
        .select_related("plan", "router")
        .only(
            "id",
            "full_name",
            "account_number",
            "router_id",
            "plan_id",
            "pppoe_username",
            "plan__id",
            "plan__name",
            "plan__download_speed_mbps",
            "router__id",
            "router__name",
        )
    )
    if not customers:
        return empty

    # Sold package Mbps per NAS (active PPPoE assignments).
    for customer in customers:
        if not customer.router_id:
            continue
        rid = int(customer.router_id)
        if rid not in by_router:
            continue
        plan = customer.plan
        sold = int(getattr(plan, "download_speed_mbps", 0) or 0) if plan else 0
        if sold > 0:
            by_router[rid]["sold_download_mbps"] = int(
                by_router[rid]["sold_download_mbps"] or 0
            ) + sold

    customer_ids = [c.pk for c in customers]
    since = timezone.now() - timedelta(minutes=_PERF_LOOKBACK_MINUTES)
    samples = list(
        CustomerUsageSample.objects.filter(
            organization=organization,
            customer_id__in=customer_ids,
            sampled_at__gte=since,
        )
        .order_by("customer_id", "-sampled_at")
        .values(
            "customer_id",
            "sampled_at",
            "session_active",
            "download_bps",
            "upload_bps",
            "uptime_seconds",
        )[: max(2000, len(customer_ids) * 40)]
    )

    agg: dict[int, dict[str, Any]] = {}
    for row in samples:
        cid = int(row["customer_id"])
        bucket = agg.get(cid)
        if bucket is None:
            bucket = {
                "sample_count": 0,
                "active_samples": 0,
                "peak_down": 0,
                "peak_up": 0,
                "sum_down": 0,
                "latest_active": bool(row.get("session_active")),
                "latest_down": int(row.get("download_bps") or 0),
                "latest_up": int(row.get("upload_bps") or 0),
                "uptime_seconds": int(row.get("uptime_seconds") or 0),
                "sampled_at": row.get("sampled_at"),
            }
            agg[cid] = bucket
        if bucket["sample_count"] >= 40:
            continue
        down = int(row.get("download_bps") or 0)
        up = int(row.get("upload_bps") or 0)
        bucket["sample_count"] += 1
        if row.get("session_active"):
            bucket["active_samples"] += 1
            bucket["sum_down"] += down
            bucket["peak_down"] = max(bucket["peak_down"], down)
            bucket["peak_up"] = max(bucket["peak_up"], up)
            bucket["uptime_seconds"] = max(
                bucket["uptime_seconds"], int(row.get("uptime_seconds") or 0)
            )

    live = get_org_live_usage(organization)
    live_pppoe = live.get("pppoe") if isinstance(live.get("pppoe"), dict) else {}
    has_samples = bool(samples) or bool(live.get("ok"))

    non_optimal: list[dict[str, Any]] = []
    sessions_active = 0
    underperforming = 0
    idle = 0
    fleet_down = 0
    fleet_up = 0
    scored_router_vals: list[int] = []

    for customer in customers:
        stats = agg.get(customer.pk)
        live_entry = live_pppoe.get(customer.pk) or live_pppoe.get(str(customer.pk))
        if not isinstance(live_entry, dict):
            live_entry = {}

        session_active = bool(
            (live_entry.get("session_active") if live_entry else None)
            if live_entry
            else (stats or {}).get("latest_active")
        )
        if live_entry and "session_active" in live_entry:
            session_active = bool(live_entry.get("session_active"))

        peak_down = int((stats or {}).get("peak_down") or 0)
        peak_up = int((stats or {}).get("peak_up") or 0)
        latest_down = int((stats or {}).get("latest_down") or 0)
        latest_up = int((stats or {}).get("latest_up") or 0)
        if live_entry:
            latest_down = max(latest_down, int(live_entry.get("download_bps") or 0))
            latest_up = max(latest_up, int(live_entry.get("upload_bps") or 0))
            peak_down = max(peak_down, latest_down)
            peak_up = max(peak_up, latest_up)

        sample_count = int((stats or {}).get("sample_count") or 0)
        active_samples = int((stats or {}).get("active_samples") or 0)
        uptime_seconds = int((stats or {}).get("uptime_seconds") or 0)
        avg_down = (
            int(round((stats or {}).get("sum_down", 0) / active_samples))
            if active_samples
            else latest_down
        )

        plan = customer.plan
        plan_mbps = int(getattr(plan, "download_speed_mbps", 0) or 0) if plan else 0
        plan_bps = _plan_download_bps(plan_mbps)
        kind, reason = _classify_client_quality(
            session_active=session_active,
            sample_count=max(sample_count, 1 if live_entry else 0),
            peak_down=peak_down,
            avg_down=avg_down,
            uptime_seconds=uptime_seconds,
            plan_bps=plan_bps,
        )
        attainment = _attainment_pct(peak_down, plan_bps)

        router_id = customer.router_id
        router_row = router_meta.get(int(router_id)) if router_id else None
        router_name = (
            (router_row or {}).get("name")
            or (getattr(customer.router, "name", None) if customer.router_id else "")
            or "Unassigned NAS"
        )
        if session_active:
            sessions_active += 1
            fleet_down += latest_down
            fleet_up += latest_up
        if router_id and int(router_id) in by_router:
            rb = by_router[int(router_id)]
            if session_active:
                rb["sessions_active"] += 1
                rb["download_mbps"] = round(
                    rb["download_mbps"] + _bps_to_mbps(latest_down), 2
                )
                rb["upload_mbps"] = round(
                    rb["upload_mbps"] + _bps_to_mbps(latest_up), 2
                )
            if attainment is not None and session_active:
                rb["_attain_sum"] += attainment
                rb["_attain_n"] += 1
            if kind == "underperforming":
                rb["underperforming_count"] += 1
            elif kind == "idle":
                rb["idle_count"] += 1

        if kind not in {"underperforming", "idle"}:
            continue

        if kind == "underperforming":
            underperforming += 1
            severity = "major"
        else:
            idle += 1
            severity = "minor"

        try:
            customer_url = reverse(
                "core:client_detail", kwargs={"customer_id": customer.pk}
            )
        except Exception:
            customer_url = ""

        non_optimal.append(
            {
                "id": customer.pk,
                "full_name": (customer.full_name or "").strip()
                or customer.account_number
                or f"#{customer.pk}",
                "account_number": customer.account_number or "",
                "pppoe_username": (customer.pppoe_username or "").strip(),
                "url": customer_url,
                "router_id": router_id,
                "router_name": router_name,
                "plan_name": (getattr(plan, "name", None) or "") if plan else "",
                "plan_download_mbps": plan_mbps or None,
                "kind": kind,
                "severity": severity,
                "reason": reason,
                "peak_download_mbps": _bps_to_mbps(peak_down),
                "live_download_mbps": _bps_to_mbps(latest_down),
                "live_upload_mbps": _bps_to_mbps(latest_up),
                "attainment_pct": attainment,
                "uptime_seconds": uptime_seconds,
                "sample_count": sample_count,
                "clients_url": (
                    f"{reverse('core:my_clients')}?tab=pppoe&router={router_id}"
                    if router_id
                    else reverse("core:my_clients") + "?tab=pppoe"
                ),
            }
        )

    non_optimal.sort(
        key=lambda row: (
            0 if row.get("kind") == "underperforming" else 1,
            row.get("attainment_pct")
            if row.get("attainment_pct") is not None
            else 999,
            -(row.get("uptime_seconds") or 0),
            (row.get("full_name") or "").lower(),
        )
    )
    non_optimal = non_optimal[:_PERF_CLIENT_LIMIT]

    for rid, rb in by_router.items():
        rb["non_optimal_count"] = int(rb["underperforming_count"]) + int(
            rb["idle_count"]
        )
        if rb["_attain_n"]:
            rb["avg_attainment_pct"] = round(rb["_attain_sum"] / rb["_attain_n"])
        else:
            rb["avg_attainment_pct"] = None

        sold = int(rb.get("sold_download_mbps") or 0)
        capacity = rb.get("uplink_capacity_mbps")
        if capacity is not None and int(capacity) > 0 and sold > 0:
            ratio = round(sold / float(capacity), 2)
            rb["oversubscription_ratio"] = ratio
            rb["oversubscribed"] = ratio >= _OVERSUB_WARN_RATIO
        else:
            rb["oversubscription_ratio"] = None
            rb["oversubscribed"] = False

        health = rb.get("_health_score")
        sessions = int(rb["sessions_active"] or 0)
        bad = int(rb["non_optimal_count"] or 0)
        if health is None and sessions <= 0 and not has_samples:
            rb["score"] = None
            rb["label"] = "No data"
            rb["tone"] = "unknown"
        else:
            base = int(health) if health is not None else 70
            if sessions > 0:
                bad_ratio = bad / max(1, sessions)
                penalty = int(round(bad_ratio * 45))
                if rb["avg_attainment_pct"] is not None:
                    attain = int(rb["avg_attainment_pct"])
                    if attain < int(_PERF_UNDERPERFORM_RATIO * 100):
                        penalty += 15
                    elif attain < int(_PERF_FAIR_RATIO * 100):
                        penalty += 8
                if rb.get("oversubscribed"):
                    ratio = float(rb.get("oversubscription_ratio") or 0)
                    if ratio >= _OVERSUB_CRITICAL_RATIO:
                        penalty += 20
                    elif ratio >= _OVERSUB_WARN_RATIO:
                        penalty += 10
                score = max(0, min(100, base - penalty))
            else:
                score = base
                if rb.get("oversubscribed"):
                    ratio = float(rb.get("oversubscription_ratio") or 0)
                    score = max(
                        0,
                        score - (20 if ratio >= _OVERSUB_CRITICAL_RATIO else 10),
                    )
            rb["score"] = score
            rb["label"] = _performance_label(score, has_data=True)
            rb["tone"] = _performance_tone(score, has_data=True)
            scored_router_vals.append(score)

        for key in ("_attain_sum", "_attain_n", "_health_score"):
            rb.pop(key, None)

    fleet_score = (
        round(sum(scored_router_vals) / len(scored_router_vals))
        if scored_router_vals
        else None
    )
    fleet_sold = sum(int(rb.get("sold_download_mbps") or 0) for rb in by_router.values())
    fleet_cap_vals = [
        int(rb["uplink_capacity_mbps"])
        for rb in by_router.values()
        if rb.get("capacity_known") and rb.get("uplink_capacity_mbps")
    ]
    fleet_cap = sum(fleet_cap_vals) if fleet_cap_vals else None
    fleet_ratio = (
        round(fleet_sold / float(fleet_cap), 2)
        if fleet_cap and fleet_cap > 0 and fleet_sold > 0
        else None
    )
    routers_oversubscribed = sum(
        1 for rb in by_router.values() if rb.get("oversubscribed")
    )
    routers_missing_capacity = sum(
        1
        for rb in by_router.values()
        if int(rb.get("sold_download_mbps") or 0) > 0 and not rb.get("capacity_known")
    )

    improvements = _build_improvements(
        routers=routers,
        by_router=by_router,
        non_optimal=non_optimal,
    )

    return {
        "summary": {
            "sessions_active": sessions_active,
            "clients_underperforming": underperforming,
            "clients_idle": idle,
            "clients_non_optimal": underperforming + idle,
            "fleet_throughput_mbps": _bps_to_mbps(fleet_down + fleet_up),
            "performance_score": fleet_score,
            "performance_label": _performance_label(
                fleet_score, has_data=has_samples or bool(scored_router_vals)
            ),
            "has_usage_samples": has_samples,
            "sold_download_mbps": fleet_sold,
            "uplink_capacity_mbps": fleet_cap,
            "oversubscription_ratio": fleet_ratio,
            "routers_oversubscribed": routers_oversubscribed,
            "routers_missing_capacity": routers_missing_capacity,
        },
        "by_router": by_router,
        "non_optimal_clients": non_optimal,
        "improvements": improvements,
    }


def _build_improvements(
    *,
    routers: list[dict[str, Any]],
    by_router: dict[int, dict[str, Any]],
    non_optimal: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Actionable NOC suggestions ranked by customer impact."""
    items: list[dict[str, Any]] = []

    for row in routers:
        rid = int(row["id"])
        perf = by_router.get(rid) or {}
        tone = row.get("tone")
        customers = int(row.get("customer_count") or 0)
        if tone == "down":
            items.append(
                {
                    "id": f"improve-down-{rid}",
                    "severity": "critical" if customers else "major",
                    "title": f"Restore {row.get('name')}",
                    "detail": (
                        f"{customers} assigned client(s) on a down NAS — "
                        f"{row.get('reason') or 'unreachable'}."
                    ),
                    "action": "Reconnect / check uplink and tunnel",
                    "router_id": rid,
                    "router_name": row.get("name") or "",
                    "customers": customers,
                    "href": row.get("detail_url") or "",
                    "kind": "router_down",
                }
            )
        elif tone == "degraded":
            items.append(
                {
                    "id": f"improve-deg-{rid}",
                    "severity": "major" if customers else "minor",
                    "title": f"Stabilize {row.get('name')}",
                    "detail": (
                        f"Management plane is {str(row.get('status') or 'degraded').replace('_', ' ')} "
                        f"with {customers} client(s) assigned."
                    ),
                    "action": "Verify API credentials, VPN, and host reachability",
                    "router_id": rid,
                    "router_name": row.get("name") or "",
                    "customers": customers,
                    "href": row.get("detail_url") or "",
                    "kind": "router_degraded",
                }
            )

        under = int(perf.get("underperforming_count") or 0)
        idle_n = int(perf.get("idle_count") or 0)
        sold = int(perf.get("sold_download_mbps") or 0)
        capacity = perf.get("uplink_capacity_mbps")
        ratio = perf.get("oversubscription_ratio")
        if perf.get("oversubscribed") and ratio is not None:
            severity = (
                "critical"
                if float(ratio) >= _OVERSUB_CRITICAL_RATIO
                else "major"
            )
            items.append(
                {
                    "id": f"improve-oversub-{rid}",
                    "severity": severity,
                    "title": f"Oversubscribed uplink on {row.get('name')}",
                    "detail": (
                        f"Sold {sold} Mbps of packages on "
                        f"{int(capacity) if capacity else '?'} Mbps uplink "
                        f"({ratio}×). Peak hours will feel slow and unreliable."
                    ),
                    "action": (
                        "Add backhaul, move clients, or stop selling heavy packages "
                        "on this NAS until ratio is under 3×"
                    ),
                    "router_id": rid,
                    "router_name": row.get("name") or "",
                    "customers": customers,
                    "href": row.get("detail_url") or "",
                    "kind": "oversubscribed",
                }
            )
        elif sold > 0 and not perf.get("capacity_known"):
            items.append(
                {
                    "id": f"improve-cap-{rid}",
                    "severity": "minor",
                    "title": f"Set uplink capacity for {row.get('name')}",
                    "detail": (
                        f"{sold} Mbps sold on this NAS but uplink capacity is unknown — "
                        "NOC cannot detect oversubscription."
                    ),
                    "action": "Edit MikroTik → set Uplink capacity (Mbps) to the real WAN speed",
                    "router_id": rid,
                    "router_name": row.get("name") or "",
                    "customers": customers,
                    "href": row.get("detail_url") or "",
                    "kind": "missing_capacity",
                }
            )
        if under >= 2 or (under >= 1 and customers >= 5):
            items.append(
                {
                    "id": f"improve-under-{rid}",
                    "severity": "major",
                    "title": f"{under} underperforming client(s) on {row.get('name')}",
                    "detail": (
                        "Dialed sessions peaked far below package Mbps — likely RF, CPE, "
                        "or shared uplink congestion."
                    ),
                    "action": "Inspect wireless/CPE and compare uplink load on this NAS",
                    "router_id": rid,
                    "router_name": row.get("name") or "",
                    "customers": under,
                    "href": row.get("clients_url") or "",
                    "kind": "underperforming",
                }
            )
        if idle_n >= 3:
            items.append(
                {
                    "id": f"improve-idle-{rid}",
                    "severity": "minor",
                    "title": f"{idle_n} idle dialed session(s) on {row.get('name')}",
                    "detail": (
                        "Clients are connected on the NAS but carrying almost no traffic."
                    ),
                    "action": "Check CPE LAN, customer Wi‑Fi, or sticky PPPoE sessions",
                    "router_id": rid,
                    "router_name": row.get("name") or "",
                    "customers": idle_n,
                    "href": row.get("clients_url") or "",
                    "kind": "idle",
                }
            )

    # Top individual underperformers when few router-level clusters.
    for client in non_optimal[:6]:
        if client.get("kind") != "underperforming":
            continue
        rid = client.get("router_id")
        if rid and any(
            i.get("kind") == "underperforming" and i.get("router_id") == rid
            for i in items
        ):
            continue
        items.append(
            {
                "id": f"improve-client-{client['id']}",
                "severity": "minor",
                "title": f"{client.get('full_name')} below plan speed",
                "detail": client.get("reason") or "",
                "action": "Open client usage / CPE and verify radio or cable path",
                "router_id": rid,
                "router_name": client.get("router_name") or "",
                "customers": 1,
                "href": client.get("url") or "",
                "kind": "client",
            }
        )

    items.sort(
        key=lambda row: (
            _SEVERITY_RANK.get(row.get("severity") or "info", 9),
            -(row.get("customers") or 0),
            (row.get("title") or "").lower(),
        )
    )
    return items[:_PERF_IMPROVE_LIMIT]