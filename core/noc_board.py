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
        },
        "routers": [],
        "alarms": [],
        "sites": [],
        "timeline": [],
        "drops": {"ok": False, "events": [], "current_count": 0},
        "faults": [],
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
        },
        "routers": routers,
        "alarms": alarms,
        "sites": sites,
        "timeline": timeline,
        "drops": drops,
        "faults": faults,
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
        .values("router_id", "sampled_at", "status")[:12000]
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
