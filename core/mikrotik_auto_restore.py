"""Persist and notify MikroTik background auto-restore attempts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone

RECORD_TTL = 7 * 24 * 3600


def _record_key(router_id: int) -> str:
    return f"mikrotik_auto_restore_last:{router_id}"


def _alert_time_key(router_id: int) -> str:
    return f"mikrotik_auto_restore_alert_t:{router_id}"


def _alert_sig_key(router_id: int) -> str:
    return f"mikrotik_auto_restore_alert:{router_id}"


def _kind_label(kind: str) -> str:
    if kind == "management":
        return "Management"
    if kind == "internet":
        return "Internet"
    return "Auto-restore"


def _at_label(dt: datetime) -> str:
    now = timezone.now()
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    secs = max(0, int((now - dt).total_seconds()))
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return timezone.localtime(dt).strftime("%b %d %H:%M")


def _human_message(outcome: dict[str, Any]) -> str:
    kind = _kind_label((outcome.get("restore_kind") or "").strip())
    if outcome.get("skipped"):
        reason = (outcome.get("reason") or "").strip()
        if reason == "account_suspended":
            return "Auto-restore skipped — MikroTik account is suspended."
        if reason == "missing_username":
            return "Auto-restore skipped — router username is missing."
        return "Auto-restore skipped."
    if outcome.get("ok"):
        note = (outcome.get("message") or "").strip()
        if not note:
            notes = outcome.get("notes")
            if isinstance(notes, list):
                note = "; ".join(str(n) for n in notes if n).strip()
            elif notes:
                note = str(notes).strip()
        base = f"{kind} connection auto-restored successfully."
        return f"{base} {note}" if note else base
    err = (
        (outcome.get("error") or outcome.get("reason") or "Restore failed.")
    ).strip()
    return f"{kind} auto-restore failed: {err}"


def _public_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "at": record.get("at"),
        "at_label": record.get("at_label"),
        "ok": bool(record.get("ok")),
        "skipped": bool(record.get("skipped")),
        "restore_kind": (record.get("restore_kind") or "").strip(),
        "status_before": (record.get("status_before") or "").strip(),
        "message": (record.get("message") or "").strip(),
        "error": ((record.get("error") or "")[:200]).strip(),
    }


def _parse_record(raw: dict[str, Any]) -> dict[str, Any]:
    record = dict(raw)
    at_raw = record.get("at")
    if at_raw:
        try:
            parsed = datetime.fromisoformat(str(at_raw).replace("Z", "+00:00"))
            record["at_label"] = _at_label(parsed)
        except (TypeError, ValueError):
            pass
    if not record.get("message"):
        record["message"] = _human_message(record)
    return _public_record(record)


def get_auto_restore_record(router_id: int) -> dict[str, Any] | None:
    raw = cache.get(_record_key(int(router_id)))
    if not raw:
        return None
    return _parse_record(raw)


def get_auto_restore_records(router_ids: list[int]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for rid in router_ids:
        record = get_auto_restore_record(rid)
        if record:
            out[int(rid)] = record
    return out


def attach_auto_restore_to_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ids = [int(row["id"]) for row in rows if row.get("id") is not None]
    records = get_auto_restore_records(ids)
    for row in rows:
        rid = row.get("id")
        if rid is None:
            continue
        record = records.get(int(rid))
        if record:
            row["auto_restore"] = record
    return rows


def _alert_signature(record: dict[str, Any]) -> str | None:
    if record.get("skipped"):
        return None
    kind = (record.get("restore_kind") or "unknown").strip()
    return f"{kind}:{'ok' if record.get('ok') else 'fail'}"


def _router_detail_url(router_id: int) -> str:
    path = reverse("core:mikrotik_detail", kwargs={"router_id": router_id})
    base = (getattr(settings, "PUBLIC_BASE_URL", "") or "").rstrip("/")
    return f"{base}{path}" if base else path


def notify_auto_restore(organization, router, record: dict[str, Any]) -> None:
    if not getattr(settings, "MIKROTIK_AUTO_RESTORE_ALERTS", False):
        return

    signature = _alert_signature(record)
    if not signature:
        return

    router_id = int(getattr(router, "pk", 0) or record.get("router_id") or 0)
    if not router_id:
        return

    alert_cd = int(
        getattr(settings, "MIKROTIK_AUTO_RESTORE_ALERT_COOLDOWN_SEC", 3600) or 3600
    )
    last_sig = cache.get(_alert_sig_key(router_id))
    if last_sig == signature and cache.get(_alert_time_key(router_id)):
        return

    cache.set(_alert_sig_key(router_id), signature, max(alert_cd * 2, 3600))
    cache.set(_alert_time_key(router_id), 1, max(60, alert_cd))

    router_name = (getattr(router, "name", None) or record.get("router_name") or "MikroTik").strip()
    host = (getattr(router, "host", None) or "").strip()
    message = (record.get("message") or _human_message(record)).strip()
    status_before = (record.get("status_before") or "").strip()
    link = _router_detail_url(router_id)

    subject_ok = record.get("ok")
    subject = (
        f"MikroTik auto-restore succeeded — {router_name}"
        if subject_ok
        else f"MikroTik auto-restore failed — {router_name}"
    )
    body_lines = [
        message,
        "",
        f"Router: {router_name}",
    ]
    if host:
        body_lines.append(f"Host: {host}")
    if status_before:
        body_lines.append(f"Status before restore: {status_before}")
    body_lines.extend(["", f"Open router: {link}", "", "— ISPCENTRIC"])
    body = "\n".join(body_lines)

    sms = message
    if len(sms) > 155:
        sms = sms[:152] + "..."

    from accounts.communications import send_email, send_sms

    owner = getattr(organization, "owner", None)
    email_to = (getattr(owner, "email", None) or "").strip()
    if email_to:
        try:
            send_email(
                organization=organization,
                to=email_to,
                subject=subject,
                body=body,
            )
        except Exception:
            pass

    phone = (getattr(organization, "phone", None) or "").strip()
    if not phone and owner is not None:
        phone = (getattr(owner, "phone", None) or "").strip()
    if phone:
        try:
            send_sms(organization=organization, to=phone, message=sms)
        except Exception:
            pass


def _load_organization(router):
    org = getattr(router, "organization", None)
    if org is not None:
        return org
    org_id = getattr(router, "organization_id", None)
    if not org_id:
        return None
    from accounts.models import Organization

    return (
        Organization.objects.select_related("owner")
        .filter(pk=org_id)
        .first()
    )


def record_auto_restore_attempt(router, outcome: dict[str, Any]) -> dict[str, Any]:
    """Store the latest attempt and optionally email/SMS the organization owner."""
    now = timezone.now()
    record = {
        **outcome,
        "router_id": getattr(router, "pk", None) or outcome.get("router_id"),
        "router_name": getattr(router, "name", None) or outcome.get("router_name"),
        "at": now.isoformat(),
        "at_label": _at_label(now),
    }
    record["message"] = _human_message(record)
    cache.set(_record_key(int(router.pk)), record, RECORD_TTL)

    org = _load_organization(router)
    if org is not None:
        try:
            notify_auto_restore(org, router, record)
        except Exception:
            pass

    return _public_record(record)
