"""Track Hotspot welcome Refer & earn / partner advert clicks per contact."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.db.models import F, Q
from django.utils import timezone

from accounts.models import HotspotPortalClick


def _normalize_mac(raw: str) -> str:
    digits = "".join(ch for ch in (raw or "").upper() if ch.isalnum())
    if len(digits) == 12:
        return ":".join(digits[i : i + 2] for i in range(0, 12, 2))
    return (raw or "").strip().upper()


def _normalize_phone(raw: str) -> str:
    try:
        from billing.services import normalize_customer_phone_key

        return normalize_customer_phone_key(raw) or ""
    except Exception:
        return "".join(ch for ch in (raw or "") if ch.isdigit())


def resolve_portal_contact(*, organization, request=None, mac: str = "", customer=None) -> dict:
    """Build a stable contact key + display fields for portal click tracking."""
    hotspot_mac = _normalize_mac(mac or "")
    if not hotspot_mac and request is not None:
        for raw in (
            request.GET.get("mac") or "",
            request.COOKIES.get("hs_mac") or "",
        ):
            hotspot_mac = _normalize_mac(raw)
            if hotspot_mac:
                break

    phone = ""
    display_name = ""
    if customer is not None:
        phone = (getattr(customer, "phone", None) or "").strip()
        display_name = (getattr(customer, "full_name", None) or "").strip()
        if not hotspot_mac:
            hotspot_mac = _normalize_mac(getattr(customer, "hotspot_mac", "") or "")

    if hotspot_mac:
        contact_key = f"mac:{hotspot_mac}"
    elif phone:
        contact_key = f"phone:{phone}"
    elif request is not None:
        session_key = request.session.session_key
        if not session_key:
            request.session.save()
            session_key = request.session.session_key
        contact_key = f"session:{session_key or request.META.get('REMOTE_ADDR') or 'anon'}"
    else:
        contact_key = "anon"

    if not display_name:
        display_name = phone or hotspot_mac or "Anonymous visitor"

    return {
        "contact_key": contact_key,
        "hotspot_mac": hotspot_mac,
        "phone": phone,
        "display_name": display_name,
        "customer": customer,
    }


def record_portal_click(
    organization,
    kind: str,
    *,
    request=None,
    mac: str = "",
    customer=None,
) -> HotspotPortalClick | None:
    """Increment a per-contact click counter for earn / partner links."""
    if organization is None:
        return None
    kind = (kind or "").strip().lower()
    valid = {choice.value for choice in HotspotPortalClick.Kind}
    if kind not in valid:
        return None

    contact = resolve_portal_contact(
        organization=organization,
        request=request,
        mac=mac,
        customer=customer,
    )
    row, created = HotspotPortalClick.objects.get_or_create(
        organization=organization,
        kind=kind,
        contact_key=contact["contact_key"],
        defaults={
            "hotspot_mac": contact["hotspot_mac"],
            "phone": contact["phone"],
            "display_name": contact["display_name"],
            "customer": contact["customer"],
            "click_count": 1,
        },
    )
    if created:
        return row

    updates = {
        "click_count": F("click_count") + 1,
        "last_clicked_at": timezone.now(),
    }
    if contact["hotspot_mac"] and not row.hotspot_mac:
        updates["hotspot_mac"] = contact["hotspot_mac"]
    if contact["phone"] and not row.phone:
        updates["phone"] = contact["phone"]
    if contact["display_name"] and (
        not row.display_name or row.display_name.startswith("Anonymous")
    ):
        updates["display_name"] = contact["display_name"]
    if contact["customer"] is not None and row.customer_id is None:
        updates["customer"] = contact["customer"]
    HotspotPortalClick.objects.filter(pk=row.pk).update(**updates)
    row.refresh_from_db()
    return row


def interest_score(
    *,
    earn_clicks: int,
    partner_1_clicks: int,
    partner_2_clicks: int,
    last_clicked_at,
    now=None,
) -> int:
    """Weighted interest score for ranking portal contacts."""
    now = now or timezone.now()
    score = (
        int(earn_clicks or 0) * 3
        + int(partner_1_clicks or 0) * 2
        + int(partner_2_clicks or 0) * 2
    )
    if last_clicked_at is not None:
        age_hours = max(0.0, (now - last_clicked_at).total_seconds() / 3600.0)
        if age_hours <= 24:
            score += 8
        elif age_hours <= 72:
            score += 4
        elif age_hours <= 168:
            score += 2
    return score


def interest_tier(*, score: int, earn_clicks: int, total_clicks: int) -> str:
    if score >= 12 or (earn_clicks >= 2 and total_clicks >= 3):
        return "hot"
    if score >= 5 or total_clicks >= 2:
        return "warm"
    return "cold"


def recency_band(last_clicked_at, *, now=None) -> str:
    if last_clicked_at is None:
        return "older"
    now = now or timezone.now()
    if last_clicked_at >= now - timedelta(hours=24):
        return "today"
    if last_clicked_at >= now - timedelta(days=7):
        return "week"
    return "older"


def _merge_identity(item: dict) -> str:
    if item.get("customer_id"):
        return f"cust:{item['customer_id']}"
    mac = (item.get("hotspot_mac") or "").strip().upper()
    if mac:
        return f"mac:{mac}"
    phone_key = _normalize_phone(item.get("phone") or "")
    if phone_key:
        return f"phone:{phone_key}"
    return f"key:{item.get('contact_key') or 'anon'}"


def _blank_lead(
    *,
    contact_key: str,
    partner1_label: str,
    partner2_label: str,
) -> dict[str, Any]:
    return {
        "contact_key": contact_key,
        "display_name": "Unknown",
        "phone": "",
        "hotspot_mac": "",
        "customer_id": None,
        "customer_name": "",
        "customer_status": "",
        "customer_status_label": "",
        "customer_account": "",
        "is_matched": False,
        "earn_clicks": 0,
        "partner_1_clicks": 0,
        "partner_2_clicks": 0,
        "partner_1_label": partner1_label,
        "partner_2_label": partner2_label,
        "total_clicks": 0,
        "interest_score": 0,
        "interest_tier": "cold",
        "recency_band": "older",
        "first_clicked_at": None,
        "last_clicked_at": None,
    }


def _merge_lead_into(target: dict, source: dict) -> None:
    target["earn_clicks"] += int(source.get("earn_clicks") or 0)
    target["partner_1_clicks"] += int(source.get("partner_1_clicks") or 0)
    target["partner_2_clicks"] += int(source.get("partner_2_clicks") or 0)
    target["total_clicks"] = (
        target["earn_clicks"] + target["partner_1_clicks"] + target["partner_2_clicks"]
    )
    if source.get("customer_id") and not target.get("customer_id"):
        target["customer_id"] = source["customer_id"]
    if source.get("phone") and not target.get("phone"):
        target["phone"] = source["phone"]
    if source.get("hotspot_mac") and not target.get("hotspot_mac"):
        target["hotspot_mac"] = source["hotspot_mac"]
    src_name = (source.get("display_name") or "").strip()
    if src_name and (
        not target.get("display_name")
        or str(target.get("display_name") or "").startswith("Anonymous")
        or target.get("display_name") in {"Unknown", source.get("hotspot_mac"), source.get("phone")}
    ):
        target["display_name"] = src_name
    for stamp_key in ("first_clicked_at", "last_clicked_at"):
        src_stamp = source.get(stamp_key)
        dst_stamp = target.get(stamp_key)
        if src_stamp is None:
            continue
        if dst_stamp is None:
            target[stamp_key] = src_stamp
        elif stamp_key == "first_clicked_at" and src_stamp < dst_stamp:
            target[stamp_key] = src_stamp
        elif stamp_key == "last_clicked_at" and src_stamp > dst_stamp:
            target[stamp_key] = src_stamp


def _enrich_with_customers(organization, leads: list[dict]) -> None:
    from billing.models import Customer

    customer_ids = {row["customer_id"] for row in leads if row.get("customer_id")}
    macs = {row["hotspot_mac"] for row in leads if row.get("hotspot_mac")}
    phones = {_normalize_phone(row.get("phone") or "") for row in leads}
    phones.discard("")

    qs = Customer.objects.filter(organization=organization).only(
        "id",
        "full_name",
        "phone",
        "phone_normalized",
        "hotspot_mac",
        "status",
        "account_number",
        "sales_ticket_number",
    )
    clauses = Q(pk__in=customer_ids) if customer_ids else Q()
    if macs:
        clauses |= Q(hotspot_mac__in=list(macs))
    if phones:
        clauses |= Q(phone_normalized__in=list(phones))
        # Fallback for orgs that never normalized phones.
        clauses |= Q(phone__in=[row.get("phone") for row in leads if row.get("phone")])
    if not clauses:
        return

    customers = list(qs.filter(clauses)[:500])
    by_id = {c.pk: c for c in customers}
    by_mac = {}
    by_phone = {}
    for customer in customers:
        mac = _normalize_mac(customer.hotspot_mac or "")
        if mac and mac not in by_mac:
            by_mac[mac] = customer
        phone_key = (customer.phone_normalized or "").strip() or _normalize_phone(
            customer.phone or ""
        )
        if phone_key and phone_key not in by_phone:
            by_phone[phone_key] = customer

    for row in leads:
        customer = None
        if row.get("customer_id"):
            customer = by_id.get(row["customer_id"])
        if customer is None and row.get("hotspot_mac"):
            customer = by_mac.get(_normalize_mac(row["hotspot_mac"]))
        if customer is None and row.get("phone"):
            customer = by_phone.get(_normalize_phone(row["phone"]))
        if customer is None:
            continue
        row["customer_id"] = customer.pk
        row["customer_name"] = customer.full_name
        row["customer_status"] = customer.status
        row["customer_status_label"] = customer.get_status_display()
        row["customer_account"] = (
            customer.sales_ticket_number or customer.account_number or ""
        )
        row["is_matched"] = True
        if not row.get("phone"):
            row["phone"] = customer.phone or ""
        if not row.get("hotspot_mac"):
            row["hotspot_mac"] = _normalize_mac(customer.hotspot_mac or "")
        if (
            not row.get("display_name")
            or str(row.get("display_name") or "").startswith("Anonymous")
            or row.get("display_name") in {row.get("hotspot_mac"), row.get("phone"), "Unknown"}
        ):
            row["display_name"] = customer.full_name


def portal_leads_for_organization(
    organization,
    *,
    limit: int = 200,
    query: str = "",
    filter_key: str = "all",
) -> tuple[list[dict], dict[str, Any]]:
    """Aggregate earn + partner clicks into ranked, filterable portal lead rows."""
    empty_summary = {
        "contacts": 0,
        "hot": 0,
        "matched": 0,
        "earn_clicks": 0,
        "partner_clicks": 0,
        "total_clicks": 0,
        "today": 0,
        "show_partner_1": False,
        "show_partner_2": False,
        "partner_1_label": "Partner 1",
        "partner_2_label": "Partner 2",
    }
    if organization is None:
        return [], empty_summary

    partner1_label = (organization.hotspot_welcome_link1_label or "").strip() or "Partner 1"
    partner2_label = (organization.hotspot_welcome_link2_label or "").strip() or "Partner 2"
    empty_summary["partner_1_label"] = partner1_label
    empty_summary["partner_2_label"] = partner2_label
    empty_summary["show_partner_1"] = bool((organization.hotspot_welcome_link1_url or "").strip())
    empty_summary["show_partner_2"] = bool((organization.hotspot_welcome_link2_url or "").strip())

    rows = list(
        HotspotPortalClick.objects.filter(organization=organization)
        .select_related("customer")
        .order_by("-last_clicked_at")[:1200]
    )
    if not rows:
        return [], empty_summary

    now = timezone.now()
    by_contact: dict[str, dict] = {}
    for row in rows:
        item = by_contact.get(row.contact_key)
        if item is None:
            item = _blank_lead(
                contact_key=row.contact_key,
                partner1_label=partner1_label,
                partner2_label=partner2_label,
            )
            item["display_name"] = (
                row.display_name or row.phone or row.hotspot_mac or "Unknown"
            )
            item["phone"] = row.phone or ""
            item["hotspot_mac"] = row.hotspot_mac or ""
            item["customer_id"] = row.customer_id
            item["first_clicked_at"] = row.first_clicked_at
            item["last_clicked_at"] = row.last_clicked_at
            by_contact[row.contact_key] = item

        if row.kind == HotspotPortalClick.Kind.EARN:
            item["earn_clicks"] = int(row.click_count or 0)
        elif row.kind == HotspotPortalClick.Kind.PARTNER_1:
            item["partner_1_clicks"] = int(row.click_count or 0)
            empty_summary["show_partner_1"] = True
        elif row.kind == HotspotPortalClick.Kind.PARTNER_2:
            item["partner_2_clicks"] = int(row.click_count or 0)
            empty_summary["show_partner_2"] = True

        item["total_clicks"] = (
            item["earn_clicks"] + item["partner_1_clicks"] + item["partner_2_clicks"]
        )
        if row.display_name and (
            not item["display_name"] or item["display_name"].startswith("Anonymous")
        ):
            item["display_name"] = row.display_name
        if row.phone and not item["phone"]:
            item["phone"] = row.phone
        if row.hotspot_mac and not item["hotspot_mac"]:
            item["hotspot_mac"] = row.hotspot_mac
        if row.customer_id and not item["customer_id"]:
            item["customer_id"] = row.customer_id
        if row.first_clicked_at and (
            item["first_clicked_at"] is None or row.first_clicked_at < item["first_clicked_at"]
        ):
            item["first_clicked_at"] = row.first_clicked_at
        if row.last_clicked_at and (
            item["last_clicked_at"] is None or row.last_clicked_at > item["last_clicked_at"]
        ):
            item["last_clicked_at"] = row.last_clicked_at

    # Merge the same person tracked under different contact keys.
    merged: dict[str, dict] = {}
    for item in by_contact.values():
        identity = _merge_identity(item)
        existing = merged.get(identity)
        if existing is None:
            merged[identity] = item
        else:
            _merge_lead_into(existing, item)

    leads = list(merged.values())
    _enrich_with_customers(organization, leads)

    # Re-merge after enrichment links MAC/phone rows to the same customer.
    remapped: dict[str, dict] = {}
    for item in leads:
        identity = _merge_identity(item)
        existing = remapped.get(identity)
        if existing is None:
            remapped[identity] = item
        else:
            _merge_lead_into(existing, item)
            if item.get("is_matched"):
                existing["is_matched"] = True
                for key in (
                    "customer_id",
                    "customer_name",
                    "customer_status",
                    "customer_status_label",
                    "customer_account",
                ):
                    if item.get(key) and not existing.get(key):
                        existing[key] = item[key]
    leads = list(remapped.values())

    for item in leads:
        item["interest_score"] = interest_score(
            earn_clicks=item["earn_clicks"],
            partner_1_clicks=item["partner_1_clicks"],
            partner_2_clicks=item["partner_2_clicks"],
            last_clicked_at=item.get("last_clicked_at"),
            now=now,
        )
        item["interest_tier"] = interest_tier(
            score=item["interest_score"],
            earn_clicks=item["earn_clicks"],
            total_clicks=item["total_clicks"],
        )
        item["recency_band"] = recency_band(item.get("last_clicked_at"), now=now)

    leads.sort(
        key=lambda row: (
            int(row.get("interest_score") or 0),
            int(row.get("total_clicks") or 0),
            row.get("last_clicked_at") or now,
        ),
        reverse=True,
    )

    summary = {
        "contacts": len(leads),
        "hot": sum(1 for row in leads if row.get("interest_tier") == "hot"),
        "matched": sum(1 for row in leads if row.get("is_matched")),
        "earn_clicks": sum(int(row.get("earn_clicks") or 0) for row in leads),
        "partner_clicks": sum(
            int(row.get("partner_1_clicks") or 0) + int(row.get("partner_2_clicks") or 0)
            for row in leads
        ),
        "total_clicks": sum(int(row.get("total_clicks") or 0) for row in leads),
        "today": sum(1 for row in leads if row.get("recency_band") == "today"),
        "show_partner_1": empty_summary["show_partner_1"],
        "show_partner_2": empty_summary["show_partner_2"],
        "partner_1_label": partner1_label,
        "partner_2_label": partner2_label,
    }

    filter_key = (filter_key or "all").strip().lower()
    query_l = (query or "").strip().lower()

    def _passes(row: dict) -> bool:
        if filter_key == "hot" and row.get("interest_tier") != "hot":
            return False
        if filter_key == "warm" and row.get("interest_tier") not in {"hot", "warm"}:
            return False
        if filter_key == "earn" and int(row.get("earn_clicks") or 0) <= 0:
            return False
        if filter_key == "partner" and (
            int(row.get("partner_1_clicks") or 0) + int(row.get("partner_2_clicks") or 0) <= 0
        ):
            return False
        if filter_key == "matched" and not row.get("is_matched"):
            return False
        if filter_key == "today" and row.get("recency_band") != "today":
            return False
        if query_l:
            hay = " ".join(
                [
                    str(row.get("display_name") or ""),
                    str(row.get("phone") or ""),
                    str(row.get("hotspot_mac") or ""),
                    str(row.get("customer_name") or ""),
                    str(row.get("customer_account") or ""),
                ]
            ).lower()
            if query_l not in hay:
                return False
        return True

    filtered = [row for row in leads if _passes(row)]
    return filtered[:limit], summary
