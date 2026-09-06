"""Buy-X-get-1-free package offers for Hotspot and PPPoE renewals."""

from __future__ import annotations

from django.db import transaction

from billing.models import PackageOfferProgress


def payments_until_free(plan, paid_count: int) -> int | None:
    """How many more paid sessions until the next free one."""
    if not getattr(plan, "offer_enabled", False):
        return None
    threshold = int(getattr(plan, "offer_pay_count", 0) or 0)
    if threshold < 1:
        return None
    return max(threshold - int(paid_count or 0), 0)


def attach_offer_progress_to_plans(plans, customer=None):
    """Annotate plan rows with offer labels and customer progress for pay portals."""
    progress_map: dict[int, int] = {}
    if customer is not None and plans:
        plan_ids = [plan.pk for plan in plans if getattr(plan, "pk", None)]
        if plan_ids:
            rows = PackageOfferProgress.objects.filter(
                customer=customer,
                plan_id__in=plan_ids,
            )
            progress_map = {row.plan_id: int(row.paid_count or 0) for row in rows}

    for plan in plans or []:
        plan.offer_label = plan.offer_display_label
        threshold = int(getattr(plan, "offer_pay_count", 0) or 0) if plan.offer_enabled else 0
        plan.offer_threshold = threshold if threshold >= 1 else None
        if customer is None or not plan.offer_enabled or threshold < 1:
            plan.offer_paid_count = None
            plan.offer_payments_remaining = None
            plan.offer_percent = None
            plan.offer_slots = []
            continue
        paid_count = int(progress_map.get(plan.pk, 0) or 0)
        paid_capped = min(paid_count, threshold)
        plan.offer_paid_count = paid_capped
        plan.offer_payments_remaining = payments_until_free(plan, paid_capped)
        plan.offer_percent = int(round((paid_capped / threshold) * 100))
        plan.offer_slots = [{"filled": index < paid_capped} for index in range(threshold)]
    return plans


def started_offer_progress_for_customer(customer, *, request=None) -> list[dict]:
    """
    Visual progress rows for each offer the customer has progress on.

    Includes every enabled package offer for this customer with at least one
    paid session, so welcome / result pages can show per-offer progress.
    """
    if customer is None:
        return []

    rows = (
        PackageOfferProgress.objects.filter(
            customer=customer,
            paid_count__gte=1,
            plan__offer_enabled=True,
            plan__offer_pay_count__gte=1,
        )
        .select_related("plan")
        .order_by("-updated_at", "plan__name")
    )

    out: list[dict] = []
    for row in rows:
        plan = row.plan
        threshold = int(plan.offer_pay_count or 0)
        if threshold < 1:
            continue
        paid = min(int(row.paid_count or 0), threshold)
        out.append(_offer_progress_row(plan, paid, request=request))
    return out


def dummy_offer_progress_for_org(organization, *, request=None, limit: int = 3) -> list[dict]:
    """
    Preview rows for the bare welcome URL (no customer MAC yet).

    Uses the org's enabled Hotspot offers with sample paid counts so staff can
    see how per-offer progress will look for real clients.
    """
    from billing.models import BillingPlan

    if organization is None:
        return []

    plans = list(
        BillingPlan.objects.filter(
            organization=organization,
            service_type=BillingPlan.ServiceType.HOTSPOT,
            offer_enabled=True,
            offer_pay_count__gte=1,
        ).order_by("price", "name")[: max(1, int(limit or 3))]
    )
    out: list[dict] = []
    for index, plan in enumerate(plans):
        threshold = int(plan.offer_pay_count or 0)
        if threshold < 1:
            continue
        # Sample progress: nearly complete on the first card, mid-way on others.
        if index == 0:
            paid = max(threshold - 1, 1)
        else:
            paid = max(1, threshold // 2)
        paid = min(paid, threshold)
        row = _offer_progress_row(plan, paid, request=request)
        row["is_dummy"] = True
        out.append(row)
    return out


def _offer_progress_row(plan, paid: int, *, request=None) -> dict:
    threshold = int(getattr(plan, "offer_pay_count", 0) or 0)
    paid = min(max(int(paid or 0), 0), threshold) if threshold else 0
    remaining = int(payments_until_free(plan, paid) or 0) if threshold else 0
    image_url = ""
    if getattr(plan, "image", None):
        try:
            path = plan.image.url
        except Exception:
            path = ""
        if path:
            if request is not None:
                try:
                    image_url = request.build_absolute_uri(path)
                except Exception:
                    image_url = path
            else:
                image_url = path
    if remaining == 1:
        nudge = "1 more payment unlocks a free session"
    elif remaining > 1:
        nudge = f"{remaining} more payments until a free session"
    else:
        nudge = "Next payment unlocks a free session"
    return {
        "plan_id": plan.pk,
        "plan_name": plan.name,
        "offer_label": plan.offer_display_label,
        "paid_count": paid,
        "threshold": threshold,
        "remaining": remaining,
        "percent": int(round((paid / threshold) * 100)) if threshold else 0,
        "slots": [{"filled": index < paid} for index in range(threshold)],
        "image_url": image_url,
        "nearly_free": remaining == 1,
        "nudge": nudge,
        "progress_label": f"{paid} of {threshold} paid",
        "is_dummy": False,
    }


def apply_paid_subscription_with_offer(customer, *, plan=None) -> dict:
    """
    Extend prepaid access after payment and update buy-X-get-1-free progress.

    Returns metadata used by pay portals and staff tools.
    """
    from billing.services import apply_subscription_renewal

    plan = plan or getattr(customer, "plan", None)
    if plan is None:
        raise ValueError("Customer has no billing plan to renew.")

    apply_subscription_renewal(customer, plan=plan)

    free_granted = False
    paid_count = 0
    remaining = payments_until_free(plan, 0)

    if plan.offer_enabled and int(plan.offer_pay_count or 0) >= 1:
        with transaction.atomic():
            progress, _created = PackageOfferProgress.objects.select_for_update().get_or_create(
                customer=customer,
                plan=plan,
                defaults={"paid_count": 0},
            )
            progress.paid_count = int(progress.paid_count or 0) + 1
            if progress.paid_count >= int(plan.offer_pay_count):
                apply_subscription_renewal(customer, plan=plan)
                progress.paid_count = 0
                free_granted = True
            progress.save(update_fields=["paid_count", "updated_at"])
            paid_count = int(progress.paid_count or 0)
            remaining = payments_until_free(plan, paid_count)

    return {
        "free_session_granted": free_granted,
        "offer_paid_count": paid_count,
        "offer_payments_remaining": remaining,
        "offer_label": plan.offer_display_label if plan.offer_enabled else "",
    }
