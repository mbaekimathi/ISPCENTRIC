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
        if customer is None or not plan.offer_enabled:
            plan.offer_paid_count = None
            plan.offer_payments_remaining = None
            continue
        paid_count = progress_map.get(plan.pk, 0)
        plan.offer_paid_count = paid_count
        plan.offer_payments_remaining = payments_until_free(plan, paid_count)
    return plans


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
