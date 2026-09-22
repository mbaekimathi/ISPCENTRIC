"""Remove a subscriber while keeping billing transactions for audit and re-pay."""

from __future__ import annotations

import logging

from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)


def _stamp_invoices_for_deleted_customer(customer) -> None:
    """Keep a short identity note on invoices after the client row is removed."""
    from billing.models import Invoice

    name = (getattr(customer, "full_name", None) or "").strip()
    account = (getattr(customer, "account_number", None) or "").strip()
    phone = (getattr(customer, "phone", None) or "").strip()
    mac = (getattr(customer, "hotspot_mac", None) or "").strip()
    parts = [p for p in (name, account, phone, f"MAC {mac}" if mac else "") if p]
    if not parts:
        return
    stamp = (
        f"[Client deleted {timezone.localtime().strftime('%Y-%m-%d %H:%M')}] "
        + " · ".join(parts)
    )
    for invoice in Invoice.objects.filter(customer_id=customer.pk).only("pk", "notes"):
        existing = (invoice.notes or "").strip()
        if stamp in existing:
            continue
        merged = f"{existing}\n{stamp}".strip() if existing else stamp
        Invoice.objects.filter(pk=invoice.pk).update(notes=merged)


def clear_customer_live_caches(customer) -> None:
    org_id = getattr(customer, "organization_id", None)
    customer_id = getattr(customer, "pk", None)
    if not customer_id:
        return
    keys = [
        f"client_usage:v3:{org_id}:{customer_id}",
        f"client_cpe_router_data:{org_id}:{customer_id}",
        f"client_cpe_router_data:devices:{org_id}:{customer_id}",
        f"client_cpe_wifi:{org_id}:{customer_id}",
    ]
    if org_id:
        keys.extend(
            [
                f"clients_surfing:{org_id}:pppoe:v8",
                f"clients_surfing:{org_id}:hotspot:v8",
            ]
        )
    cache.delete_many([k for k in keys if k and "None" not in k])
    try:
        from billing.usage_samples import _invalidate_client_usage_trend_cache

        _invalidate_client_usage_trend_cache(customer_id)
    except Exception:
        pass
    try:
        from core.mikrotik_connect import clear_hotspot_authorize_pending

        clear_hotspot_authorize_pending(customer)
    except Exception:
        pass


def disconnect_customer_from_nas(customer) -> None:
    from billing.models import Customer

    service = getattr(customer, "service_type", "")
    if service == Customer.ServiceType.HOTSPOT:
        from core.mikrotik_connect import disconnect_hotspot_customer

        disconnect_hotspot_customer(customer)
        return
    if service == Customer.ServiceType.PPPOE and (customer.pppoe_username or "").strip():
        if not customer.router_id:
            return
        try:
            from core.mikrotik_connect import provision_customer_pppoe

            provision_customer_pppoe(
                customer, ensure_stack=False, force_disabled=True
            )
        except Exception:
            logger.exception(
                "Could not disable PPPoE for deleted customer=%s",
                customer.pk,
            )


def _invalidate_open_vouchers(customer) -> int:
    from billing.models import AccessVoucher

    return AccessVoucher.objects.filter(
        customer_id=customer.pk,
        status=AccessVoucher.Status.VALID,
    ).update(
        status=AccessVoucher.Status.INVALID,
        invalidated_at=timezone.now(),
    )


def purge_customer_session_details(customer) -> None:
    """Drop usage / funnel rows; billing rows stay via FK SET_NULL or CASCADE rules."""
    from billing.models import CustomerUsageSample, HotspotConnectionAttempt

    CustomerUsageSample.objects.filter(customer_id=customer.pk).delete()
    HotspotConnectionAttempt.objects.filter(customer_id=customer.pk).delete()


@transaction.atomic
def delete_customer_preserving_transactions(customer) -> dict:
    """
    Remove the subscriber from the workspace and NAS, drop session/usage
    details, and keep invoices, payments, and STK history (unlinked).

    After delete the device MAC / phone is free so the captive pay page can
    register a fresh Hotspot shell on the next Wi‑Fi join.
    """
    from billing.models import Customer

    if customer is None or not getattr(customer, "pk", None):
        return {"ok": False, "error": "No customer to delete."}

    customer_id = customer.pk
    org_id = customer.organization_id
    service_type = customer.service_type
    name = customer.full_name or ""

    # NAS first while MAC / PPPoE identity is still known.
    try:
        disconnect_customer_from_nas(customer)
    except Exception:
        logger.exception("NAS disconnect failed during delete customer=%s", customer_id)

    vouchers_invalidated = _invalidate_open_vouchers(customer)
    _stamp_invoices_for_deleted_customer(customer)
    purge_customer_session_details(customer)
    clear_customer_live_caches(customer)

    customer.delete()

    return {
        "ok": True,
        "customer_id": customer_id,
        "organization_id": org_id,
        "service_type": service_type,
        "name": name,
        "vouchers_invalidated": vouchers_invalidated,
    }


def reset_live_access_for_repay(customer) -> dict:
    """
    After ending a package, kick live sessions, clear usage snapshots, and
    push the captive pay path — without deleting the client or billing history.
    """
    from billing.models import Customer

    if customer is None or not getattr(customer, "pk", None):
        return {"ok": False, "error": "No customer."}

    provision_result: dict = {"ok": False, "skipped": True}
    service = getattr(customer, "service_type", "")
    if service in (Customer.ServiceType.HOTSPOT, Customer.ServiceType.PPPOE):
        try:
            from core.mikrotik_connect import sync_customer_subscription_access

            provision_result = sync_customer_subscription_access(
                customer,
                provision=True,
                reauthenticate=True,
                quick=False,
            )
        except Exception:
            logger.exception(
                "NAS sync failed while resetting access customer=%s",
                customer.pk,
            )
        if service == Customer.ServiceType.HOTSPOT:
            # Best-effort kick even when sync skipped (router offline).
            try:
                disconnect_customer_from_nas(customer)
            except Exception:
                logger.exception(
                    "Hotspot disconnect failed while resetting access customer=%s",
                    customer.pk,
                )
        elif service == Customer.ServiceType.PPPOE and customer.router_id:
            try:
                from core.mikrotik_connect import provision_customer_pppoe

                provision_customer_pppoe(
                    customer, ensure_stack=False, force_disabled=True
                )
            except Exception:
                logger.exception(
                    "PPPoE block failed while resetting access customer=%s",
                    customer.pk,
                )

    purge_customer_session_details(customer)
    clear_customer_live_caches(customer)
    try:
        from core.mikrotik_connect import invalidate_captive_redirect_cache_for_customer

        invalidate_captive_redirect_cache_for_customer(customer)
    except Exception:
        pass

    return {"ok": True, "provision": provision_result}
