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
    parts = [p for p in (name, account) if p]
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
        f"client_remote_access:{customer_id}:v4",
        f"client_remote_access_stable:{customer_id}:v1",
        f"client_remote_access_pending:{customer_id}:v1",
    ]
    if org_id:
        keys.extend(
            [
                f"clients_surfing:{org_id}:pppoe:v9",
                f"clients_surfing:{org_id}:hotspot:v9",
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


def collect_customer_hotspot_macs(customer) -> list[str]:
    """MACs to purge from the NAS before the customer/device row disappears."""
    from billing.devices import hotspot_macs_for_customer, normalize_device_mac

    macs: list[str] = []
    seen: set[str] = set()
    for raw in hotspot_macs_for_customer(customer):
        mac = normalize_device_mac(raw)
        if mac and mac not in seen:
            seen.add(mac)
            macs.append(mac)
    primary = normalize_device_mac(getattr(customer, "hotspot_mac", "") or "")
    if primary and primary not in seen:
        macs.append(primary)
    return macs


def enqueue_hotspot_macs_block(organization, macs: list[str]) -> None:
    """Retry Hotspot MAC removal when the router was offline at delete time."""
    if not organization or not macs:
        return
    try:
        from core.mikrotik_connect import enqueue_hotspot_block_pending

        for mac in macs:
            enqueue_hotspot_block_pending(organization, mac, customer_id=None)
    except Exception:
        logger.exception(
            "Could not enqueue Hotspot block pending for org=%s",
            getattr(organization, "pk", None),
        )


def disconnect_customer_from_nas(customer) -> dict:
    """
    Kick the subscriber off the ISP MikroTik and drop live credentials.

    Hotspot: disable + remove MAC users and sessions.
    PPPoE: remove /ppp/secret (not only disable) and kick the active session.
    """
    from billing.models import Customer

    service = getattr(customer, "service_type", "")
    result: dict = {"ok": False, "service": service, "macs": [], "deferred": False}

    if service == Customer.ServiceType.HOTSPOT:
        from core.mikrotik_connect import disconnect_hotspot_customer

        macs = collect_customer_hotspot_macs(customer)
        result["macs"] = list(macs)
        nas = disconnect_hotspot_customer(customer, macs=macs)
        result["ok"] = bool(nas.get("ok") or nas.get("skipped"))
        result["deferred"] = bool(nas.get("skipped") or nas.get("timeout"))
        result["nas"] = nas
        if result["deferred"] or not nas.get("ok"):
            enqueue_hotspot_macs_block(getattr(customer, "organization", None), macs)
        return result

    if service == Customer.ServiceType.PPPOE and (customer.pppoe_username or "").strip():
        if not customer.router_id:
            return {**result, "ok": True, "skipped": True, "message": "No router."}
        try:
            from core.mikrotik_connect import remove_customer_pppoe_secret

            nas = remove_customer_pppoe_secret(customer)
            result["ok"] = bool(nas.get("ok") or nas.get("skipped"))
            result["nas"] = nas
            if not result["ok"]:
                # Fall back to disable so the account cannot dial while offline.
                from core.mikrotik_connect import provision_customer_pppoe

                provision_customer_pppoe(
                    customer, ensure_stack=False, force_disabled=True
                )
        except Exception:
            logger.exception(
                "Could not remove PPPoE secret for deleted customer=%s",
                customer.pk,
            )
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
        return result

    return {**result, "ok": True, "skipped": True}


def purge_customer_access_credentials(
    customer, *, clear_pppoe_password: bool = True
) -> dict:
    """
    Remove access credentials (vouchers, CPE secrets) while keeping Payment/Invoice/STK.

    Voucher codes are access credentials — deleting them frees the MAC/phone for
    a clean pay-page re-registration. Payment rows stay for books / M-Pesa audit.

    ``clear_pppoe_password=False`` keeps the dial password so End access can
    re-provision after the next recharge without regenerating secrets.
    """
    from billing.models import AccessVoucher

    vouchers_deleted, _ = AccessVoucher.objects.filter(customer_id=customer.pk).delete()
    # Clear CPE admin credentials stored on the customer row.
    fields = ["cpe_username", "cpe_password", "wifi_password"]
    if clear_pppoe_password:
        fields.append("pppoe_password")
    updates: list[str] = []
    for field in fields:
        if hasattr(customer, field) and getattr(customer, field, None):
            setattr(customer, field, "")
            updates.append(field)
    if updates:
        try:
            customer.save(update_fields=updates)
        except Exception:
            logger.exception(
                "Could not clear CPE credentials customer=%s", customer.pk
            )
    return {"vouchers_deleted": int(vouchers_deleted or 0)}


def purge_customer_session_details(customer) -> None:
    """Drop usage / funnel rows; billing rows stay via FK SET_NULL or CASCADE rules."""
    from billing.models import CustomerUsageSample, HotspotConnectionAttempt

    CustomerUsageSample.objects.filter(customer_id=customer.pk).delete()
    HotspotConnectionAttempt.objects.filter(customer_id=customer.pk).delete()


def scrub_portal_leads_for_customer(customer) -> int:
    """Forget MAC on portal click leads so deleted devices are not re-surfaced."""
    try:
        from accounts.models import HotspotPortalClick
    except Exception:
        return 0
    mac = (getattr(customer, "hotspot_mac", None) or "").strip()
    qs = HotspotPortalClick.objects.filter(customer_id=customer.pk)
    updated = qs.update(hotspot_mac="", customer=None)
    if mac:
        updated += HotspotPortalClick.objects.filter(
            organization_id=customer.organization_id,
            hotspot_mac__iexact=mac,
        ).update(hotspot_mac="")
    return int(updated or 0)


@transaction.atomic
def delete_customer_preserving_transactions(customer) -> dict:
    """
    Remove the subscriber from the workspace and NAS, drop credentials and
    session details, and keep invoices, payments, and STK history (unlinked).

    After delete the device MAC / phone is free so the captive pay page can
    register a fresh Hotspot shell on the next Wi‑Fi join.
    """
    if customer is None or not getattr(customer, "pk", None):
        return {"ok": False, "error": "No customer to delete."}

    customer_id = customer.pk
    org = getattr(customer, "organization", None)
    org_id = customer.organization_id
    service_type = customer.service_type
    name = customer.full_name or ""
    macs = collect_customer_hotspot_macs(customer)

    # NAS first while MAC / PPPoE identity is still known.
    nas_result: dict = {}
    try:
        nas_result = disconnect_customer_from_nas(customer)
    except Exception:
        logger.exception("NAS disconnect failed during delete customer=%s", customer_id)
        enqueue_hotspot_macs_block(org, macs)

    creds = purge_customer_access_credentials(customer)
    _stamp_invoices_for_deleted_customer(customer)
    purge_customer_session_details(customer)
    scrub_portal_leads_for_customer(customer)
    clear_customer_live_caches(customer)

    customer.delete()

    return {
        "ok": True,
        "customer_id": customer_id,
        "organization_id": org_id,
        "service_type": service_type,
        "name": name,
        "macs_purged": macs,
        "vouchers_deleted": creds.get("vouchers_deleted", 0),
        "nas": nas_result,
    }


@transaction.atomic
def delete_hotspot_device(customer, mac: str) -> dict:
    """
    Remove one Hotspot gadget from a client: NAS user, device row, voucher claim.

    Keeps the Customer and all Payment / Invoice / STK rows so they can pay again.
    If this was the last / primary device and the account is an unpaid shell,
    discard the shell so the MAC is fully free for the pay page.
    """
    from billing.devices import (
        discard_unpaid_hotspot_pay_shell,
        is_unpaid_hotspot_pay_shell,
        normalize_device_mac,
        set_primary_hotspot_mac,
    )
    from billing.models import AccessVoucher, Customer, CustomerDevice

    if customer is None or not getattr(customer, "pk", None):
        return {"ok": False, "error": "No customer."}
    mac = normalize_device_mac(mac)
    if not mac:
        return {"ok": False, "error": "Could not identify this device."}
    if getattr(customer, "service_type", "") != Customer.ServiceType.HOTSPOT:
        return {"ok": False, "error": "Only Hotspot devices can be removed this way."}

    org = getattr(customer, "organization", None)

    # Kick this MAC off the NAS while we still know the customer.
    try:
        from core.mikrotik_connect import disconnect_hotspot_customer

        nas = disconnect_hotspot_customer(customer, macs=[mac])
        if nas.get("skipped") or nas.get("timeout") or not nas.get("ok"):
            enqueue_hotspot_macs_block(org, [mac])
    except Exception:
        logger.exception(
            "NAS disconnect failed during device delete customer=%s mac=%s",
            customer.pk,
            mac,
        )
        enqueue_hotspot_macs_block(org, [mac])

    # Drop voucher claims / codes reserved for this MAC (access credentials).
    AccessVoucher.objects.filter(
        customer_id=customer.pk,
        redeemed_mac__iexact=mac,
    ).delete()
    # Unused VALID sibling codes stay — they belong to other gadgets on the account.

    CustomerDevice.objects.filter(
        organization_id=customer.organization_id,
        mac__iexact=mac,
    ).delete()

    primary = normalize_device_mac(getattr(customer, "hotspot_mac", "") or "")
    remaining = list(
        CustomerDevice.objects.filter(customer_id=customer.pk)
        .exclude(mac__iexact=mac)
        .values_list("mac", flat=True)
    )
    if primary == mac:
        if remaining:
            set_primary_hotspot_mac(customer, remaining[0])
        else:
            customer.hotspot_mac = None
            customer.save(update_fields=["hotspot_mac"])

    clear_customer_live_caches(customer)

    # Never-paid shells with no devices left: remove the customer row so the
    # MAC can rejoin the pay page cleanly. Paid accounts stay for billing.
    discarded = False
    customer.refresh_from_db()
    if is_unpaid_hotspot_pay_shell(customer) and not remaining:
        discarded = bool(discard_unpaid_hotspot_pay_shell(customer))

    return {
        "ok": True,
        "mac": mac,
        "customer_deleted": discarded,
        "remaining_devices": len(remaining),
    }


def reset_live_access_for_repay(customer) -> dict:
    """
    After ending a package, reset access credentials so the client can pay again.

    Keeps the Customer row and billing history (Invoice / Payment / STK).
    Purges devices, vouchers, usage samples, and live NAS credentials so Hotspot
    MACs are free for the captive pay page and PPPoE cannot dial until recharged.
    """
    from billing.models import Customer

    if customer is None or not getattr(customer, "pk", None):
        return {"ok": False, "error": "No customer."}

    service = getattr(customer, "service_type", "")
    macs = collect_customer_hotspot_macs(customer)
    provision_result: dict = {"ok": False, "skipped": True}
    devices_unlinked: list[str] = []

    # Kick / remove NAS credentials while MAC / PPPoE identity is still known.
    try:
        nas_result = disconnect_customer_from_nas(customer)
        provision_result = {"ok": True, "nas": nas_result}
    except Exception:
        logger.exception(
            "NAS disconnect failed while resetting access customer=%s",
            customer.pk,
        )
        enqueue_hotspot_macs_block(getattr(customer, "organization", None), macs)

    if service == Customer.ServiceType.HOTSPOT:
        try:
            from billing.devices import unlink_hotspot_devices

            # Empty keep list: drop every gadget so MACs can rejoin the pay page.
            devices_unlinked = unlink_hotspot_devices(customer, keep_macs=[])
        except Exception:
            logger.exception(
                "Device unlink failed while resetting access customer=%s",
                customer.pk,
            )
            devices_unlinked = []
            if getattr(customer, "hotspot_mac", None):
                try:
                    customer.hotspot_mac = None
                    customer.save(update_fields=["hotspot_mac"])
                except Exception:
                    pass
    elif service == Customer.ServiceType.PPPOE and not provision_result.get("ok"):
        # disconnect_customer_from_nas already removes the secret when possible;
        # fall back to disable if that path skipped or failed.
        if customer.router_id:
            try:
                from core.mikrotik_connect import provision_customer_pppoe

                provision_result = provision_customer_pppoe(
                    customer, ensure_stack=False, force_disabled=True
                )
            except Exception:
                logger.exception(
                    "PPPoE disable fallback failed while ending access customer=%s",
                    customer.pk,
                )

    # Vouchers are access credentials — delete them (payments stay).
    # Keep PPPoE dial password so the next recharge can re-push /ppp/secret.
    creds = purge_customer_access_credentials(
        customer,
        clear_pppoe_password=(service != Customer.ServiceType.PPPOE),
    )

    purge_customer_session_details(customer)
    scrub_portal_leads_for_customer(customer)
    clear_customer_live_caches(customer)
    try:
        from core.mikrotik_connect import invalidate_captive_redirect_cache_for_customer

        invalidate_captive_redirect_cache_for_customer(customer)
    except Exception:
        pass

    return {
        "ok": True,
        "provision": provision_result,
        "macs_purged": macs,
        "devices_unlinked": devices_unlinked,
        "vouchers_deleted": creds.get("vouchers_deleted", 0),
    }
