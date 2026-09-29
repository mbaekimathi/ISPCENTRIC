"""Bulk transfer of billing clients between MikroTik routers."""

from __future__ import annotations

import logging
import threading
from typing import Any

from django.core.cache import cache
from django.db.models import Count, Q

from billing.models import Customer
from core.models import MikroTikRouter
from core.subscription_sync import (
    customer_needs_nas_provision,
    enqueue_customer_subscription_sync,
)

logger = logging.getLogger(__name__)


def transfer_customer_to_router(customer: Customer, target_router: MikroTikRouter) -> dict[str, Any]:
    """
    Reassign one client to ``target_router`` and enqueue NAS provision when needed.

    Mirrors the single-client ``update_client_details`` router_changed path.
    """
    from core.mikrotik_connect import (
        provision_customer_pppoe,
        provision_static_client_dhcp_lease,
    )

    old_router_id = customer.router_id
    target_id = getattr(target_router, "pk", None)
    if old_router_id == target_id:
        return {"moved": False, "reason": "already_on_target"}

    customer.router = target_router
    customer.save(update_fields=["router"])

    org_id = getattr(customer, "organization_id", None)
    if org_id:
        cache.delete(f"client_cpe_router_data:{org_id}:{customer.pk}")
        cache.delete(f"client_cpe_wifi:{org_id}:{customer.pk}")

    sync_pppoe = (
        customer.service_type == Customer.ServiceType.PPPOE
        and bool(customer.router_id)
        and bool((customer.pppoe_username or "").strip())
    )
    static_dhcp_bind = (
        customer.service_type == Customer.ServiceType.STATIC
        and bool(customer.router_id)
        and bool((customer.cpe_ip or "").strip())
        and bool((customer.cpe_mac or "").strip())
    )

    if sync_pppoe:

        def _bg_provision(pk: int = customer.pk) -> None:
            from django.db import connection

            try:
                cust = Customer.objects.select_related(
                    "plan", "router", "organization"
                ).get(pk=pk)
                if cust.pppoe_username and cust.router_id:
                    provision_customer_pppoe(cust, ensure_stack=False)
            except Exception:
                logger.exception("PPPoE provision failed after transfer for customer %s", pk)
            finally:
                connection.close()

        threading.Thread(target=_bg_provision, daemon=True).start()

    if static_dhcp_bind:

        def _bg_bind(pk: int = customer.pk) -> None:
            from django.db import connection

            try:
                cust = Customer.objects.select_related("router", "organization").get(
                    pk=pk
                )
                provision_static_client_dhcp_lease(cust)
            except Exception:
                logger.exception("Static DHCP bind failed after transfer for customer %s", pk)
            finally:
                connection.close()

        threading.Thread(target=_bg_bind, daemon=True).start()

    if customer.router_id and (customer.pppoe_username or "").strip():
        enqueue_customer_subscription_sync(
            customer.pk,
            customer_needs_nas_provision(customer),
            wait_first=True,
            quick=True,
        )

    return {
        "moved": True,
        "from_router_id": old_router_id,
        "to_router_id": target_id,
        "sync_pppoe": sync_pppoe,
        "static_dhcp": static_dhcp_bind,
    }


def build_transfer_groups(org, *, focus_router_id: int | None = None) -> tuple[list, list, list]:
    """Return (routers, PPPoE customers, groups) for the transfer page.

    Hotspot clients are excluded — they are not provisioned per-router the same way.
    """
    pppoe = Customer.ServiceType.PPPOE
    routers = list(
        MikroTikRouter.objects.filter(organization=org)
        .annotate(
            customer_count=Count(
                "customers",
                filter=Q(customers__service_type=pppoe),
            )
        )
        .order_by("name")
    )
    customers = list(
        Customer.objects.filter(organization=org, service_type=pppoe)
        .select_related("router", "plan")
        .order_by("full_name", "id")
    )

    groups: list[dict[str, Any]] = []
    for router in routers:
        groups.append(
            {
                "key": f"r{router.pk}",
                "router": router,
                "router_id": router.pk,
                "title": router.name,
                "subtitle": router.host or "",
                "customers": [c for c in customers if c.router_id == router.pk],
                "focused": focus_router_id == router.pk,
            }
        )
    unassigned = [c for c in customers if not c.router_id]
    groups.append(
        {
            "key": "unassigned",
            "router": None,
            "router_id": None,
            "title": "No MikroTik assigned",
            "subtitle": "Clients not linked to a router yet",
            "customers": unassigned,
            "focused": False,
        }
    )
    if focus_router_id:
        groups.sort(key=lambda g: (0 if g.get("focused") else 1, g["title"].lower()))
    return routers, customers, groups
