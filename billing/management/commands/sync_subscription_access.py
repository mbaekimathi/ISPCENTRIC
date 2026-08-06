"""Sync internet access from package start/end dates across all organizations."""

from django.core.management.base import BaseCommand
from django.db.models import Q

from billing.models import Customer
from core.mikrotik_connect import (
    apply_hotspot_on_router,
    repair_router_expired_captive_redirect,
    sync_customer_subscription_access,
)


class Command(BaseCommand):
    help = (
        "Disable internet for PPPoE and Hotspot clients outside their package "
        "period, and re-enable it for those inside it. Also re-installs expired "
        "pay redirects on NAS routers so phones get an instant captive popup."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--organization",
            type=int,
            default=0,
            help="Limit sync to one organization id.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report who would be blocked/allowed without touching routers.",
        )

    @staticmethod
    def _hotspot_routers(org_ids):
        """Every active router of the organizations that have Hotspot clients."""
        from core.models import MikroTikRouter

        if not org_ids:
            return []
        return (
            MikroTikRouter.objects.filter(
                organization_id__in=org_ids,
                account_status=MikroTikRouter.AccountStatus.ACTIVE,
            )
            .exclude(host="")
            .order_by("id")
        )

    @staticmethod
    def _routers_for_ids(router_ids):
        from core.models import MikroTikRouter

        if not router_ids:
            return []
        return list(
            MikroTikRouter.objects.filter(
                pk__in=router_ids,
                account_status=MikroTikRouter.AccountStatus.ACTIVE,
            )
            .exclude(host="")
            .order_by("id")
        )

    def handle(self, *args, **options):
        from billing.services import customer_receives_internet

        # Hotspot packages are usually hourly, so this sweep is what ends a
        # session on time: nothing else revisits a Hotspot MAC between the
        # payment that provisioned it and its expiry.
        qs = (
            Customer.objects.filter(
                Q(service_type=Customer.ServiceType.PPPOE) & ~Q(pppoe_username="")
                | Q(service_type=Customer.ServiceType.HOTSPOT) & ~Q(hotspot_mac="")
            )
            .select_related("plan", "organization", "router")
            .order_by("organization_id", "id")
        )
        org_id = int(options.get("organization") or 0)
        if org_id:
            qs = qs.filter(organization_id=org_id)

        dry_run = bool(options.get("dry_run"))
        blocked = allowed = errors = 0
        hotspot_org_ids: set[int] = set()
        # NAS routers that blocked at least one PPPoE client — repair captive
        # redirect rules so any device that dials/connects still pops pay instantly.
        repair_router_ids: set[int] = set()

        for customer in qs:
            receives = customer_receives_internet(customer)
            if dry_run:
                label = "ALLOW" if receives else "BLOCK"
                self.stdout.write(
                    f"{label}  {customer.account_number}  {customer.full_name}  "
                    f"{customer.package_start} -> {customer.package_end}"
                )
                if receives:
                    allowed += 1
                else:
                    blocked += 1
                continue

            # Hotspot access lives in a per-router user table that is rewritten
            # wholesale, so it is swept once per router below rather than once
            # per customer.
            if customer.service_type == Customer.ServiceType.HOTSPOT:
                hotspot_org_ids.add(customer.organization_id)
                if receives:
                    allowed += 1
                else:
                    blocked += 1
                continue

            result = sync_customer_subscription_access(
                customer,
                provision=True,
            )
            if result.get("allowed"):
                allowed += 1
            else:
                blocked += 1
                router_id = getattr(customer, "router_id", None)
                if router_id:
                    repair_router_ids.add(router_id)
                # Re-push CPE renew popup when surfing is blocked but login.html
                # never landed (or CPE was offline at cut-off).
                portal = result.get("portal") or {}
                if (
                    customer.service_type == Customer.ServiceType.PPPOE
                    and not portal.get("ok")
                    and not dry_run
                ):
                    try:
                        from core.mikrotik_connect import (
                            _pppoe_pay_portal_url,
                            apply_cpe_renew_portal,
                        )

                        pay_url = _pppoe_pay_portal_url(
                            customer.organization, customer=customer
                        )
                        retry = apply_cpe_renew_portal(
                            customer, enabled=True, portal_url=pay_url
                        )
                        if retry.get("ok"):
                            self.stdout.write(
                                f"{customer.account_number}: cpe-renew repaired"
                            )
                        elif not retry.get("skipped"):
                            errors += 1
                            self.stderr.write(
                                self.style.WARNING(
                                    f"{customer.account_number}: cpe-renew "
                                    f"{retry.get('error') or 'failed'}"
                                )
                            )
                    except Exception as exc:  # noqa: BLE001
                        errors += 1
                        self.stderr.write(
                            self.style.WARNING(
                                f"{customer.account_number}: cpe-renew {exc}"
                            )
                        )
            if not result.get("ok"):
                errors += 1
                err = (
                    (result.get("portal") or {}).get("error")
                    or (result.get("provision") or {}).get("error")
                    or result.get("message")
                )
                self.stderr.write(self.style.WARNING(f"{customer.account_number}: {err}"))
            else:
                state = "allowed" if result.get("allowed") else "blocked"
                self.stdout.write(f"{customer.account_number}: {state}")

        for router in self._hotspot_routers(hotspot_org_ids):
            result = apply_hotspot_on_router(router, enabled=True)
            if result.get("ok"):
                self.stdout.write(f"hotspot {router.host}: synced")
            else:
                errors += 1
                self.stderr.write(
                    self.style.WARNING(f"hotspot {router.host}: {result.get('error')}")
                )

        for router in self._routers_for_ids(repair_router_ids):
            repair = repair_router_expired_captive_redirect(router)
            if repair.get("ok"):
                self.stdout.write(
                    f"expired-redirect {router.host}: "
                    f"{repair.get('message') or 'ok'}"
                )
            elif not repair.get("skipped"):
                errors += 1
                self.stderr.write(
                    self.style.WARNING(
                        f"expired-redirect {router.host}: {repair.get('error')}"
                    )
                )

        self.stdout.write(
            self.style.SUCCESS(
                f"Done. allowed={allowed} blocked={blocked} errors={errors}"
                + (" (dry-run)" if dry_run else "")
            )
        )
