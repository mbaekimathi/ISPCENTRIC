"""Sync internet access from package start/end dates across all organizations."""

from django.core.management.base import BaseCommand
from django.db.models import Q

from billing.models import Customer
from core.mikrotik_connect import (
    repair_hotspot_captive_portal,
    repair_router_expired_captive_redirect,
    sweep_log_text,
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

    def _write(self, stream, message, style=None):
        """Write sweep lines without crashing Windows cp1252 consoles on arrows."""
        text = sweep_log_text(message)
        if style is not None:
            text = style(text)
        try:
            stream.write(text)
        except UnicodeEncodeError:
            encoding = getattr(getattr(stream, "_out", None), "encoding", None) or "ascii"
            stream.write(text.encode(encoding, errors="replace").decode(encoding))

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
        expired_hotspot: list[Customer] = []
        # NAS routers that blocked at least one PPPoE client — repair captive
        # redirect rules so any device that dials/connects still pops pay instantly.
        repair_router_ids: set[int] = set()

        for customer in qs:
            receives = customer_receives_internet(customer)
            if dry_run:
                label = "ALLOW" if receives else "BLOCK"
                self._write(
                    self.stdout,
                    f"{label}  {customer.account_number}  {customer.full_name}  "
                    f"{customer.package_start} -> {customer.package_end}",
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
                    expired_hotspot.append(customer)
                continue

            result = sync_customer_subscription_access(
                customer,
                provision=True,
            )
            if result.get("allowed"):
                allowed += 1
                # Paid clients whose CPE was offline at restore time still need
                # the renew Hotspot cleared once they redial.
                if (
                    customer.service_type == Customer.ServiceType.PPPOE
                    and result.get("cpe_renew_clear_pending")
                    and not dry_run
                ):
                    try:
                        from core.mikrotik_connect import (
                            _clear_cpe_renew_with_retries,
                            _pppoe_pay_portal_url,
                        )

                        pay_url = _pppoe_pay_portal_url(
                            customer.organization, customer=customer
                        )
                        clear = _clear_cpe_renew_with_retries(
                            customer,
                            pay_url=pay_url,
                            attempts=2,
                            settle_seconds=1.0,
                        )
                        if clear.get("ok"):
                            self._write(
                                self.stdout,
                                f"{customer.account_number}: cpe-renew cleared",
                            )
                        elif not clear.get("skipped"):
                            errors += 1
                            self._write(
                                self.stderr,
                                f"{customer.account_number}: cpe-clear "
                                f"{clear.get('error') or 'failed'}",
                                style=self.style.WARNING,
                            )
                    except Exception as exc:  # noqa: BLE001
                        errors += 1
                        self._write(
                            self.stderr,
                            f"{customer.account_number}: cpe-clear {exc}",
                            style=self.style.WARNING,
                        )
            else:
                blocked += 1
                router_id = getattr(customer, "router_id", None)
                if router_id:
                    repair_router_ids.add(router_id)
                # Re-push CPE renew only when the earlier attempt actually failed
                # (not when the CPE was offline / skipped — that just wastes API).
                portal = result.get("portal") or {}
                if (
                    customer.service_type == Customer.ServiceType.PPPOE
                    and not portal.get("ok")
                    and not portal.get("skipped")
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
                            self._write(
                                self.stdout,
                                f"{customer.account_number}: cpe-renew repaired",
                            )
                        elif not retry.get("skipped"):
                            errors += 1
                            self._write(
                                self.stderr,
                                f"{customer.account_number}: cpe-renew "
                                f"{retry.get('error') or 'failed'}",
                                style=self.style.WARNING,
                            )
                    except Exception as exc:  # noqa: BLE001
                        errors += 1
                        self._write(
                            self.stderr,
                            f"{customer.account_number}: cpe-renew {exc}",
                            style=self.style.WARNING,
                        )
            if not result.get("ok"):
                portal = result.get("portal") or {}
                provision = result.get("provision") or {}
                cpe_offline = bool(portal.get("skipped")) and not portal.get("ok")
                nas_ok = bool(provision.get("ok"))
                # CPE offline with NAS already correct is a notice, not a sweep error.
                if cpe_offline and nas_ok:
                    state = "allowed" if result.get("allowed") else "blocked"
                    note = " (CPE offline — NAS ok)"
                    self._write(
                        self.stdout,
                        f"{customer.account_number}: {state}{note}",
                    )
                else:
                    errors += 1
                    err = (
                        portal.get("error")
                        or provision.get("error")
                        or result.get("message")
                    )
                    self._write(
                        self.stderr,
                        f"{customer.account_number}: {err}",
                        style=self.style.WARNING,
                    )
            else:
                state = "allowed" if result.get("allowed") else "blocked"
                self._write(self.stdout, f"{customer.account_number}: {state}")

        if expired_hotspot and not dry_run:
            try:
                from billing.vouchers import (
                    invalidate_unused_vouchers_for_expired_customers,
                )

                burned = invalidate_unused_vouchers_for_expired_customers(
                    expired_hotspot
                )
                if burned:
                    self._write(
                        self.stdout,
                        f"burned {burned} leftover Hotspot voucher(s) after expiry",
                    )
            except Exception as exc:  # noqa: BLE001
                errors += 1
                self._write(
                    self.stderr,
                    f"voucher expiry burn: {exc}",
                    style=self.style.WARNING,
                )

        for router in self._hotspot_routers(hotspot_org_ids):
            # Correction loop: lost login.html / option 114 must not leave unpaid
            # Wi-Fi clients on "connected, no internet" until the next cron.
            result = repair_hotspot_captive_portal(router)
            if result.get("ok") or result.get("skipped"):
                note = "synced"
                if any(
                    "repaired on attempt" in str(n)
                    for n in (result.get("notes") or [])
                ):
                    note = "captive repaired"
                self._write(self.stdout, f"hotspot {router.host}: {note}")
            else:
                errors += 1
                self._write(
                    self.stderr,
                    f"hotspot {router.host}: {result.get('error')}",
                    style=self.style.WARNING,
                )

        for router in self._routers_for_ids(repair_router_ids):
            repair = repair_router_expired_captive_redirect(router)
            if repair.get("ok"):
                self._write(
                    self.stdout,
                    f"expired-redirect {router.host}: "
                    f"{repair.get('message') or 'ok'}",
                )
            elif not repair.get("skipped"):
                errors += 1
                self._write(
                    self.stderr,
                    f"expired-redirect {router.host}: {repair.get('error')}",
                    style=self.style.WARNING,
                )

        self._write(
            self.stdout,
            f"Done. allowed={allowed} blocked={blocked} errors={errors}"
            + (" (dry-run)" if dry_run else ""),
            style=self.style.SUCCESS,
        )
