"""Sync internet access from package start/end dates across all organizations."""

from django.core.management.base import BaseCommand
from django.db.models import Q

from billing.models import Customer
from core.mikrotik_connect import (
    refresh_onboarded_router_config,
    sweep_log_text,
    sync_customer_subscription_access,
)
from core.subscription_sync import (
    release_subscription_sweep_lock,
    try_acquire_subscription_sweep_lock,
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
        parser.add_argument(
            "--force",
            action="store_true",
            help=(
                "Run even if another sweep holds the cross-process lock "
                "(emergency only — can race MikroTik API writes)."
            ),
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
        dry_run = bool(options.get("dry_run"))
        force = bool(options.get("force"))
        lock_held = False
        if not dry_run and not force:
            # Match systemd TimeoutStartSec so a crashed sweep cannot wedge the
            # fleet for longer than one timer cycle.
            if not try_acquire_subscription_sweep_lock(ttl_sec=600):
                self._write(
                    self.stdout,
                    "Skipped: another subscription sweep is already running "
                    "(avoids partial MikroTik updates that drop some paid clients).",
                )
                return
            lock_held = True

        try:
            self._sync_all(options, dry_run=dry_run)
        finally:
            if lock_held:
                release_subscription_sweep_lock()

    def _sync_all(self, options, *, dry_run: bool) -> None:
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

        blocked = allowed = errors = 0
        hotspot_org_ids: set[int] = set()
        expired_hotspot: list[Customer] = []

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
            # per customer. Still push paid MACs individually with
            # reauthenticate=False so a failed wholesale rewrite cannot leave
            # a subscribed client disabled after deploy.
            if customer.service_type == Customer.ServiceType.HOTSPOT:
                hotspot_org_ids.add(customer.organization_id)
                if receives:
                    allowed += 1
                    if not dry_run:
                        try:
                            hs_result = sync_customer_subscription_access(
                                customer,
                                provision=True,
                                reauthenticate=False,
                            )
                            if hs_result.get("ok"):
                                self._write(
                                    self.stdout,
                                    f"{customer.account_number}: hotspot allowed",
                                )
                            elif not hs_result.get("skipped"):
                                errors += 1
                                self._write(
                                    self.stderr,
                                    f"{customer.account_number}: hotspot "
                                    f"{(hs_result.get('provision') or {}).get('error') or hs_result.get('message') or 'restore failed'}",
                                    style=self.style.WARNING,
                                )
                        except Exception as exc:  # noqa: BLE001
                            errors += 1
                            self._write(
                                self.stderr,
                                f"{customer.account_number}: hotspot {exc}",
                                style=self.style.WARNING,
                            )
                else:
                    blocked += 1
                    expired_hotspot.append(customer)
                    # Push the MAC disable + session kill immediately. Waiting
                    # only for the later per-router rewrite left expired phones
                    # surfing until that heavier step finished (or failed).
                    if not dry_run:
                        try:
                            hs_result = sync_customer_subscription_access(
                                customer,
                                provision=True,
                            )
                            if hs_result.get("ok"):
                                self._write(
                                    self.stdout,
                                    f"{customer.account_number}: hotspot blocked",
                                )
                            elif not hs_result.get("skipped"):
                                errors += 1
                                self._write(
                                    self.stderr,
                                    f"{customer.account_number}: hotspot "
                                    f"{(hs_result.get('provision') or {}).get('error') or hs_result.get('message') or 'block failed'}",
                                    style=self.style.WARNING,
                                )
                        except Exception as exc:  # noqa: BLE001
                            errors += 1
                            self._write(
                                self.stderr,
                                f"{customer.account_number}: hotspot {exc}",
                                style=self.style.WARNING,
                            )
                continue

            result = sync_customer_subscription_access(
                customer,
                provision=True,
                # Fleet sweep: restore/block on the ISP NAS immediately.
                # Do not stall the whole org on offline CPE SSH/proxy (Ctrl+C
                # traces). Pending CPE renew clear is finished when they redial.
                quick=True,
            )
            if result.get("allowed"):
                allowed += 1
            else:
                blocked += 1
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
                            _CAPTIVE_API_TIMEOUT,
                            _pppoe_pay_portal_url,
                            apply_cpe_renew_portal,
                        )

                        pay_url = _pppoe_pay_portal_url(
                            customer.organization, customer=customer
                        )
                        retry = apply_cpe_renew_portal(
                            customer,
                            enabled=True,
                            portal_url=pay_url,
                            timeout=_CAPTIVE_API_TIMEOUT,
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
                # CPE offline / pending clear with NAS already correct is a
                # notice, not a sweep error — surfing is decided on the NAS.
                if nas_ok and (
                    cpe_offline or result.get("cpe_renew_clear_pending")
                ):
                    state = "allowed" if result.get("allowed") else "blocked"
                    note = (
                        " (CPE renew clear pending)"
                        if result.get("cpe_renew_clear_pending")
                        else " (CPE offline — NAS ok)"
                    )
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
                note = ""
                if result.get("allowed") and result.get("cpe_renew_clear_pending"):
                    note = " (CPE renew clear pending)"
                self._write(self.stdout, f"{customer.account_number}: {state}{note}")

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

        if not dry_run:
            from core.models import MikroTikRouter

            router_qs = (
                MikroTikRouter.objects.filter(
                    account_status=MikroTikRouter.AccountStatus.ACTIVE,
                )
                .exclude(host="")
                .select_related("organization")
                .order_by("id")
            )
            if org_id:
                router_qs = router_qs.filter(organization_id=org_id)

            for router in router_qs:
                # Never force Hotspot re-login on a routine sweep — that drops
                # every paid phone mid-session after deploys / worker restarts.
                result = refresh_onboarded_router_config(
                    router,
                    reauthenticate=False,
                )
                if result.get("ok") or result.get("skipped"):
                    note = result.get("message") or "synced"
                    self._write(self.stdout, f"nas {router.host}: {note}")
                else:
                    errors += 1
                    self._write(
                        self.stderr,
                        f"nas {router.host}: "
                        f"{result.get('error') or result.get('message')}",
                        style=self.style.WARNING,
                    )

        self._write(
            self.stdout,
            f"Done. allowed={allowed} blocked={blocked} errors={errors}"
            + (" (dry-run)" if dry_run else ""),
            style=self.style.SUCCESS,
        )
