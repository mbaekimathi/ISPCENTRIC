"""Sync internet access from package start/end dates across all organizations."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from django.core.management.base import BaseCommand
from django.db.models import Q

from billing.models import Customer
from core.mikrotik_connect import (
    refresh_onboarded_router_config,
    sweep_log_text,
    sync_hotspot_subscription_batch_on_router,
    sync_pppoe_subscription_batch_on_router,
)
from core.subscription_sync import (
    release_subscription_sweep_lock,
    try_acquire_subscription_sweep_lock,
)


class Command(BaseCommand):
    help = (
        "Disable internet for PPPoE and Hotspot clients outside their package "
        "period, and re-enable it for those inside it. Runs per MikroTik with "
        "batch session kicks so CPEs redial together."
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
        parser.add_argument(
            "--clear-lock",
            action="store_true",
            help=(
                "Release a stuck sweep lock (e.g. after Ctrl+C) and exit. "
                "Does not sync routers."
            ),
        )
        parser.add_argument(
            "--workers",
            type=int,
            default=4,
            help="How many MikroTiks to sync in parallel (default 4).",
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

    def handle(self, *args, **options):
        if bool(options.get("clear_lock")):
            release_subscription_sweep_lock()
            self._write(self.stdout, "Subscription sweep lock cleared.")
            return

        dry_run = bool(options.get("dry_run"))
        force = bool(options.get("force"))
        lock_held = False
        if not dry_run and not force:
            if not try_acquire_subscription_sweep_lock(ttl_sec=600):
                self._write(
                    self.stdout,
                    "Skipped: another subscription sweep is already running "
                    "(avoids partial MikroTik updates that drop some paid clients). "
                    "Use --force to run anyway, or --clear-lock if a prior run "
                    "was interrupted.",
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
        from core.models import MikroTikRouter

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

        customers = list(qs)
        if dry_run:
            allowed = blocked = 0
            for customer in customers:
                receives = customer_receives_internet(customer)
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
            self._write(
                self.stdout,
                f"Done. allowed={allowed} blocked={blocked} errors=0 (dry-run)",
                style=self.style.SUCCESS,
            )
            return

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
        routers = list(router_qs)

        hotspot_by_org: dict[int, list[Customer]] = {}
        expired_hotspot: list[Customer] = []
        for customer in customers:
            if customer.service_type != Customer.ServiceType.HOTSPOT:
                continue
            org_pk = customer.organization_id
            hotspot_by_org.setdefault(org_pk, []).append(customer)
            if not customer_receives_internet(customer):
                expired_hotspot.append(customer)

        workers = max(1, min(int(options.get("workers") or 4), 8, max(1, len(routers))))
        errors = 0
        allowed = sum(1 for c in customers if customer_receives_internet(c))
        blocked = len(customers) - allowed

        def _work_one(router):
            from core.mikrotik_connect import _pppoe_customers_for_router

            pppoe_customers = list(_pppoe_customers_for_router(router))
            hs_customers = [
                c
                for c in hotspot_by_org.get(router.organization_id, [])
                if c.router_id in (None, router.pk)
            ]

            pppoe_result = {"ok": True, "allowed": 0, "blocked": 0, "errors": 0, "skipped": True}
            if pppoe_customers:
                pppoe_result = sync_pppoe_subscription_batch_on_router(
                    router, pppoe_customers
                )

            hs_result = {"ok": True, "allowed": 0, "blocked": 0, "errors": 0, "skipped": True}
            if hs_customers:
                hs_result = sync_hotspot_subscription_batch_on_router(
                    router,
                    hs_customers,
                    reauthenticate_paid=False,
                )

            refresh = refresh_onboarded_router_config(
                router,
                reauthenticate=False,
                sync_pppoe_secrets=False,
            )
            return {
                "router": router,
                "pppoe": pppoe_result,
                "hotspot": hs_result,
                "refresh": refresh,
            }

        if not routers:
            self._write(self.stdout, "No active MikroTik routers to sync.")
        elif workers == 1 or len(routers) == 1:
            outcomes = [_work_one(router) for router in routers]
        else:
            outcomes = []
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_work_one, router): router for router in routers}
                for fut in as_completed(futures):
                    try:
                        outcomes.append(fut.result())
                    except Exception as exc:  # noqa: BLE001
                        router = futures[fut]
                        errors += 1
                        self._write(
                            self.stderr,
                            f"nas {getattr(router, 'host', '')}: {exc}",
                            style=self.style.WARNING,
                        )

        for outcome in outcomes:
            router = outcome["router"]
            host = getattr(router, "host", "") or ""
            name = getattr(router, "name", "") or host
            pppoe = outcome.get("pppoe") or {}
            hotspot = outcome.get("hotspot") or {}
            refresh = outcome.get("refresh") or {}

            errors += int(pppoe.get("errors") or 0) + int(hotspot.get("errors") or 0)

            if pppoe.get("ok") or pppoe.get("skipped"):
                kick_n = int(pppoe.get("kick_accounts") or 0)
                self._write(
                    self.stdout,
                    f"nas {name}: {pppoe.get('message') or 'pppoe ok'}"
                    + (f" (batch redial {kick_n} account(s))" if kick_n else ""),
                )
            else:
                errors += 1
                self._write(
                    self.stderr,
                    f"nas {name}: pppoe {pppoe.get('error') or 'failed'}",
                    style=self.style.WARNING,
                )

            if hotspot.get("ok") or hotspot.get("skipped"):
                if not hotspot.get("skipped"):
                    self._write(
                        self.stdout,
                        f"nas {name}: {hotspot.get('message') or 'hotspot ok'}",
                    )
            else:
                errors += 1
                self._write(
                    self.stderr,
                    f"nas {name}: hotspot {hotspot.get('error') or 'failed'}",
                    style=self.style.WARNING,
                )

            if refresh.get("ok") or refresh.get("skipped"):
                self._write(
                    self.stdout,
                    f"nas {host}: {refresh.get('message') or 'captive ok'}",
                )
            else:
                errors += 1
                self._write(
                    self.stderr,
                    f"nas {host}: "
                    f"{refresh.get('error') or refresh.get('message') or 'refresh failed'}",
                    style=self.style.WARNING,
                )

        if expired_hotspot:
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

        self._write(
            self.stdout,
            f"Done. allowed={allowed} blocked={blocked} errors={errors} "
            f"routers={len(routers)} workers={workers}",
            style=self.style.SUCCESS,
        )
