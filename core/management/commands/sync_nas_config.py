"""Push critical NAS config to every active MikroTik after deploy."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from core.mikrotik_connect import refresh_onboarded_router_config, sweep_log_text
from core.subscription_sync import (
    acquire_subscription_sweep_lock_with_retry,
    release_subscription_sweep_lock,
)


class Command(BaseCommand):
    help = (
        "Re-push PPPoE stack / blocked profile, expired pay redirects, and "
        "Hotspot captive portal pages to every active MikroTik. Run after "
        "deploy so routers pick up code changes without a manual UI push. "
        "Holds the subscription fleet lock so it never races the sweep."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--organization",
            type=int,
            default=0,
            help="Limit to one organization id.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="List routers that would be updated without touching them.",
        )
        parser.add_argument(
            "--skip-pppoe",
            action="store_true",
            help="Skip full PPPoE stack / secret sync.",
        )
        parser.add_argument(
            "--skip-hotspot",
            action="store_true",
            help="Skip Hotspot captive portal repair.",
        )
        parser.add_argument(
            "--sync-secrets",
            action="store_true",
            help=(
                "Also rewrite every /ppp/secret (can briefly redial CPEs). "
                "Default is stack/captive only — subscription sweep owns access."
            ),
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Run even if the subscription sweep lock is held.",
        )

    def _write(self, stream, message, style=None):
        text = sweep_log_text(message)
        if style is not None:
            text = style(text)
        try:
            stream.write(text + "\n")
        except UnicodeEncodeError:
            stream.write(text.encode("ascii", errors="replace").decode("ascii") + "\n")

    def handle(self, *args, **options):
        from billing.models import Customer
        from core.models import MikroTikRouter

        dry_run = bool(options.get("dry_run"))
        skip_pppoe = bool(options.get("skip_pppoe"))
        skip_hotspot = bool(options.get("skip_hotspot"))
        sync_secrets = bool(options.get("sync_secrets"))
        force = bool(options.get("force"))
        org_id = int(options.get("organization") or 0)

        lock_held = False
        if not dry_run and not force:
            if not acquire_subscription_sweep_lock_with_retry(
                ttl_sec=900, attempts=8, wait_sec=5.0
            ):
                self._write(
                    self.stderr,
                    "Skipped: subscription sweep / expiry watch holds the fleet lock. "
                    "Retry in a minute, or pass --force (may race MikroTik writes).",
                    style=self.style.WARNING,
                )
                raise SystemExit(2)
            lock_held = True

        try:
            qs = (
                MikroTikRouter.objects.filter(
                    account_status=MikroTikRouter.AccountStatus.ACTIVE,
                )
                .exclude(host="")
                .select_related("organization")
                .order_by("organization_id", "id")
            )
            if org_id:
                qs = qs.filter(organization_id=org_id)

            routers = list(qs)
            if not routers:
                self._write(self.stdout, "No active MikroTik routers to sync.")
                return

            ok = errors = skipped = 0
            for router in routers:
                org = router.organization
                label = f"{getattr(router, 'name', '') or router.host} ({router.host})"
                if org is None:
                    skipped += 1
                    self._write(
                        self.stderr,
                        f"skip {label}: no organization",
                        style=self.style.WARNING,
                    )
                    continue

                compulsory = bool(getattr(org, "pppoe_compulsory", False))
                hotspot_on = bool(getattr(org, "hotspot_enabled", False))
                has_pppoe = Customer.objects.filter(
                    organization=org,
                    service_type=Customer.ServiceType.PPPOE,
                ).exclude(pppoe_username="").exists()
                has_hotspot = hotspot_on or Customer.objects.filter(
                    organization=org,
                    service_type=Customer.ServiceType.HOTSPOT,
                ).exclude(hotspot_mac="").exists()

                if dry_run:
                    parts = []
                    if not skip_pppoe and (compulsory or has_pppoe):
                        parts.append(
                            "pppoe-stack+secrets" if sync_secrets else "pppoe-stack"
                        )
                    else:
                        parts.append("expired-redirect")
                    if not skip_hotspot and (hotspot_on or has_hotspot or compulsory):
                        parts.append("hotspot")
                    self._write(
                        self.stdout,
                        f"DRY {label}: {', '.join(parts)}",
                    )
                    ok += 1
                    continue

                result = refresh_onboarded_router_config(
                    router,
                    skip_pppoe=skip_pppoe,
                    skip_hotspot=skip_hotspot,
                    reauthenticate=False,
                    # Default: do not rewrite secrets on deploy — avoids kicking
                    # every paid CPE. Access is owned by the subscription sweep.
                    sync_pppoe_secrets=bool(sync_secrets),
                )
                if result.get("ok"):
                    ok += 1
                    note = result.get("message") or "synced"
                    self._write(self.stdout, f"{label}: {note}")
                elif result.get("skipped"):
                    skipped += 1
                    self._write(
                        self.stdout,
                        f"{label}: {result.get('message') or 'skipped'}",
                    )
                else:
                    errors += 1
                    self._write(
                        self.stderr,
                        f"{label}: {result.get('error') or result.get('message') or 'failed'}",
                        style=self.style.WARNING,
                    )

            self._write(
                self.stdout,
                f"NAS config sync finished: {ok} ok, {errors} error(s), {skipped} skipped"
                + (" (dry-run)" if dry_run else "")
                + ("" if sync_secrets else " [secrets left to subscription sweep]"),
            )
            if errors and not dry_run:
                raise SystemExit(1)
        finally:
            if lock_held:
                release_subscription_sweep_lock()
