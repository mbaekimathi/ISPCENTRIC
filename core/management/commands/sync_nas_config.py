"""Push critical NAS config to every active MikroTik after deploy."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from core.mikrotik_connect import refresh_onboarded_router_config, sweep_log_text


class Command(BaseCommand):
    help = (
        "Re-push PPPoE stack / blocked profile, expired pay redirects, and "
        "Hotspot captive portal pages to every active MikroTik. Run after "
        "deploy so routers pick up code changes without a manual UI push."
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
        org_id = int(options.get("organization") or 0)

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
                    parts.append("pppoe-stack")
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
            + (" (dry-run)" if dry_run else ""),
        )
        if errors and not dry_run:
            # Non-zero so deploy scripts can keep the pending-retry stamp.
            raise SystemExit(1)
