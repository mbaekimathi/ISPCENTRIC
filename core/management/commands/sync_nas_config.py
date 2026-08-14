"""Push critical NAS config to every active MikroTik after deploy."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from core.mikrotik_connect import (
    apply_pppoe_enforcement_on_router,
    repair_hotspot_captive_portal,
    repair_router_expired_captive_redirect,
    sweep_log_text,
)


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
            stream.write(text.encode("ascii", "replace").decode("ascii") + "\n")

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

            router_ok = True
            notes: list[str] = []

            # 1) Full PPPoE stack when the org uses PPPoE / compulsory mode.
            #    Always refresh expired redirect + blocked profile otherwise.
            if not skip_pppoe and (compulsory or has_pppoe):
                try:
                    result = apply_pppoe_enforcement_on_router(
                        router,
                        compulsory=compulsory,
                        hotspot_fallback=True if compulsory else False,
                    )
                except Exception as exc:  # noqa: BLE001
                    result = {"ok": False, "error": str(exc)}
                if result.get("ok"):
                    notes.append("pppoe ok")
                    if result.get("notes"):
                        notes.extend(
                            sweep_log_text(n) for n in list(result["notes"])[:4]
                        )
                else:
                    router_ok = False
                    errors += 1
                    self._write(
                        self.stderr,
                        f"{label}: pppoe {result.get('error') or 'failed'}",
                        style=self.style.WARNING,
                    )
            else:
                try:
                    result = repair_router_expired_captive_redirect(router)
                except Exception as exc:  # noqa: BLE001
                    result = {"ok": False, "error": str(exc)}
                if result.get("ok") or result.get("skipped"):
                    notes.append(result.get("message") or "expired-redirect ok")
                else:
                    router_ok = False
                    errors += 1
                    self._write(
                        self.stderr,
                        f"{label}: redirect {result.get('error') or 'failed'}",
                        style=self.style.WARNING,
                    )

            # 2) Hotspot captive pages / login.html when Hotspot is in use.
            #    Compulsory PPPoE already pushed Hotspot fallback above.
            need_hotspot = (
                not skip_hotspot
                and (hotspot_on or has_hotspot)
                and not (compulsory and not skip_pppoe)
            )
            if need_hotspot:
                try:
                    hs = repair_hotspot_captive_portal(
                        router, organization=org, attempts=2
                    )
                except Exception as exc:  # noqa: BLE001
                    hs = {"ok": False, "error": str(exc)}
                if hs.get("ok") or hs.get("skipped"):
                    notes.append("hotspot ok" if hs.get("ok") else "hotspot skipped")
                else:
                    router_ok = False
                    errors += 1
                    self._write(
                        self.stderr,
                        f"{label}: hotspot {hs.get('error') or 'failed'}",
                        style=self.style.WARNING,
                    )

            if router_ok:
                ok += 1
                self._write(
                    self.stdout,
                    f"{label}: " + ("; ".join(notes) if notes else "synced"),
                )

        self._write(
            self.stdout,
            f"NAS config sync finished: {ok} ok, {errors} error(s), {skipped} skipped"
            + (" (dry-run)" if dry_run else ""),
        )
        if errors and not dry_run:
            # Non-zero so deploy scripts can keep the pending-retry stamp.
            raise SystemExit(1)
