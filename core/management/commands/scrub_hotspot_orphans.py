"""Scrub unauthorized Hotspot MAC users and drain pending pay-wall blocks."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from core.mikrotik_connect import scrub_hotspot_orphans_fleet, sweep_log_text


class Command(BaseCommand):
    help = (
        "Disable Hotspot MAC users that billing does not authorize, purge stale "
        "ok-list entries, and retry blocks queued while routers were offline."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--organization",
            type=int,
            default=0,
            help="Limit scrub to one organization id.",
        )
        parser.add_argument(
            "--workers",
            type=int,
            default=4,
            help="How many MikroTiks to scrub in parallel (default 4).",
        )

    def handle(self, *args, **options):
        org_id = int(options.get("organization") or 0)
        workers = int(options.get("workers") or 4)
        results = scrub_hotspot_orphans_fleet(
            organization_id=org_id,
            workers=workers,
        )

        blocked = sum(int(row.get("blocked") or 0) for row in results)
        pending_drained = 0
        errors = 0
        for row in results:
            pending_drained = max(
                pending_drained, int(row.get("pending_drained") or 0)
            )
            if row.get("error"):
                errors += 1
                self.stderr.write(
                    self.style.ERROR(
                        sweep_log_text(
                            f"Router {row.get('router_id')}: {row.get('error')}"
                        )
                    )
                )
            elif not row.get("skipped"):
                self.stdout.write(
                    sweep_log_text(row.get("message") or str(row))
                )

        summary = (
            f"Hotspot orphan scrub complete — blocked={blocked}, "
            f"pending_drained={pending_drained}, routers={len(results)}, errors={errors}"
        )
        self.stdout.write(self.style.SUCCESS(sweep_log_text(summary)))
