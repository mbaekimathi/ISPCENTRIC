"""Run smart-balance link health checks and client rebalance without the UI open."""

from django.core.management.base import BaseCommand

from core.boot import run_smart_balance_monitor_fleet


class Command(BaseCommand):
    help = (
        "Ping-check each smart-balance MikroTik, sideline slow ISP links, and "
        "rebalance heavy clients toward lighter uplinks. Schedule every minute "
        "so balance works even when nobody has the ports page open."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--organization",
            type=int,
            default=0,
            help="Limit to one organization id.",
        )
        parser.add_argument(
            "--router",
            type=int,
            default=0,
            help="Limit to one MikroTik router id.",
        )
        parser.add_argument(
            "--no-rebalance",
            action="store_true",
            help="Only run the ping monitor — do not move clients.",
        )
        parser.add_argument(
            "--workers",
            type=int,
            default=4,
            help="Routers to maintain in parallel (default 4).",
        )

    def handle(self, *args, **options):
        org_id = int(options.get("organization") or 0)
        router_id = int(options.get("router") or 0)
        rebalance = not bool(options.get("no_rebalance"))
        workers = max(1, int(options.get("workers") or 4))

        result = run_smart_balance_monitor_fleet(
            organization_id=org_id,
            router_id=router_id,
            rebalance=rebalance,
            workers=workers,
        )
        if result.get("skipped"):
            self.stdout.write(
                f"Smart balance monitor skipped ({result.get('reason') or 'locked'})."
            )
            return
        if not result.get("routers"):
            self.stdout.write("No active smart-balance routers matched.")
            return

        for line in result.get("messages") or []:
            level = line.get("level") or "info"
            text = line.get("text") or ""
            if level == "error":
                self.stdout.write(self.style.ERROR(text))
            elif level == "warn":
                self.stdout.write(self.style.WARNING(text))
            elif level == "success":
                self.stdout.write(self.style.SUCCESS(text))
            else:
                self.stdout.write(text)

        summary = (
            f"routers={result.get('routers')} ok={result.get('ok_count')} "
            f"sidelined_ports={result.get('slow_total')} "
            f"clients_moved={result.get('moved_total')}"
        )
        if result.get("errors"):
            self.stdout.write(self.style.WARNING(summary))
        else:
            self.stdout.write(self.style.SUCCESS(summary))
