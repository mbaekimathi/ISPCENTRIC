"""
Loop-test MikroTik live telemetry (WAN speeds, CPU, multi-host dial).

Examples:
  python manage.py diagnose_mikrotik_live --dry-run
  python manage.py diagnose_mikrotik_live --router=1 --loops 8 --settle 2
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from core.connectivity_verification import routers_for_connectivity_check
from core.mikrotik_connect import run_mikrotik_live_stability_loop, sweep_log_text


class Command(BaseCommand):
    help = (
        "Loop-test MikroTik live snapshot reads (LAN/tunnel fallback + WAN speeds) "
        "to catch flaky or zero live telemetry."
    )

    def add_arguments(self, parser):
        parser.add_argument("--organization", type=int, default=0)
        parser.add_argument("--router", type=int, default=0)
        parser.add_argument("--name", default="")
        parser.add_argument("--loops", type=int, default=5)
        parser.add_argument("--settle", type=float, default=2.0)
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Single live read — no settle loops.",
        )

    def handle(self, *args, **options):
        org_id = int(options.get("organization") or 0)
        router_id = int(options.get("router") or 0)
        name = (options.get("name") or "").strip()
        loops = 1 if options.get("dry_run") else max(1, int(options["loops"]))
        settle = 0.0 if options.get("dry_run") else max(0.0, float(options["settle"]))

        routers = routers_for_connectivity_check(
            organization_id=org_id,
            router_id=router_id,
        )
        if name:
            needle = name.lower()
            routers = [r for r in routers if needle in (r.name or "").lower()]

        if not routers:
            raise CommandError(
                "No active MikroTik routers matched — pass --router, --name, "
                "or --organization."
            )

        failed = 0
        flaky = 0
        for router in routers:
            host = router.api_host or router.host
            self.stdout.write(
                sweep_log_text(
                    f"\n=== {router.name} ({host}) "
                    f"org={getattr(router.organization, 'name', '-') or router.organization_id} ==="
                )
            )
            outcome = run_mikrotik_live_stability_loop(
                router,
                loops=loops,
                settle=settle,
                log_fn=lambda msg: self.stdout.write(sweep_log_text(msg)),
            )
            summary = (
                f"{router.name}: passed={outcome.get('passed')} "
                f"flaky={outcome.get('flaky')} failures={outcome.get('failures')} "
                f"zero_speeds={outcome.get('zero_speeds')} "
                f"hosts={','.join(outcome.get('hosts_seen') or []) or '-'}"
            )
            self.stdout.write(sweep_log_text(summary))
            if not outcome.get("passed"):
                failed += 1
            if outcome.get("flaky"):
                flaky += 1

        if failed:
            raise CommandError(
                f"{failed} router(s) failed live loop ({flaky} flaky). "
                "Check LAN/tunnel reachability and WAN interface assignment."
            )
