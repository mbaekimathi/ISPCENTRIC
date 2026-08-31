"""
Loop-test dashboard status probes (multi-host + classify) for flaky disconnects.

Examples:
  python manage.py diagnose_router_status_stability --dry-run
  python manage.py diagnose_router_status_stability --router=18 --loops 8 --settle 2
  python manage.py diagnose_router_status_stability --name \"Edge\"
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from core.connectivity_verification import routers_for_connectivity_check
from core.mikrotik_connect import sweep_log_text
from core.mikrotik_status_samples import run_router_status_stability_loop


class Command(BaseCommand):
    help = (
        "Loop-test MikroTik status collection (tunnel/LAN candidates + retry probes) "
        "to catch routers that falsely show Offline after onboard."
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
            help="Single status probe — no settle loops.",
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
            outcome = run_router_status_stability_loop(
                router,
                loops=loops,
                settle=settle,
                log_fn=lambda msg: self.stdout.write(sweep_log_text(msg)),
            )
            counts = outcome.get("status_counts") or {}
            status_bits = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            summary = (
                f"{router.name}: passed={outcome.get('passed')} "
                f"flaky={outcome.get('flaky')} "
                f"dominant={outcome.get('dominant_failure') or 'none'} "
                f"statuses[{status_bits}]"
            )
            if outcome.get("passed") and not outcome.get("flaky"):
                self.stdout.write(self.style.SUCCESS(sweep_log_text(summary)))
            elif outcome.get("passed") and outcome.get("flaky"):
                flaky += 1
                self.stdout.write(self.style.WARNING(sweep_log_text(f"FLAKY: {summary}")))
            else:
                failed += 1
                self.stdout.write(self.style.ERROR(sweep_log_text(f"FAIL: {summary}")))
                last = (outcome.get("attempts") or [{}])[-1]
                if last.get("error"):
                    self.stdout.write(sweep_log_text(f"  error: {last['error']}"))

        self.stdout.write(
            sweep_log_text(
                f"\nDone. routers={len(routers)} failed={failed} flaky={flaky} "
                f"loops={loops}"
            )
        )
        if failed:
            raise CommandError(
                f"{failed} router(s) never reached Connected across {loops} attempt(s)."
            )
