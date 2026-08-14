"""
Layered MikroTik health loops for \"Why it dropped\" diagnosis.

Probes ping, TCP 8728/8291/80/8080, and API login repeatedly so flaky
tunnel / firewall / credential failures are visible as pass rates.

Examples:
  python manage.py diagnose_router_health --dry-run
  python manage.py diagnose_router_health --router=18 --loops 8 --settle 2
  python manage.py diagnose_router_health --organization=1 --loops 5
  python manage.py diagnose_router_health --name \"KILY\"
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from core.connectivity_verification import (
    evaluate_layered_health,
    format_layered_loop_summary,
    routers_for_connectivity_check,
    run_layered_health_loop,
)
from core.mikrotik_connect import sweep_log_text


class Command(BaseCommand):
    help = (
        "Loop-test MikroTik health layers (ping, :8728, :80, API auth) to "
        "explain Offline / Limited / Auth failed drops."
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
            help="Check one MikroTik NAS by id.",
        )
        parser.add_argument(
            "--name",
            default="",
            help="Case-insensitive substring match on router name.",
        )
        parser.add_argument(
            "--loops",
            type=int,
            default=5,
            help="Probe attempts per router (default 5).",
        )
        parser.add_argument(
            "--settle",
            type=float,
            default=2.0,
            help="Seconds between attempts (default 2).",
        )
        parser.add_argument(
            "--timeout",
            type=float,
            default=2.0,
            help="Per-layer socket/login timeout seconds (default 2).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Single layered probe — no settle loops.",
        )

    def handle(self, *args, **options):
        org_id = int(options.get("organization") or 0)
        router_id = int(options.get("router") or 0)
        name = (options.get("name") or "").strip()
        loops = 1 if options.get("dry_run") else max(1, int(options["loops"]))
        settle = 0.0 if options.get("dry_run") else max(0.0, float(options["settle"]))
        timeout = max(0.5, float(options["timeout"]))

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
            if options.get("dry_run"):
                evaluation = evaluate_layered_health(router, timeout=timeout)
                layers = (evaluation.get("details") or {}).get("layers") or {}
                self.stdout.write(
                    sweep_log_text(
                        f"  status={evaluation.get('status')} "
                        f"score={evaluation.get('score')}% "
                        f"fail={evaluation.get('failing_layer') or '-'} "
                        f"ping={layers.get('ping')} "
                        f"api8728={layers.get('tcp_8728')} "
                        f"http80={layers.get('tcp_80')} "
                        f"auth={layers.get('api_auth')}"
                    )
                )
                if evaluation.get("error"):
                    self.stdout.write(sweep_log_text(f"  error: {evaluation['error']}"))
                if evaluation.get("hint"):
                    self.stdout.write(
                        self.style.WARNING(sweep_log_text(f"  hint: {evaluation['hint']}"))
                    )
                if evaluation.get("ok"):
                    self.stdout.write(self.style.SUCCESS(sweep_log_text(f"PASS: {router.name}")))
                else:
                    failed += 1
                    self.stdout.write(
                        self.style.ERROR(
                            sweep_log_text(
                                f"FAIL: {router.name} — {evaluation.get('reason') or evaluation.get('error')}"
                            )
                        )
                    )
                continue

            outcome = run_layered_health_loop(
                router,
                loops=loops,
                settle=settle,
                timeout=timeout,
                log_fn=lambda msg: self.stdout.write(sweep_log_text(msg)),
            )
            summary = format_layered_loop_summary(outcome)
            if outcome.passed and not outcome.flaky:
                self.stdout.write(self.style.SUCCESS(sweep_log_text(summary)))
            elif outcome.passed and outcome.flaky:
                flaky += 1
                self.stdout.write(self.style.WARNING(sweep_log_text(f"FLAKY: {summary}")))
                self._print_fix(outcome)
            else:
                failed += 1
                self.stdout.write(self.style.ERROR(sweep_log_text(f"FAIL: {summary}")))
                self._print_fix(outcome)

        self.stdout.write(
            sweep_log_text(
                f"\nDone. routers={len(routers)} failed={failed} flaky={flaky} "
                f"loops={loops} timeout={timeout}s"
            )
        )
        if failed:
            raise CommandError(
                f"{failed} router(s) never reached Connected across {loops} attempt(s)."
            )

    def _print_fix(self, outcome) -> None:
        ev = outcome.last_evaluation or {}
        if ev.get("reason"):
            self.stdout.write(sweep_log_text(f"  reason: {ev['reason']}"))
        if ev.get("hint"):
            self.stdout.write(self.style.WARNING(sweep_log_text(f"  hint: {ev['hint']}")))
        rates = outcome.layer_pass_rates or {}
        self.stdout.write(
            sweep_log_text(
                "  layer pass rates: "
                f"ping={rates.get('ping', 0)}% "
                f"8728={rates.get('tcp_8728', 0)}% "
                f"8291={rates.get('tcp_8291', 0)}% "
                f"80={rates.get('tcp_80', 0)}% "
                f"auth={rates.get('api_auth', 0)}%"
            )
        )
