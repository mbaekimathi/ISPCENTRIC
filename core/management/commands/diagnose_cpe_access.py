"""
Layered remote CPE access loops (Open client router path).

Probes NAS → PPPoE/session → ping → web ports via NAS proxy → API login.

Examples:
  python manage.py diagnose_cpe_access --customer=5 --loops 3
  python manage.py diagnose_cpe_access --router=18 --loops 2 --settle 2
  python manage.py diagnose_cpe_access --dry-run --organization=1
  python manage.py diagnose_cpe_access --customer=5 --web-only
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from core.connectivity_verification import (
    evaluate_layered_cpe_access,
    format_cpe_access_loop_summary,
    pppoe_customers_for_connectivity,
    run_layered_cpe_access_loop,
)
from core.mikrotik_connect import sweep_log_text
from billing.models import Customer


class Command(BaseCommand):
    help = (
        "Loop-test remote client-router access layers used by Open client router "
        "(NAS, session, ping, web ports, API)."
    )

    def add_arguments(self, parser):
        parser.add_argument("--organization", type=int, default=0)
        parser.add_argument("--router", type=int, default=0)
        parser.add_argument("--customer", type=int, default=0)
        parser.add_argument(
            "--loops",
            type=int,
            default=3,
            help="Attempts per client (default 3).",
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
            default=8.0,
            help="Per-probe timeout seconds (default 8).",
        )
        parser.add_argument(
            "--web-only",
            action="store_true",
            help="Skip CPE API login — only prove web management ports.",
        )
        parser.add_argument(
            "--no-enable",
            action="store_true",
            help="Do not auto-enable CPE www/API via SSH.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Single layered probe — no settle loops.",
        )
        parser.add_argument(
            "--include-offline",
            action="store_true",
            help="Also check clients with no live PPPoE (default skips after first offline).",
        )

    def handle(self, *args, **options):
        org_id = int(options.get("organization") or 0)
        router_id = int(options.get("router") or 0)
        customer_id = int(options.get("customer") or 0)
        loops = 1 if options.get("dry_run") else max(1, int(options["loops"]))
        settle = 0.0 if options.get("dry_run") else max(0.0, float(options["settle"]))
        timeout = max(2.0, float(options["timeout"]))
        try_api = not bool(options.get("web_only"))
        auto_enable = not bool(options.get("no_enable"))

        if customer_id:
            customers = list(
                Customer.objects.select_related("router", "organization").filter(
                    pk=customer_id
                )
            )
            if not customers:
                raise CommandError(f"Customer {customer_id} not found.")
        else:
            customers = pppoe_customers_for_connectivity(
                organization_id=org_id,
                router_id=router_id,
            )
            # Also include static clients on the same NAS when filtering by router/org.
            static_qs = Customer.objects.filter(
                service_type=Customer.ServiceType.STATIC,
            ).exclude(cpe_ip="").exclude(cpe_ip__isnull=True).select_related(
                "router", "organization"
            )
            if router_id:
                static_qs = static_qs.filter(router_id=router_id)
            elif org_id:
                static_qs = static_qs.filter(organization_id=org_id)
            if router_id or org_id:
                seen = {c.pk for c in customers}
                for c in static_qs:
                    if c.pk not in seen:
                        customers.append(c)

        if not customers:
            raise CommandError(
                "No clients matched — pass --customer, --router, or --organization."
            )

        failed = 0
        flaky = 0
        offline = 0

        for customer in customers:
            router = customer.router
            self.stdout.write(
                sweep_log_text(
                    f"\n=== {customer.account_number} ({customer.full_name}) "
                    f"type={customer.service_type} "
                    f"nas={getattr(router, 'name', None) or '-'} ==="
                )
            )

            if options.get("dry_run"):
                evaluation = evaluate_layered_cpe_access(
                    customer,
                    timeout=timeout,
                    try_api=try_api,
                    auto_enable=auto_enable,
                )
                layers = (evaluation.get("details") or {}).get("layers") or {}
                failure = evaluation.get("failure_class") or "-"
                self.stdout.write(
                    sweep_log_text(
                        f"  fail={failure} nas={layers.get('nas_ok')} "
                        f"session={layers.get('session_active')} "
                        f"ping={layers.get('ping_ok')} web={layers.get('web_ok')} "
                        f"api={layers.get('api_ok')} "
                        f"host={(evaluation.get('details') or {}).get('cpe_host') or '-'} "
                        f"port={(evaluation.get('details') or {}).get('web_port') or '-'}"
                    )
                )
                if evaluation.get("error"):
                    self.stdout.write(sweep_log_text(f"  error: {evaluation['error']}"))
                if evaluation.get("hint"):
                    self.stdout.write(
                        self.style.WARNING(sweep_log_text(f"  hint: {evaluation['hint']}"))
                    )
                if evaluation.get("ok") and not evaluation.get("skipped"):
                    self.stdout.write(
                        self.style.SUCCESS(
                            sweep_log_text(f"PASS: {customer.account_number}")
                        )
                    )
                elif failure == "offline":
                    offline += 1
                    self.stdout.write(
                        self.style.WARNING(
                            sweep_log_text(f"OFFLINE: {customer.account_number}")
                        )
                    )
                else:
                    failed += 1
                    self.stdout.write(
                        self.style.ERROR(
                            sweep_log_text(f"FAIL: {customer.account_number} — {failure}")
                        )
                    )
                continue

            outcome = run_layered_cpe_access_loop(
                customer,
                loops=loops,
                settle=settle,
                timeout=timeout,
                try_api=try_api,
                auto_enable=auto_enable,
                log_fn=lambda msg: self.stdout.write(sweep_log_text(msg)),
            )
            summary = format_cpe_access_loop_summary(outcome)
            dominant = outcome.dominant_failure or ""
            if outcome.passed and not outcome.flaky:
                self.stdout.write(self.style.SUCCESS(sweep_log_text(summary)))
            elif outcome.passed and outcome.flaky:
                flaky += 1
                self.stdout.write(self.style.WARNING(sweep_log_text(f"FLAKY: {summary}")))
                self._print_fix(outcome)
            elif dominant == "offline":
                offline += 1
                self.stdout.write(self.style.WARNING(sweep_log_text(f"OFFLINE: {summary}")))
                self._print_fix(outcome)
            else:
                failed += 1
                self.stdout.write(self.style.ERROR(sweep_log_text(f"FAIL: {summary}")))
                self._print_fix(outcome)

        self.stdout.write(
            sweep_log_text(
                f"\nDone. clients={len(customers)} failed={failed} "
                f"flaky={flaky} offline={offline} loops={loops}"
            )
        )
        if failed:
            raise CommandError(
                f"{failed} client(s) cannot be remotely managed "
                f"(web ports / credentials / NAS)."
            )

    def _print_fix(self, outcome) -> None:
        ev = outcome.last_evaluation or {}
        if ev.get("error"):
            self.stdout.write(sweep_log_text(f"  error: {ev['error']}"))
        if ev.get("hint"):
            self.stdout.write(self.style.WARNING(sweep_log_text(f"  hint: {ev['hint']}")))
        rates = outcome.layer_pass_rates or {}
        self.stdout.write(
            sweep_log_text(
                "  layer pass rates: "
                f"nas={rates.get('nas_ok', 0)}% "
                f"session={rates.get('session_active', 0)}% "
                f"ping={rates.get('ping_ok', 0)}% "
                f"web={rates.get('web_ok', 0)}% "
                f"api={rates.get('api_ok', 0)}%"
            )
        )
