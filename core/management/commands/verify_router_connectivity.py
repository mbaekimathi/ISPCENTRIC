"""
Loop-verify MikroTik NAS and client CPE communication.

Examples:
  python manage.py verify_router_connectivity --dry-run
  python manage.py verify_router_connectivity --organization=1
  python manage.py verify_router_connectivity --router=18 --loops 5 --repair
  python manage.py verify_router_connectivity --customer=5 --target all --deep
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from core.connectivity_verification import (
    evaluate_cpe_connectivity,
    evaluate_nas_connectivity,
    format_connectivity_summary,
    pppoe_customers_for_connectivity,
    routers_for_connectivity_check,
    run_cpe_connectivity_loop,
    run_nas_connectivity_loop,
)
from core.mikrotik_connect import sweep_log_text


class Command(BaseCommand):
    help = (
        "Correction loops for MikroTik NAS API and client CPE reachability. "
        "Run on the machine that can reach the router (LAN or WireGuard VPS)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--target",
            choices=("nas", "cpe", "all"),
            default="all",
            help="Check NAS only, CPE only, or both (default: all).",
        )
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
            "--customer",
            type=int,
            default=0,
            help="Check one PPPoE client's NAS + CPE path.",
        )
        parser.add_argument(
            "--loops",
            type=int,
            default=3,
            help="Max attempts per target (default 3).",
        )
        parser.add_argument(
            "--settle",
            type=float,
            default=1.5,
            help="Seconds between attempts (default 1.5).",
        )
        parser.add_argument(
            "--repair",
            action="store_true",
            help="Try NAS reconnect / CPE proxy setup between attempts.",
        )
        parser.add_argument(
            "--deep",
            action="store_true",
            help="For CPE checks, also test API login via NAS proxy (slower).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Single probe per target — no settle loops or repair.",
        )

    def handle(self, *args, **options):
        org_id = int(options.get("organization") or 0)
        router_id = int(options.get("router") or 0)
        customer_id = int(options.get("customer") or 0)
        target = (options.get("target") or "all").strip().lower()
        loops = 1 if options.get("dry_run") else max(1, int(options["loops"]))
        settle = 0.0 if options.get("dry_run") else max(0.0, float(options["settle"]))
        repair = bool(options.get("repair")) and not options.get("dry_run")
        deep = bool(options.get("deep"))

        if customer_id:
            from billing.models import Customer

            customer = Customer.objects.select_related("router", "organization").filter(
                pk=customer_id
            ).first()
            if customer is None:
                raise CommandError(f"Customer {customer_id} not found.")
            if target == "nas" and customer.router_id:
                router_id = customer.router_id
                customer_id = 0
            elif target == "cpe":
                pass
            else:
                target = "all"

        outcomes = []

        if target in {"nas", "all"}:
            routers = routers_for_connectivity_check(
                organization_id=org_id,
                router_id=router_id,
            )
            if not routers and target == "nas":
                raise CommandError("No active MikroTik routers matched the filters.")
            for router in routers:
                self.stdout.write(
                    sweep_log_text(
                        f"\n--- NAS {router.name} ({router.api_host or router.host}) "
                        f"org={getattr(router.organization, 'name', '-') or router.organization_id} ---"
                    )
                )
                if options.get("dry_run"):
                    evaluation = evaluate_nas_connectivity(router)
                    from core.connectivity_verification import LoopAttempt, LoopOutcome

                    outcome = LoopOutcome(target="nas", router=router)
                    outcome.last_evaluation = evaluation
                    outcome.passed = bool(evaluation.get("ok"))
                    outcome.attempts.append(
                        LoopAttempt(
                            attempt=1,
                            ok=outcome.passed,
                            reachable=bool(evaluation.get("reachable")),
                            api_ok=bool(evaluation.get("api_ok")),
                            error=evaluation.get("error") or "",
                            hint=evaluation.get("hint") or "",
                            details=evaluation.get("details") or {},
                        )
                    )
                    self.stdout.write(
                        sweep_log_text(
                            f"  reachable={evaluation.get('reachable')} "
                            f"api_ok={evaluation.get('api_ok')}"
                        )
                    )
                else:
                    outcome = run_nas_connectivity_loop(
                        router,
                        loops=loops,
                        settle=settle,
                        repair=repair,
                        log_fn=lambda msg: self.stdout.write(sweep_log_text(msg)),
                    )
                outcomes.append(outcome)
                self._report_outcome(outcome, label=router.name)

        if target in {"cpe", "all"}:
            customers = pppoe_customers_for_connectivity(
                organization_id=org_id,
                customer_id=customer_id,
                router_id=router_id if target == "cpe" and not customer_id else 0,
            )
            if not customers and target in {"cpe", "all"} and not router_id:
                if target == "cpe":
                    raise CommandError("No PPPoE clients matched the filters.")
            elif customers and target == "all" and router_id and not customer_id:
                customers = [c for c in customers if c.router_id == router_id]
            for customer in customers:
                self.stdout.write(
                    sweep_log_text(
                        f"\n--- CPE {customer.account_number} "
                        f"({customer.full_name}) pppoe={customer.pppoe_username} ---"
                    )
                )
                if options.get("dry_run"):
                    evaluation = evaluate_cpe_connectivity(customer, deep=deep)
                    from core.connectivity_verification import LoopOutcome

                    outcome = LoopOutcome(target="cpe", customer=customer)
                    outcome.last_evaluation = evaluation
                    outcome.passed = bool(
                        evaluation.get("ok")
                        and (
                            evaluation.get("skipped")
                            or evaluation.get("cpe_ok")
                            or evaluation.get("session_active")
                        )
                    )
                    self.stdout.write(
                        sweep_log_text(
                            f"  nas_ok={evaluation.get('nas_ok')} "
                            f"session_active={evaluation.get('session_active')} "
                            f"cpe_ok={evaluation.get('cpe_ok')}"
                        )
                    )
                    outcomes.append(outcome)
                else:
                    outcome = run_cpe_connectivity_loop(
                        customer,
                        loops=loops,
                        settle=settle,
                        deep=deep,
                        repair=repair,
                        log_fn=lambda msg: self.stdout.write(sweep_log_text(msg)),
                    )
                    outcomes.append(outcome)
                self._report_outcome(outcome, label=customer.account_number)

        if not outcomes:
            raise CommandError(
                "Nothing to check — pass --router, --customer, or --organization."
            )

        failed = sum(1 for o in outcomes if not o.passed)
        style = self.style.SUCCESS if failed == 0 else self.style.WARNING
        self.stdout.write(style(sweep_log_text(f"\n{format_connectivity_summary(outcomes)}")))

        if failed:
            raise CommandError(
                f"{failed} connectivity check(s) failed after {loops} attempt(s) each."
            )

    def _report_outcome(self, outcome, *, label: str) -> None:
        if outcome.passed:
            note = ""
            ev = outcome.last_evaluation or {}
            if ev.get("skipped") and ev.get("hint"):
                note = f" ({ev.get('hint')})"
            self.stdout.write(self.style.SUCCESS(sweep_log_text(f"PASS: {label}{note}")))
            return
        ev = outcome.last_evaluation or {}
        err = ev.get("error") or "connectivity failed"
        hint = ev.get("hint") or ""
        self.stdout.write(self.style.ERROR(sweep_log_text(f"FAIL: {label} — {err}")))
        if hint:
            self.stdout.write(self.style.WARNING(sweep_log_text(f"  hint: {hint}")))
