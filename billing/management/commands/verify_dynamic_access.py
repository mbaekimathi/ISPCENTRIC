"""Correction-loop verifier for dynamic dual-path access (PPPoE + Hotspot)."""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from billing.access_verification import (
    billing_allows_surf,
    customers_for_access_verification,
    format_loop_summary,
    run_access_correction_loop,
)
from billing.management.commands.verify_access_accounts import _safe_text


class Command(BaseCommand):
    help = (
        "Loop-sync PPPoE and Hotspot clients in dynamic-access organizations "
        "until each customer's NAS state matches billing policy."
    )

    def add_arguments(self, parser):
        parser.add_argument("--organization", type=int, default=0)
        parser.add_argument("--customer", type=int, default=0)
        parser.add_argument("--loops", type=int, default=3)
        parser.add_argument("--settle", type=float, default=1.5)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        org_id = int(options.get("organization") or 0)
        customer_id = int(options.get("customer") or 0)
        loops = max(1, int(options["loops"]))
        settle = max(0.0, float(options["settle"]))
        dry_run = bool(options["dry_run"])

        customers = customers_for_access_verification(
            organization_id=org_id,
            customer_id=customer_id,
            service="all",
            dynamic_only=not bool(customer_id),
        )
        if not customers:
            raise CommandError("No matching PPPoE/Hotspot customers found.")

        outcomes = []
        for customer in customers:
            org = customer.organization
            self.stdout.write(
                _safe_text(
                    f"\n--- {customer.account_number} ({customer.service_type}) "
                    f"org={getattr(org, 'name', '-')} ---"
                )
            )
            self.stdout.write(
                f"billing_allows={billing_allows_surf(customer)}  "
                f"package={customer.package_start} -> {customer.package_end}"
            )
            outcome = run_access_correction_loop(
                customer,
                loops=loops,
                settle=settle,
                dry_run=dry_run,
                log_fn=lambda msg: self.stdout.write(_safe_text(msg)),
            )
            outcomes.append(outcome)
            if outcome.passed:
                self.stdout.write(
                    self.style.SUCCESS(
                        _safe_text(f"PASS: {customer.account_number}")
                    )
                )
            else:
                last = outcome.last_evaluation.get("sync_result") or {}
                self.stdout.write(
                    self.style.ERROR(
                        _safe_text(
                            f"FAIL: {customer.account_number} — "
                            f"{last.get('message') or 'NAS mismatch'}"
                        )
                    )
                )

        failed = sum(1 for o in outcomes if not o.passed)
        style = self.style.SUCCESS if failed == 0 else self.style.WARNING
        self.stdout.write(style(_safe_text(f"\n{format_loop_summary(outcomes)}")))
        if failed:
            raise CommandError(
                f"{failed} customer(s) still mismatch dynamic access policy."
            )
