"""
Loop-verify PPPoE and Hotspot accounts until NAS state matches billing policy.

Examples:
  python manage.py verify_access_accounts --dry-run
  python manage.py verify_access_accounts --service pppoe --organization 1
  python manage.py verify_access_accounts --service hotspot --customer 8 --loops 5
  python manage.py verify_access_accounts --dynamic-only
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from billing.access_verification import (
    billing_allows_surf,
    customers_for_access_verification,
    format_loop_summary,
    run_access_correction_loop,
)


def _safe_text(value) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("\u2011", "-")
        .replace("\u2013", "-")
        .replace("\u2014", "-")
        .replace("\u2212", "-")
        .replace("\u2026", "...")
    )


class Command(BaseCommand):
    help = (
        "Correction loops for PPPoE and Hotspot accounts: verify billing policy "
        "matches MikroTik (paid/active = surf allowed; unpaid/expired = blocked)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--service",
            choices=("all", "pppoe", "hotspot"),
            default="all",
            help="Which account type to check (default: all).",
        )
        parser.add_argument(
            "--organization",
            type=int,
            default=0,
            help="Limit to one organization id.",
        )
        parser.add_argument(
            "--customer",
            type=int,
            default=0,
            help="Verify one customer id only.",
        )
        parser.add_argument(
            "--loops",
            type=int,
            default=3,
            help="Max correction attempts per account (default 3).",
        )
        parser.add_argument(
            "--settle",
            type=float,
            default=1.5,
            help="Seconds between attempts (default 1.5).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Billing policy check only — no MikroTik push.",
        )
        parser.add_argument(
            "--dynamic-only",
            action="store_true",
            help="Only orgs with PPPoE compulsory + Hotspot enabled.",
        )

    def handle(self, *args, **options):
        org_id = int(options.get("organization") or 0)
        customer_id = int(options.get("customer") or 0)
        service = options.get("service") or "all"
        loops = max(1, int(options["loops"]))
        settle = max(0.0, float(options["settle"]))
        dry_run = bool(options["dry_run"])
        dynamic_only = bool(options["dynamic_only"])

        customers = customers_for_access_verification(
            organization_id=org_id,
            customer_id=customer_id,
            service=service,
            dynamic_only=dynamic_only,
        )
        if not customers:
            raise CommandError(
                "No matching PPPoE/Hotspot accounts found for the given filters."
            )

        self.stdout.write(
            _safe_text(
                f"Checking {len(customers)} account(s)  service={service}  "
                f"dry_run={dry_run}  loops={loops}"
            )
        )

        outcomes = []
        for customer in customers:
            org = customer.organization
            billing_ok = billing_allows_surf(customer)
            self.stdout.write(
                _safe_text(
                    f"\n--- [{customer.service_type}] {customer.account_number} "
                    f"org={getattr(org, 'name', '-')} ---"
                )
            )
            self.stdout.write(
                f"billing_allows_surf={billing_ok}  "
                f"package={customer.package_start} -> {customer.package_end}"
            )
            if customer.service_type == customer.ServiceType.PPPOE:
                self.stdout.write(
                    f"pppoe_username={customer.pppoe_username or '-'}"
                )
            else:
                self.stdout.write(f"hotspot_mac={customer.hotspot_mac or '-'}")

            outcome = run_access_correction_loop(
                customer,
                loops=loops,
                settle=settle,
                dry_run=dry_run,
                log_fn=lambda msg: self.stdout.write(_safe_text(msg)),
            )
            outcomes.append(outcome)

            if outcome.passed:
                note = ""
                last_details = (outcome.last_evaluation.get("details") or {})
                if last_details.get("cpe_clear_pending"):
                    note = " (CPE renew popup clears when CPE redials)"
                self.stdout.write(
                    self.style.SUCCESS(
                        _safe_text(f"PASS: {customer.account_number}{note}")
                    )
                )
            else:
                last = outcome.last_evaluation.get("sync_result") or {}
                hint = last.get("message") or "NAS state mismatch"
                self.stdout.write(
                    self.style.ERROR(
                        _safe_text(f"FAIL: {customer.account_number} — {hint}")
                    )
                )

        summary = format_loop_summary(outcomes)
        failed = sum(1 for o in outcomes if not o.passed)
        style = self.style.SUCCESS if failed == 0 else self.style.WARNING
        self.stdout.write(style(_safe_text(f"\n{summary}")))

        if failed:
            raise CommandError(
                f"{failed} account(s) still mismatch billing policy after "
                f"{loops} attempt(s) each."
            )
