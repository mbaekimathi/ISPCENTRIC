"""Correction-loop verifier for paid clients that should be surfing."""

from __future__ import annotations

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from billing.models import Customer
from billing.access_verification import (
    billing_allows_surf,
    evaluate_nas_policy,
    run_access_correction_loop,
)


def _safe_text(value) -> str:
    """ASCII-safe text for Windows consoles (cp1252) that choke on fancy dashes."""
    text = "" if value is None else str(value)
    return (
        text.replace("\u2011", "-")
        .replace("\u2013", "-")
        .replace("\u2014", "-")
        .replace("\u2212", "-")
        .replace("\u2026", "...")
        .replace("\u2018", "'")
        .replace("\u2019", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
    )


class Command(BaseCommand):
    help = (
        "Loop-sync a customer's subscription access until surfing is restored "
        "(or attempts are exhausted). Works the same on local and hosted - "
        "run it on the machine that can reach the MikroTik API."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--customer",
            type=int,
            required=True,
            help="Customer primary key (e.g. 7).",
        )
        parser.add_argument(
            "--loops",
            type=int,
            default=5,
            help="Max correction attempts (default 5).",
        )
        parser.add_argument(
            "--settle",
            type=float,
            default=2.0,
            help="Seconds to wait between attempts for CPE redial (default 2).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report status only — do not push to routers.",
        )

    def handle(self, *args, **options):
        from core.hotspot_portal import public_base_url

        customer_id = int(options["customer"])
        loops = max(1, int(options["loops"]))
        settle = max(0.0, float(options["settle"]))
        dry_run = bool(options["dry_run"])

        customer = (
            Customer.objects.select_related("plan", "router", "organization")
            .filter(pk=customer_id)
            .first()
        )
        if customer is None:
            raise CommandError(f"Customer {customer_id} not found.")

        hosted = bool(getattr(settings, "HOSTED", False))
        base = (public_base_url() or getattr(settings, "PUBLIC_BASE_URL", "") or "").rstrip(
            "/"
        )
        self.stdout.write(
            self.style.NOTICE(
                _safe_text(
                    f"env={'hosted' if hosted else 'local'}  "
                    f"PUBLIC_BASE_URL={base or '(auto/empty)'}  "
                    f"customer={customer.account_number}  "
                    f"service={customer.service_type}"
                )
            )
        )
        self.stdout.write(
            _safe_text(
                f"package {customer.package_start} -> {customer.package_end}  "
                f"status={customer.status}  "
                f"router={getattr(customer.router, 'name', None) or '-'}  "
                f"expect_surf={billing_allows_surf(customer)}"
            )
        )

        outcome = run_access_correction_loop(
            customer,
            loops=loops,
            settle=settle,
            dry_run=dry_run,
            log_fn=lambda msg: self.stdout.write(
                _safe_text(
                    msg.replace("billing_ok=", "billing_allows=")
                )
            ),
        )

        for attempt in outcome.attempts:
            sync_result = attempt.sync_result or {}
            portal = sync_result.get("portal") or {}
            provision = sync_result.get("provision") or {}
            self.stdout.write(
                _safe_text(
                    f"sync ok={sync_result.get('ok')}  "
                    f"allowed={sync_result.get('allowed')}"
                )
            )
            if sync_result.get("message"):
                self.stdout.write(_safe_text(f"message: {sync_result.get('message')}"))
            if provision:
                self.stdout.write(
                    _safe_text(
                        "NAS: "
                        f"ok={provision.get('ok')}  "
                        f"profile={provision.get('profile')}  "
                        f"disabled={provision.get('disabled')}  "
                        f"kicked={provision.get('kicked')}"
                    )
                )
            if portal:
                self.stdout.write(
                    _safe_text(
                        "CPE: "
                        f"ok={portal.get('ok')}  "
                        f"skipped={portal.get('skipped')}  "
                        f"error={portal.get('error') or '-'}"
                    )
                )
            self.stdout.write(
                f"pending_after={sync_result.get('cpe_renew_clear_pending')}"
            )

        if outcome.passed:
            expect = "surfing" if billing_allows_surf(customer) else "blocked"
            self.stdout.write(
                self.style.SUCCESS(
                    f"\nPASS: {customer.account_number} access {expect} "
                    f"(attempt {len(outcome.attempts)})."
                )
            )
            return

        last = outcome.last_evaluation.get("sync_result") or {}
        self.stdout.write(
            self.style.ERROR(
                f"\nFAIL: {customer.account_number} not fully enforced after "
                f"{len(outcome.attempts)} attempt(s)."
            )
        )
        hint = (last.get("portal") or {}).get("error") or last.get("message") or ""
        if hint:
            self.stdout.write(self.style.WARNING(_safe_text(f"last status: {hint}")))
        if not billing_allows_surf(customer):
            raise CommandError(
                "Billing denies internet but NAS is not fully blocking this account."
            )
        raise CommandError(
            "Billing allows internet but NAS restore is incomplete "
            "(CPE offline or renew popup pending)."
        )

    @staticmethod
    def _surfing_restored(result: dict, customer: Customer) -> bool:
        """Legacy helper — prefer evaluate_nas_policy()."""
        return bool(evaluate_nas_policy(customer, result).get("policy_match"))
