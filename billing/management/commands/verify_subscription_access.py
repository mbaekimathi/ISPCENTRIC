"""Correction-loop verifier for paid clients that should be surfing."""

from __future__ import annotations

import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from billing.models import Customer
from billing.services import customer_receives_internet


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
        from core.mikrotik_connect import (
            cpe_renew_clear_is_pending,
            sync_customer_subscription_access,
        )
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
                f"router={getattr(customer.router, 'name', None) or '-'}"
            )
        )

        last: dict = {}
        for attempt in range(1, loops + 1):
            allowed_billing = customer_receives_internet(customer)
            pending_before = cpe_renew_clear_is_pending(customer)
            self.stdout.write(
                f"\n=== attempt {attempt}/{loops}  "
                f"billing_allows={allowed_billing}  "
                f"cpe_clear_pending={pending_before} ==="
            )

            if dry_run:
                last = {
                    "ok": allowed_billing and not pending_before,
                    "allowed": allowed_billing,
                    "cpe_renew_clear_pending": pending_before,
                    "message": "dry-run - no router push",
                    "portal": {},
                    "provision": {},
                }
            else:
                last = sync_customer_subscription_access(
                    customer,
                    provision=True,
                    reauthenticate=True,
                )
                customer.refresh_from_db()

            portal = last.get("portal") or {}
            provision = last.get("provision") or {}
            self.stdout.write(
                _safe_text(
                    f"sync ok={last.get('ok')}  allowed={last.get('allowed')}"
                )
            )
            self.stdout.write(_safe_text(f"message: {last.get('message')}"))
            if provision:
                self.stdout.write(
                    _safe_text(
                        "NAS: "
                        f"ok={provision.get('ok')}  "
                        f"profile={provision.get('profile')}  "
                        f"disabled={provision.get('disabled')}  "
                        f"kicked={provision.get('kicked')}  "
                        f"notes={provision.get('notes') or []}"
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
                f"pending_after={last.get('cpe_renew_clear_pending')}"
            )

            surfing_ok = self._surfing_restored(last, customer)
            if surfing_ok:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"\nPASS: {customer.account_number} should be surfing "
                        f"(attempt {attempt})."
                    )
                )
                return

            if attempt < loops and settle > 0 and not dry_run:
                self.stdout.write(f"settling {settle:.1f}s for CPE redial...")
                time.sleep(settle)
                customer = (
                    Customer.objects.select_related("plan", "router", "organization")
                    .get(pk=customer_id)
                )

        self.stdout.write(
            self.style.ERROR(
                f"\nFAIL: {customer.account_number} not fully restored after "
                f"{loops} attempt(s)."
            )
        )
        hint = (last.get("portal") or {}).get("error") or last.get("message") or ""
        if hint:
            self.stdout.write(self.style.WARNING(_safe_text(f"last status: {hint}")))
        if not customer_receives_internet(customer):
            raise CommandError(
                "Billing still denies internet - package period/status is not active."
            )
        raise CommandError(
            "NAS may be restored but CPE renew clear is still pending "
            "(CPE offline). Power-cycle the CPE, then re-run this command."
        )

    @staticmethod
    def _surfing_restored(result: dict, customer: Customer) -> bool:
        """True when billing + NAS agree and CPE renew is not trapping Wi-Fi."""
        if not result.get("allowed"):
            return False
        if not customer_receives_internet(customer):
            return False
        provision = result.get("provision") or {}
        if customer.service_type == Customer.ServiceType.PPPOE:
            if not provision.get("ok"):
                return False
            if provision.get("disabled"):
                return False
            if result.get("cpe_renew_clear_pending"):
                return False
            portal = result.get("portal") or {}
            # Skipped+pending means Wi-Fi may still be captive.
            if portal.get("skipped") and not portal.get("ok"):
                from core.mikrotik_connect import cpe_renew_clear_is_pending

                if cpe_renew_clear_is_pending(customer):
                    return False
            return bool(result.get("ok") or provision.get("ok"))
        # Hotspot: authorize must land (or be explicitly skipped offline).
        return bool(result.get("ok") and provision.get("ok"))
