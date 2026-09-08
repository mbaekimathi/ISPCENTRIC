"""Simulate or probe usage sampling accuracy for PPPoE / Hotspot clients."""

from __future__ import annotations

from django.core.management.base import BaseCommand
from django.utils import timezone


class Command(BaseCommand):
    help = (
        "Run a usage-accuracy loop: resolve each client's MikroTik, optionally "
        "simulate NAS sessions, sample, and report mismatches between expected "
        "and persisted CustomerUsageSample rows."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--organization",
            type=int,
            required=True,
            help="Organization id to audit.",
        )
        parser.add_argument(
            "--customer",
            type=int,
            default=0,
            help="Limit to one customer id (0 = all PPPoE/Hotspot).",
        )
        parser.add_argument(
            "--live",
            action="store_true",
            help="Probe real MikroTiks instead of injecting simulated sessions.",
        )
        parser.add_argument(
            "--loops",
            type=int,
            default=2,
            help="How many sample rounds to run (sim mode advances counters).",
        )
        parser.add_argument(
            "--assign-missing",
            action="store_true",
            help="Persist resolved router onto clients that have none assigned.",
        )

    def handle(self, *args, **options):
        from accounts.models import Organization
        from billing.models import Customer, CustomerUsageSample
        from billing.usage_samples import sample_organization_usage, usage_trend_payload
        from core.models import MikroTikRouter
        from core.views import customer_supports_live_usage, resolve_client_usage_router

        org = Organization.objects.filter(pk=int(options["organization"])).first()
        if org is None:
            self.stderr.write(self.style.ERROR("Organization not found."))
            return

        customer_id = int(options.get("customer") or 0)
        customers = list(
            Customer.objects.filter(organization=org)
            .exclude(service_type=Customer.ServiceType.STATIC)
            .select_related("router")
            .order_by("id")
        )
        if customer_id:
            customers = [c for c in customers if c.pk == customer_id]
            if not customers:
                self.stderr.write(self.style.ERROR(f"Customer {customer_id} not found."))
                return

        routers = list(
            MikroTikRouter.objects.filter(
                organization=org,
                account_status=MikroTikRouter.AccountStatus.ACTIVE,
            ).order_by("id")
        )
        self.stdout.write(
            f"Org={org.pk} clients={len(customers)} active_routers={len(routers)} "
            f"mode={'live' if options['live'] else 'simulate'} loops={options['loops']}"
        )

        resolution_rows = []
        for customer in customers:
            supports = customer_supports_live_usage(customer)
            resolved = resolve_client_usage_router(customer, org) if supports else None
            resolution_rows.append((customer, supports, resolved))
            assigned = customer.router_id
            resolved_id = resolved.pk if resolved else None
            flag = "OK"
            if supports and resolved is None:
                flag = "NO_ROUTER"
            elif supports and not assigned and resolved_id:
                flag = "RESOLVED_UNASSIGNED"
            self.stdout.write(
                f"  client={customer.pk} {customer.service_type} "
                f"user={(customer.pppoe_username or customer.hotspot_mac or '')!r} "
                f"assigned={assigned} resolved={resolved_id} [{flag}]"
            )
            if (
                options["assign_missing"]
                and supports
                and not assigned
                and resolved is not None
            ):
                customer.router = resolved
                customer.save(update_fields=["router"])
                self.stdout.write(
                    self.style.WARNING(
                        f"    assigned router {resolved.pk} ({resolved.name}) → client {customer.pk}"
                    )
                )

        if options["live"]:
            for i in range(max(1, int(options["loops"]))):
                result = sample_organization_usage(org, force=True)
                self.stdout.write(
                    f"live sample[{i + 1}] sampled={result.get('sampled')} "
                    f"skipped={result.get('skipped')}"
                )
            for customer, supports, resolved in resolution_rows:
                if not supports:
                    continue
                latest = (
                    CustomerUsageSample.objects.filter(customer=customer)
                    .order_by("-sampled_at")
                    .first()
                )
                age = (
                    (timezone.now() - latest.sampled_at).total_seconds()
                    if latest
                    else None
                )
                self.stdout.write(
                    f"  sample client={customer.pk} "
                    f"latest={'none' if latest is None else latest.sampled_at.isoformat()} "
                    f"age_s={age} active={getattr(latest, 'session_active', None)} "
                    f"bi={getattr(latest, 'bytes_in', None)} bo={getattr(latest, 'bytes_out', None)}"
                )
            return

        # Simulation: inject deterministic sessions and verify attribution + deltas.
        from unittest.mock import patch

        pppoe_clients = [
            c
            for c, supports, _ in resolution_rows
            if supports and c.service_type == Customer.ServiceType.PPPOE
        ]
        if not pppoe_clients:
            self.stdout.write("No PPPoE clients to simulate.")
            return
        if not routers:
            self.stderr.write(self.style.ERROR("No active routers — cannot simulate."))
            return

        base_in = 10_000
        base_out = 40_000
        loops = max(1, int(options["loops"]))
        expected_delta = 0

        def _sessions_for_round(round_idx: int):
            sessions = {}
            for idx, customer in enumerate(pppoe_clients):
                key = (customer.pppoe_username or "").strip().lower()
                if not key:
                    continue
                # Spread clients across routers when several exist.
                router = routers[idx % len(routers)]
                bi = base_in + idx * 1000 + round_idx * 500
                bo = base_out + idx * 2000 + round_idx * 1500
                sessions.setdefault(router.host, {})[key] = {
                    "session_active": True,
                    "bytes_in": bi,
                    "bytes_out": bo,
                    "uptime_raw": f"{round_idx + 1}m",
                    "address": f"10.{router.pk}.{idx}.10",
                }
            return sessions

        failures = 0
        for round_idx in range(loops):
            host_sessions = _sessions_for_round(round_idx)

            def _pppoe(host, *_a, **_k):
                return {
                    "ok": True,
                    "sessions": host_sessions.get(host, {}),
                    "error": "",
                }

            with patch(
                "core.mikrotik_connect.fetch_router_bulk_pppoe_usage", side_effect=_pppoe
            ), patch(
                "core.mikrotik_connect.fetch_router_bulk_hotspot_usage",
                return_value={"ok": True, "sessions": {}, "error": ""},
            ):
                from django.core.cache import cache

                # Bypass per-client write throttles between simulation rounds.
                cache.clear()
                result = sample_organization_usage(org, force=True)

            self.stdout.write(
                f"sim sample[{round_idx + 1}] sampled={result.get('sampled')}"
            )
            for idx, customer in enumerate(pppoe_clients):
                key = (customer.pppoe_username or "").strip().lower()
                router = routers[idx % len(routers)]
                expected = host_sessions.get(router.host, {}).get(key)
                if not expected:
                    continue
                latest = (
                    CustomerUsageSample.objects.filter(customer=customer)
                    .order_by("-sampled_at")
                    .first()
                )
                if latest is None:
                    failures += 1
                    self.stderr.write(
                        self.style.ERROR(f"  FAIL client={customer.pk}: no sample written")
                    )
                    continue
                ok = (
                    latest.session_active
                    and latest.bytes_in == expected["bytes_in"]
                    and latest.bytes_out == expected["bytes_out"]
                )
                if not ok:
                    failures += 1
                    self.stderr.write(
                        self.style.ERROR(
                            f"  FAIL client={customer.pk}: got bi={latest.bytes_in} "
                            f"bo={latest.bytes_out} expected {expected['bytes_in']}/"
                            f"{expected['bytes_out']}"
                        )
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"  OK client={customer.pk} router_host={router.host} "
                            f"bi={latest.bytes_in} bo={latest.bytes_out}"
                        )
                    )
            if round_idx > 0:
                expected_delta += 500 + 1500  # per-client per-round delta

        if loops >= 2:
            for customer in pppoe_clients:
                trends = usage_trend_payload(customer, hours=6, use_cache=False)
                used = int((trends.get("summary") or {}).get("data_used_bytes") or 0)
                # Each round after the first adds 2000 bytes for every client.
                want = (loops - 1) * 2000
                if used != want:
                    failures += 1
                    self.stderr.write(
                        self.style.ERROR(
                            f"  FAIL trend client={customer.pk}: data_used={used} want={want}"
                        )
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"  OK trend client={customer.pk} data_used_bytes={used}"
                        )
                    )

        if failures:
            self.stderr.write(self.style.ERROR(f"Completed with {failures} failure(s)."))
            raise SystemExit(1)
        self.stdout.write(self.style.SUCCESS("Usage accuracy simulation passed."))
