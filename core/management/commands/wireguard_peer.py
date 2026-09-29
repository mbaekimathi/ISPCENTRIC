"""
Provision the WireGuard tunnel that lets a hosted billing server reach routers.

    python manage.py wireguard_peer --server-keys      # once, on the VPS
    python manage.py wireguard_peer --new "Site name"  # before onboarding
    python manage.py wireguard_peer --all              # every onboarded router
    python manage.py wireguard_peer 9                  # one router
    python manage.py wireguard_peer --server-config KEY
"""

from django.core.management.base import BaseCommand, CommandError

from core import wireguard
from core.models import MikroTikRouter


class Command(BaseCommand):
    help = "Generate WireGuard tunnel configuration for MikroTik routers."

    def add_arguments(self, parser):
        parser.add_argument(
            "router_id",
            nargs="*",
            type=int,
            help="Router ids to provision. Omit with --all for every router.",
        )
        parser.add_argument(
            "--all",
            action="store_true",
            help="Provision every onboarded router.",
        )
        parser.add_argument(
            "--new",
            metavar="LABEL",
            help=(
                "Reserve a peer for a router that is not onboarded yet. Bring the "
                "tunnel up first, then onboard using the reserved address as host."
            ),
        )
        parser.add_argument(
            "--organization",
            type=int,
            metavar="ID",
            help="Organization id for --new (required on multi-tenant servers).",
        )
        parser.add_argument(
            "--rotate",
            action="store_true",
            help="Replace existing keys instead of reusing them.",
        )
        parser.add_argument(
            "--server-keys",
            action="store_true",
            help="Generate the VPS keypair and exit.",
        )
        parser.add_argument(
            "--sync-server",
            action="store_true",
            help="Apply every known peer to the local WireGuard interface (VPS).",
        )
        parser.add_argument(
            "--bootstrap-server",
            action="store_true",
            help=(
                "Write /etc/wireguard/wg0.conf from the VPS private key file and "
                "bring wg0 up (run as root on first deploy)."
            ),
        )
        parser.add_argument(
            "--verify-server-key",
            action="store_true",
            help=(
                "Compare WIREGUARD_SERVER_PUBLIC_KEY in .env with live wg0; exit 1 on mismatch."
            ),
        )
        parser.add_argument(
            "--private-key-file",
            metavar="PATH",
            default="",
            help="Private key file for --bootstrap-server (default: /etc/wireguard/ispcentric-server.key).",
        )
        parser.add_argument(
            "--server-config",
            metavar="PRIVATE_KEY",
            help="Print /etc/wireguard/wg0.conf containing all known peers.",
        )

    def handle(self, *args, **options):
        if options["server_keys"]:
            self._server_keys()
            return

        if options["verify_server_key"]:
            align = wireguard.server_public_key_alignment()
            configured = (align.get("configured") or "").strip()
            live = (align.get("live") or "").strip()
            script_key = (align.get("script_key") or "").strip()
            if align.get("error"):
                raise CommandError(align["error"])
            self.stdout.write(f"  .env : {configured}")
            self.stdout.write(f"  wg0  : {live or '(unreadable)'}")
            self.stdout.write(f"  script embeds : {script_key}")
            if align.get("mismatch"):
                raise CommandError(
                    align.get("fix_hint")
                    or "WIREGUARD_SERVER_PUBLIC_KEY does not match live wg0."
                )
            if not live:
                self.stdout.write(
                    self.style.WARNING(
                        "Could not read live wg0 — fix WIREGUARD_SYNC_COMMAND / sudoers."
                    )
                )
            else:
                self.stdout.write(self.style.SUCCESS("Server public key matches live wg0."))
            return

        if options["bootstrap_server"]:
            outcome = wireguard.bootstrap_server_wg0(
                private_key_file=(options.get("private_key_file") or "").strip(),
            )
            if not outcome.get("ok"):
                raise CommandError(outcome.get("error") or "WireGuard server bootstrap failed.")
            self.stdout.write(
                self.style.SUCCESS(
                    f"WireGuard server ready on {outcome.get('interface')} "
                    f"({outcome.get('conf_path')})."
                )
            )
            synced = int(outcome.get("synced") or 0)
            if synced:
                self.stdout.write(self.style.SUCCESS(f"Synced {synced} peer(s) to wg0."))
            peer_sync = outcome.get("peer_sync") or {}
            for err in peer_sync.get("errors") or []:
                self.stdout.write(self.style.WARNING(err))
            return

        if options["sync_server"]:
            outcome = wireguard.sync_all_server_peers()
            if outcome.get("skipped"):
                errors = [str(e).strip() for e in (outcome.get("errors") or []) if str(e).strip()]
                if errors:
                    raise CommandError(errors[0])
                reason = (outcome.get("reason") or "").strip()
                if reason == "sync_script_missing":
                    raise CommandError(
                        "WireGuard sync helper script is missing or not runnable. "
                        "On the VPS run as root: "
                        "sed -i 's/\\r$//' /opt/ispcentric/scripts/*.sh && "
                        "chmod +x /opt/ispcentric/scripts/*.sh"
                    )
                raise CommandError(
                    "Cannot update WireGuard peers from this process "
                    f"(not bound to {wireguard.server_address()} and "
                    "WIREGUARD_SYNC_COMMAND is unset)."
                )
            purged = int(outcome.get("reservations_purged") or 0)
            orphans = int(outcome.get("orphans_pruned") or 0)
            self.stdout.write(
                self.style.SUCCESS(
                    f"Synced {outcome.get('synced', 0)} peer(s) to "
                    f"{wireguard._wireguard_interface()}."
                    + (f" Purged {purged} stale reservation(s)." if purged else "")
                    + (f" Removed {orphans} orphan runtime peer(s)." if orphans else "")
                )
            )
            for err in outcome.get("errors") or []:
                self.stdout.write(self.style.WARNING(err))
            if outcome.get("errors"):
                raise CommandError("Some peers could not be synced.")
            return

        if options["server_config"]:
            self.stdout.write(wireguard.server_config(options["server_config"]))
            return

        if options["new"]:
            self._reserve(options["new"], organization_id=options.get("organization"))
        else:
            for router in self._select_routers(options):
                self._provision(router, rotate=options["rotate"])

        self.stdout.write("")
        self.stdout.write(
            self.style.WARNING(
                "Rebuild /etc/wireguard/wg0.conf on the VPS with --server-config, "
                "then run `systemctl restart wg-quick@wg0`."
            )
        )

    def _select_routers(self, options):
        ids = options["router_id"]
        if ids:
            routers = list(MikroTikRouter.objects.filter(pk__in=ids).order_by("id"))
            missing = set(ids) - {r.pk for r in routers}
            if missing:
                raise CommandError(
                    "No router with id " + ", ".join(str(m) for m in sorted(missing))
                )
            return routers
        if options["all"]:
            routers = list(MikroTikRouter.objects.order_by("id"))
            if not routers:
                raise CommandError(
                    "There are no onboarded routers. If this server cannot reach a "
                    'router yet, reserve its peer first with --new "Site name".'
                )
            return routers
        raise CommandError('Pass router ids, --all, or --new "Site name".')

    def _server_keys(self):
        live = wireguard._read_live_wg_interface_public_key()
        if live:
            self.stdout.write(self.style.SUCCESS("Live WireGuard interface public-key"))
            self.stdout.write(f"  {wireguard._wireguard_interface()} : {live}")
            self.stdout.write("")
            try:
                configured = wireguard._server_public_key()
            except ValueError:
                configured = ""
            if configured and configured != live:
                self.stdout.write(
                    self.style.WARNING(
                        "WIREGUARD_SERVER_PUBLIC_KEY in .env differs from live wg0 — "
                        "update .env or onboarding scripts may embed the wrong VPS key."
                    )
                )
                self.stdout.write(f"  .env currently : {configured}")
                self.stdout.write("")
        private_key, public_key = wireguard.generate_keypair()
        self.stdout.write(self.style.SUCCESS("New VPS WireGuard keypair (only when rotating wg0)"))
        self.stdout.write("")
        self.stdout.write(f"  private key : {private_key}")
        self.stdout.write(f"  public key  : {public_key}")
        self.stdout.write("")
        self.stdout.write("Put the public key in .env so router scripts can use it:")
        self.stdout.write(f"  WIREGUARD_SERVER_PUBLIC_KEY={public_key}")
        self.stdout.write("")
        self.stdout.write("Keep the private key on the VPS only (never commit it):")
        self.stdout.write(
            f"  echo '{private_key}' | sudo tee /etc/wireguard/ispcentric-server.key"
        )
        self.stdout.write("  sudo chmod 600 /etc/wireguard/ispcentric-server.key")
        self.stdout.write("  sudo python manage.py wireguard_peer --bootstrap-server")
        self.stdout.write("")
        self.stdout.write("Or build wg0.conf manually:")
        self.stdout.write(
            f"  python manage.py wireguard_peer --server-config '{private_key}'"
        )

    def _reserve(self, label: str, *, organization_id=None):
        from accounts.models import Organization

        organization = None
        if organization_id:
            organization = Organization.objects.filter(pk=organization_id).first()
            if organization is None:
                raise CommandError(f"No organization with id {organization_id}.")
        elif Organization.objects.count() == 1:
            organization = Organization.objects.first()
        else:
            raise CommandError(
                'Pass --organization ID with --new on servers with multiple ISP accounts.'
            )
        reservation, peer_sync = wireguard.reserve_peer(label, organization=organization)
        self._report(
            f"{reservation.label} (not onboarded yet) -> {reservation.address}",
            address=reservation.address,
            private_key=reservation.private_key,
            public_key=reservation.public_key,
            label=f"{reservation.label} (not onboarded yet)",
        )
        if peer_sync.get("ok"):
            self.stdout.write(
                self.style.SUCCESS(
                    f"VPS peer applied to {wireguard._wireguard_interface()}."
                )
            )
        elif not peer_sync.get("skipped"):
            self.stdout.write(
                self.style.WARNING(
                    "Could not apply peer on this machine: "
                    + (peer_sync.get("error") or "unknown error")
                )
            )
        self.stdout.write("")
        self.stdout.write(
            f"Once the tunnel is up, onboard this router in the app with host "
            f"{reservation.address}."
        )

    def _provision(self, router, *, rotate: bool):
        changed = []

        # A router reserved before onboarding was saved with the tunnel address
        # as its host. Adopt that peer instead of allocating a second one.
        if not rotate and wireguard.adopt_reservation_for_router(router):
            router.refresh_from_db()
            self._report(
                f"{router.name} (id {router.pk}) -> {router.vpn_address}",
                address=router.vpn_address,
                private_key=router.vpn_private_key,
                public_key=router.vpn_public_key,
                label=f"{router.name} (router id {router.pk})",
            )
            return

        if rotate or not router.vpn_private_key:
            private_key, public_key = wireguard.generate_keypair()
            router.vpn_private_key = private_key
            router.vpn_public_key = public_key
            changed += ["vpn_private_key", "vpn_public_key"]
        elif not router.vpn_public_key:
            router.vpn_public_key = wireguard.public_key_for(router.vpn_private_key)
            changed.append("vpn_public_key")

        if not router.vpn_address:
            router.vpn_address = wireguard.allocate_address()
            changed.append("vpn_address")

        if changed:
            router.save(update_fields=[*dict.fromkeys(changed), "updated_at"])

        self._report(
            f"{router.name} (id {router.pk}) -> {router.vpn_address}",
            address=router.vpn_address,
            private_key=router.vpn_private_key,
            public_key=router.vpn_public_key,
            label=f"{router.name} (router id {router.pk})",
        )

    def _report(self, heading, *, address, private_key, public_key, label):
        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(f"=== {heading} ==="))
        self.stdout.write("")
        self.stdout.write("--- paste into the MikroTik terminal ---")
        self.stdout.write(wireguard.routeros_script(address, private_key))
        self.stdout.write("")
        self.stdout.write("--- included in wg0.conf by --server-config ---")
        self.stdout.write(wireguard.server_peer_block(label, address, public_key))
