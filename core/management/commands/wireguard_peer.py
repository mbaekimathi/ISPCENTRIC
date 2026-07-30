"""
Provision the WireGuard tunnel that lets a hosted billing server reach routers.

    python manage.py wireguard_peer --server-keys   # once, on the VPS
    python manage.py wireguard_peer --all           # keys for every router
    python manage.py wireguard_peer 9               # one router
    python manage.py wireguard_peer --server-config # rebuild wg0.conf
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
            help="Provision every router that has no tunnel address yet.",
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
            "--server-config",
            metavar="PRIVATE_KEY",
            help="Print /etc/wireguard/wg0.conf containing all provisioned peers.",
        )

    def handle(self, *args, **options):
        if options["server_keys"]:
            self._server_keys()
            return

        if options["server_config"]:
            self.stdout.write(wireguard.server_config(options["server_config"]))
            return

        routers = self._select_routers(options)
        for router in routers:
            self._provision(router, rotate=options["rotate"])

        self.stdout.write("")
        self.stdout.write(
            self.style.WARNING(
                "Add the peer blocks above to /etc/wireguard/wg0.conf on the VPS "
                "(or regenerate it with --server-config), then run "
                "`systemctl restart wg-quick@wg0`."
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
                raise CommandError("There are no routers to provision.")
            return routers
        raise CommandError("Pass one or more router ids, or --all.")

    def _server_keys(self):
        private_key, public_key = wireguard.generate_keypair()
        self.stdout.write(self.style.SUCCESS("VPS WireGuard keypair"))
        self.stdout.write("")
        self.stdout.write(f"  private key : {private_key}")
        self.stdout.write(f"  public key  : {public_key}")
        self.stdout.write("")
        self.stdout.write("Put the public key in .env so router scripts can use it:")
        self.stdout.write(f"  WIREGUARD_SERVER_PUBLIC_KEY={public_key}")
        self.stdout.write("")
        self.stdout.write("Keep the private key for /etc/wireguard/wg0.conf only:")
        self.stdout.write(
            f"  python manage.py wireguard_peer --server-config '{private_key}'"
        )

    def _provision(self, router, *, rotate: bool):
        changed = []
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
            router.save(update_fields=[*changed, "updated_at"])

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS(
                f"=== {router.name} (id {router.pk}) -> {router.vpn_address} ==="
            )
        )
        self.stdout.write("")
        self.stdout.write("--- paste into the MikroTik terminal ---")
        self.stdout.write(wireguard.routeros_script(router))
        self.stdout.write("")
        self.stdout.write("--- add to /etc/wireguard/wg0.conf on the VPS ---")
        self.stdout.write(wireguard.server_peer_block(router))
