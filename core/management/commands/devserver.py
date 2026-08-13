"""Fast local development server with quicker autoreload cycles."""

from __future__ import annotations

from django.core.management.commands.runserver import Command as RunserverCommand


class Command(RunserverCommand):
    help = (
        "Start the development server with faster reloads "
        "(skips system checks unless --checks is passed). "
        "WireGuard peer sync and subscription access sweep start automatically "
        "from AppConfig (same as hosted WSGI / plain runserver)."
    )

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            "--checks",
            action="store_true",
            help="Run Django system checks on startup (slower reloads).",
        )
        parser.add_argument(
            "--no-sweep",
            action="store_true",
            help="Do not start the background subscription access sweep.",
        )
        parser.add_argument(
            "--no-tunnel-sync",
            action="store_true",
            help="Do not sync WireGuard peers on startup.",
        )

    def handle(self, *args, **options):
        if not options.pop("checks", False):
            options["skip_checks"] = True
        # Flags stay on sys.argv so core.boot.should_start_runtime_tasks sees them.
        options.pop("no_sweep", False)
        options.pop("no_tunnel_sync", False)
        super().handle(*args, **options)
