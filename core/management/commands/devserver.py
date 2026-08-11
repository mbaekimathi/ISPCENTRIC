"""Fast local development server with quicker autoreload cycles."""

from __future__ import annotations

import logging
import os
import threading
import time

from django.core.management.commands.runserver import Command as RunserverCommand

logger = logging.getLogger(__name__)

_sweep_thread_started = False


def _subscription_sweep_enabled() -> bool:
    return os.getenv("SUBSCRIPTION_SWEEP_ENABLED", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }


def _subscription_sweep_interval_sec() -> float:
    try:
        return max(60.0, float(os.getenv("SUBSCRIPTION_SWEEP_INTERVAL_SEC", "300")))
    except (TypeError, ValueError):
        return 300.0


def _run_subscription_sweep(*, label: str = "sweep") -> None:
    from io import StringIO

    from django.core.management import call_command

    out = StringIO()
    try:
        call_command("sync_subscription_access", stdout=out, stderr=out)
        text = out.getvalue().strip()
        if text:
            logger.info("subscription %s: %s", label, text.splitlines()[-1])
    except Exception:
        logger.exception("subscription %s failed", label)


def _start_subscription_sweep_loop() -> None:
    """Background loop: enforce PPPoE/Hotspot access from package dates."""
    global _sweep_thread_started
    if _sweep_thread_started or not _subscription_sweep_enabled():
        return
    _sweep_thread_started = True
    interval = _subscription_sweep_interval_sec()

    def _loop() -> None:
        _run_subscription_sweep(label="startup")
        while True:
            time.sleep(interval)
            _run_subscription_sweep(label="interval")

    threading.Thread(
        target=_loop,
        name="subscription-sweep",
        daemon=True,
    ).start()
    logger.info(
        "Subscription sweep armed (every %.0fs). Disable with SUBSCRIPTION_SWEEP_ENABLED=false.",
        interval,
    )


class Command(RunserverCommand):
    help = (
        "Start the development server with faster reloads "
        "(skips system checks unless --checks is passed). "
        "Also runs sync_subscription_access on startup and every 5 minutes."
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

    def handle(self, *args, **options):
        if not options.pop("checks", False):
            options["skip_checks"] = True
        if not options.pop("no_sweep", False):
            _start_subscription_sweep_loop()
        super().handle(*args, **options)
