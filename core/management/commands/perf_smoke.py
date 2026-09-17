"""
Run hot-path performance smoke tests and print a short pass/fail summary.

Usage:
    python manage.py perf_smoke
"""

from django.core.management.base import BaseCommand
from django.test.utils import get_runner
from django.conf import settings


class Command(BaseCommand):
    help = "Run performance smoke tests for workspace, clients, billing, and NOC."

    def handle(self, *args, **options):
        TestRunner = get_runner(settings)
        runner = TestRunner(verbosity=1, interactive=False, keepdb=True)
        failures = runner.run_tests(["core.test_perf_smoke"])
        if failures:
            self.stderr.write(self.style.ERROR(f"perf_smoke FAILED ({failures})"))
            raise SystemExit(1)
        self.stdout.write(self.style.SUCCESS("perf_smoke OK"))
