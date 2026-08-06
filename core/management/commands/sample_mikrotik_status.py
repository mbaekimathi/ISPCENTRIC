"""Probe MikroTik routers and persist health samples for the performance trend."""

from django.core.management.base import BaseCommand

from core.mikrotik_status_samples import sample_all_organizations


class Command(BaseCommand):
    help = (
        "Probe every onboarded MikroTik and store health samples so the "
        "workspace performance trend (and outage history) keep updating even "
        "when nobody has /app/ open."
    )

    def handle(self, *args, **options):
        result = sample_all_organizations()
        self.stdout.write(
            self.style.SUCCESS(
                "Sampled organizations={organizations} routers={routers} "
                "samples_written={samples}".format(**result)
            )
        )
