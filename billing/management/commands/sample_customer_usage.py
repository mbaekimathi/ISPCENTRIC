"""Snapshot PPPoE/Hotspot usage for every organization (no page visit required)."""

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = (
        "Probe every organization's MikroTiks and persist CustomerUsageSample "
        "rows so /app/clients/usage/ and per-client usage analysis keep history "
        "even when nobody has those pages open."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--organization",
            type=int,
            default=0,
            help="Limit sampling to one organization id (0 = all).",
        )

    def handle(self, *args, **options):
        org_id = int(options.get("organization") or 0)
        if org_id:
            from accounts.models import Organization
            from billing.usage_samples import sample_organization_usage
            from core.boot import _mark_usage_sampling_heartbeat

            org = Organization.objects.filter(pk=org_id).first()
            if org is None:
                self.stderr.write(self.style.ERROR(f"Organization {org_id} not found."))
                return
            result = sample_organization_usage(org, force=True)
            _mark_usage_sampling_heartbeat()
            self.stdout.write(
                self.style.SUCCESS(
                    "Sampled organization={org} sampled={sampled} skipped={skipped}".format(
                        org=org_id,
                        sampled=int((result or {}).get("sampled") or 0),
                        skipped=bool((result or {}).get("skipped")),
                    )
                )
            )
            return

        from core.boot import run_usage_sample_all_orgs

        result = run_usage_sample_all_orgs(label="command")
        style = self.style.WARNING if result.get("skipped") else self.style.SUCCESS
        self.stdout.write(
            style(
                "Usage sample label={label} organizations={organizations} "
                "sampled={sampled} skipped={skipped}".format(
                    label=result.get("label") or "command",
                    organizations=int(result.get("organizations") or 0),
                    sampled=int(result.get("sampled") or 0),
                    skipped=bool(result.get("skipped")),
                )
            )
        )
