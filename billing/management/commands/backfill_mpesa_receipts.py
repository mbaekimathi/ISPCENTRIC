"""Backfill missing M-Pesa receipt numbers on successful STK pushes."""

from django.core.management.base import BaseCommand

from billing.models import StkPushRequest
from billing.stk import backfill_mpesa_receipt_for_stk, extract_mpesa_receipt_from_raw


class Command(BaseCommand):
    help = (
        "Copy M-Pesa receipt numbers from stored STK raw_callback JSON onto "
        "StkPushRequest.mpesa_receipt and linked Payment.reference rows."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--organization",
            type=int,
            default=0,
            help="Limit to one organization id.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be updated without saving.",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Process at most this many STK rows (0 = no limit).",
        )

    def handle(self, *args, **options):
        qs = (
            StkPushRequest.objects.filter(
                status=StkPushRequest.Status.SUCCESS,
                mpesa_receipt="",
            )
            .exclude(raw_callback={})
            .order_by("-id")
        )
        org_id = int(options.get("organization") or 0)
        if org_id:
            qs = qs.filter(organization_id=org_id)

        limit = int(options.get("limit") or 0)
        if limit > 0:
            qs = qs[:limit]

        dry_run = bool(options.get("dry_run"))
        fixed = 0
        skipped = 0

        for stk in qs.iterator():
            raw = stk.raw_callback if isinstance(stk.raw_callback, dict) else {}
            preview = extract_mpesa_receipt_from_raw(raw)
            if not preview:
                skipped += 1
                continue
            if dry_run:
                self.stdout.write(f"Would backfill STK {stk.pk} -> {preview}")
                fixed += 1
                continue
            recovered = backfill_mpesa_receipt_for_stk(stk)
            if recovered:
                fixed += 1
                self.stdout.write(f"STK {stk.pk} -> {recovered}")
            else:
                skipped += 1

        suffix = " (dry run)" if dry_run else ""
        self.stdout.write(
            self.style.SUCCESS(
                f"Done{suffix}: backfilled {fixed}, skipped {skipped}."
            )
        )
