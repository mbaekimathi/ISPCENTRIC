from django.db import migrations, models


def upgrade_referral_codes_and_status(apps, schema_editor):
    Organization = apps.get_model("accounts", "Organization")
    MikroTikRouter = apps.get_model("core", "MikroTikRouter")
    orgs_with_router = set(
        MikroTikRouter.objects.values_list("organization_id", flat=True).distinct()
    )

    used = set()
    for org in Organization.objects.all().iterator():
        # Phone-only referral codes.
        digits = "".join(ch for ch in (org.phone or "") if ch.isdigit())
        if digits.startswith("254") and len(digits) >= 12:
            digits = digits[3:]
        elif digits.startswith("0") and len(digits) >= 10:
            digits = digits.lstrip("0")
        if not digits:
            digits = (org.referral_code or "").strip()
            digits = "".join(ch for ch in digits if ch.isdigit()) or f"{org.pk:09d}"
        code = digits
        n = 1
        while code in used:
            n += 1
            code = f"{digits}{n}"
        used.add(code)
        org.referral_code = code

        if org.referred_by_id:
            if org.pk in orgs_with_router:
                org.referral_status = "active"
            else:
                org.referral_status = org.referral_status or "pending"
        else:
            org.referral_status = ""
        org.save(update_fields=["referral_code", "referral_status"])


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0042_rename_landing_register"),
        ("core", "0015_mikrotik_status_sample"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="referral_status",
            field=models.CharField(
                blank=True,
                choices=[("pending", "Pending"), ("active", "Active")],
                db_index=True,
                default="",
                help_text=(
                    "When this org was referred: pending until the first MikroTik "
                    "is onboarded, then active."
                ),
                max_length=16,
                verbose_name="Referral status",
            ),
        ),
        migrations.AlterField(
            model_name="organization",
            name="referral_code",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text="Shareable code — the organization's phone digits.",
                max_length=64,
                null=True,
                unique=True,
                verbose_name="Referral code",
            ),
        ),
        migrations.RunPython(upgrade_referral_codes_and_status, noop_reverse),
    ]
