import secrets

from django.db import migrations, models


def fill_join_codes(apps, schema_editor):
    Organization = apps.get_model("accounts", "Organization")
    used = set(
        Organization.objects.exclude(join_code__isnull=True)
        .exclude(join_code="")
        .values_list("join_code", flat=True)
    )
    for org in Organization.objects.all():
        if org.join_code and len(org.join_code) == 6:
            continue
        while True:
            code = f"{secrets.randbelow(1_000_000):06d}"
            if code not in used:
                used.add(code)
                org.join_code = code
                org.save(update_fields=["join_code"])
                break


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0003_employee"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="join_code",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text="6-digit code employees use to join this company",
                max_length=6,
            ),
            preserve_default=False,
        ),
        migrations.RunPython(fill_join_codes, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="organization",
            name="join_code",
            field=models.CharField(
                db_index=True,
                help_text="6-digit code employees use to join this company",
                max_length=6,
                unique=True,
            ),
        ),
    ]
