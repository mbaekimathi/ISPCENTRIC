import secrets

from django.db import migrations, models


def backfill_organization_login_codes(apps, schema_editor):
    Organization = apps.get_model("accounts", "Organization")
    User = apps.get_model("auth", "User")
    used_codes: set[str] = set()

    for org in Organization.objects.select_related("owner").order_by("pk"):
        owner = getattr(org, "owner", None)
        code = (org.login_code or "").strip()
        if not code and owner is not None:
            candidate = (owner.username or "").strip()
            if len(candidate) == 6 and candidate.isdigit() and candidate not in used_codes:
                code = candidate
            else:
                for _ in range(200):
                    candidate = f"{secrets.randbelow(1_000_000):06d}"
                    if candidate not in used_codes:
                        code = candidate
                        break
            used_codes.add(code)
            org.login_code = code
            org.save(update_fields=["login_code"])

        if owner is None:
            continue
        username = (owner.username or "").strip()
        if len(username) == 6 and username.isdigit():
            new_username = f"isp-owner-{org.pk}-{secrets.token_hex(4)}"
            while User.objects.filter(username=new_username).exists():
                new_username = f"isp-owner-{org.pk}-{secrets.token_hex(4)}"
            User.objects.filter(pk=owner.pk).update(username=new_username)


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0051_security_hardening_encryption_audit"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="login_code",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text="6-digit code the ISP owner uses to log in (separate from staff login codes).",
                max_length=6,
            ),
        ),
        migrations.RunPython(backfill_organization_login_codes, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="organization",
            name="login_code",
            field=models.CharField(
                db_index=True,
                help_text="6-digit code the ISP owner uses to log in (separate from staff login codes).",
                max_length=6,
                unique=True,
            ),
        ),
    ]
