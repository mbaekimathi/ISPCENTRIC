import secrets

from django.db import migrations, models


def fill_login_codes(apps, schema_editor):
    Employee = apps.get_model("accounts", "Employee")
    used = set(
        Employee.objects.exclude(login_code="")
        .exclude(login_code__isnull=True)
        .values_list("login_code", flat=True)
    )
    for emp in Employee.objects.all():
        if emp.login_code and len(str(emp.login_code)) == 6:
            used.add(emp.login_code)
            continue
        while True:
            code = f"{secrets.randbelow(1_000_000):06d}"
            if code not in used:
                used.add(code)
                emp.login_code = code
                emp.save(update_fields=["login_code"])
                break


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0005_employee_status_role"),
    ]

    operations = [
        migrations.AddField(
            model_name="employee",
            name="login_code",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text="6-digit code the employee uses to log in",
                max_length=6,
            ),
            preserve_default=False,
        ),
        migrations.RunPython(fill_login_codes, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="employee",
            name="login_code",
            field=models.CharField(
                db_index=True,
                help_text="6-digit code the employee uses to log in",
                max_length=6,
                unique=True,
            ),
        ),
    ]
