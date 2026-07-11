from django.db import migrations


STATUS_ENUM = (
    "ENUM('pending_approval','active','suspended','burned') "
    "NOT NULL DEFAULT 'pending_approval'"
)
ROLE_ENUM = (
    "ENUM('pending','super_admin','administrator','manager','it_support','sales','technician') "
    "NOT NULL DEFAULT 'pending'"
)

STATUS_VARCHAR = "VARCHAR(32) NOT NULL DEFAULT 'pending_approval'"
ROLE_VARCHAR = "VARCHAR(32) NOT NULL DEFAULT 'pending'"


def forwards(apps, schema_editor):
    if schema_editor.connection.vendor != "mysql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            f"ALTER TABLE accounts_employee MODIFY COLUMN status {STATUS_ENUM}"
        )
        cursor.execute(
            f"ALTER TABLE accounts_employee MODIFY COLUMN `role` {ROLE_ENUM}"
        )


def backwards(apps, schema_editor):
    if schema_editor.connection.vendor != "mysql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            f"ALTER TABLE accounts_employee MODIFY COLUMN status {STATUS_VARCHAR}"
        )
        cursor.execute(
            f"ALTER TABLE accounts_employee MODIFY COLUMN `role` {ROLE_VARCHAR}"
        )


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0007_employee_organization_optional"),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
