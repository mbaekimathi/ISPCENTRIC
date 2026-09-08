from django.db import migrations, models


# Old status → new linear lifecycle status.
STATUS_MAP = {
    "new": "lead",
    "in_progress": "assigned",
    "allocated": "queued",
    "allocated_open": "queued",
    "allocated_closed": "assigned",
    "accepted": "assigned",
    "inactive": "installed",
    # unchanged:
    "active": "active",
    "suspended": "suspended",
    "not_interested": "not_interested",
}


def forwards_remap_status(apps, schema_editor):
    Customer = apps.get_model("billing", "Customer")
    for old, new in STATUS_MAP.items():
        if old == new:
            continue
        Customer.objects.filter(status=old).update(status=new)


def backwards_remap_status(apps, schema_editor):
    Customer = apps.get_model("billing", "Customer")
    reverse = {
        "lead": "new",
        "queued": "allocated_open",
        "assigned": "allocated_closed",
        "installed": "inactive",
    }
    for new, old in reverse.items():
        Customer.objects.filter(status=new).update(status=old)


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0049_customer_status_in_progress_pending_activation"),
    ]

    operations = [
        migrations.AlterField(
            model_name="customer",
            name="status",
            field=models.CharField(
                choices=[
                    ("lead", "Lead"),
                    ("queued", "Queued for install"),
                    ("assigned", "Assigned"),
                    ("installed", "Installed"),
                    ("active", "Active"),
                    ("suspended", "Suspended"),
                    ("not_interested", "Not interested"),
                    # Keep old keys readable during RunPython remap window.
                    ("new", "Pending connection"),
                    ("in_progress", "In progress"),
                    ("allocated", "Allocated"),
                    ("allocated_open", "Allocated — open"),
                    ("allocated_closed", "Allocated — closed"),
                    ("accepted", "Accepted"),
                    ("inactive", "Pending activation"),
                ],
                default="active",
                max_length=20,
            ),
        ),
        migrations.RunPython(forwards_remap_status, backwards_remap_status),
        migrations.AlterField(
            model_name="customer",
            name="status",
            field=models.CharField(
                choices=[
                    ("lead", "Lead"),
                    ("queued", "Queued for install"),
                    ("assigned", "Assigned"),
                    ("installed", "Installed"),
                    ("active", "Active"),
                    ("suspended", "Suspended"),
                    ("not_interested", "Not interested"),
                ],
                default="active",
                max_length=20,
            ),
        ),
    ]
