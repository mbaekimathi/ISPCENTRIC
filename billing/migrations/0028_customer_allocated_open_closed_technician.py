from django.db import migrations, models
import django.db.models.deletion


def forwards_allocated_closed(apps, schema_editor):
    Customer = apps.get_model("billing", "Customer")
    Customer.objects.filter(status="allocated").update(status="allocated_closed")


def backwards_allocated(apps, schema_editor):
    Customer = apps.get_model("billing", "Customer")
    Customer.objects.filter(status__in=["allocated_open", "allocated_closed"]).update(
        status="allocated"
    )


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0030_role_commission_package_percent"),
        ("billing", "0027_stkpushrequest_purpose"),
    ]

    operations = [
        migrations.AlterField(
            model_name="customer",
            name="status",
            field=models.CharField(
                choices=[
                    ("new", "New"),
                    ("allocated", "Allocated"),
                    ("allocated_open", "Allocated — open"),
                    ("allocated_closed", "Allocated — closed"),
                    ("accepted", "Accepted"),
                    ("not_interested", "Not interested"),
                    ("active", "Active"),
                    ("suspended", "Suspended"),
                    ("inactive", "Inactive"),
                ],
                default="active",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="customer",
            name="assigned_technician",
            field=models.ForeignKey(
                blank=True,
                help_text="Technician assigned when this lead was allocated (closed assignment).",
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="assigned_customers",
                to="accounts.employee",
            ),
        ),
        migrations.RunPython(forwards_allocated_closed, backwards_allocated),
    ]
