from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0022_customer_location_building"),
    ]

    operations = [
        migrations.AddField(
            model_name="customer",
            name="sales_ticket_number",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text="Generated when sales registers this client.",
                max_length=40,
                null=True,
                unique=True,
                verbose_name="Sales ticket number",
            ),
        ),
    ]
