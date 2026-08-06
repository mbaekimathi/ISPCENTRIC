from decimal import Decimal

from django.db import migrations, models


def forwards_fill_discount_price(apps, schema_editor):
    NetworkEquipment = apps.get_model("accounts", "NetworkEquipment")
    for item in NetworkEquipment.objects.all().iterator():
        selling = item.selling_price or Decimal("0")
        amount = item.discount_amount or Decimal("0")
        if item.discount_enabled:
            price = selling - amount
            if price < 0:
                price = Decimal("0")
        else:
            price = Decimal("0")
        item.discount_price = price
        item.save(update_fields=["discount_price"])


def backwards_noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0045_networkequipment_selling_price_discount"),
    ]

    operations = [
        migrations.AddField(
            model_name="networkequipment",
            name="discount_price",
            field=models.DecimalField(
                decimal_places=2,
                default=Decimal("0"),
                help_text="Price to sell at when a discount is enabled.",
                max_digits=12,
                verbose_name="Discount price",
            ),
        ),
        migrations.AlterField(
            model_name="networkequipment",
            name="discount_enabled",
            field=models.BooleanField(
                default=False,
                help_text="When enabled, the item sells at discount_price instead of selling_price.",
                verbose_name="Enable discount",
            ),
        ),
        migrations.AlterField(
            model_name="networkequipment",
            name="discount_amount",
            field=models.DecimalField(
                decimal_places=2,
                default=Decimal("0"),
                help_text="Calculated savings in KES (selling price minus discount price).",
                max_digits=12,
                verbose_name="Discount amount",
            ),
        ),
        migrations.RunPython(forwards_fill_discount_price, backwards_noop),
    ]
