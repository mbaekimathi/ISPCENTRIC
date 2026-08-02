from django.db import migrations


def reformat_sales_ticket_numbers(apps, schema_editor):
    import secrets

    Customer = apps.get_model("billing", "Customer")
    qs = (
        Customer.objects.filter(service_type="pppoe")
        .exclude(sales_ticket_number__startswith="PPP-")
        .order_by("id")
    )

    for customer in qs.iterator():
        for _ in range(80):
            candidate = f"PPP-{secrets.token_hex(2).upper()}"
            if not Customer.objects.filter(sales_ticket_number=candidate).exists():
                customer.sales_ticket_number = candidate
                customer.save(update_fields=["sales_ticket_number"])
                break
        else:
            raise RuntimeError(
                f"Could not generate a unique PPP ticket for customer {customer.pk}."
            )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0024_backfill_sales_ticket_numbers"),
    ]

    operations = [
        migrations.RunPython(reformat_sales_ticket_numbers, noop_reverse),
    ]
