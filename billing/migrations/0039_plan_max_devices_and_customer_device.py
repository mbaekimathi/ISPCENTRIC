from django.db import migrations, models
import django.core.validators
import django.db.models.deletion


def backfill_customer_devices(apps, schema_editor):
    Customer = apps.get_model("billing", "Customer")
    CustomerDevice = apps.get_model("billing", "CustomerDevice")

    def normalize(mac: str) -> str:
        mac = (mac or "").strip().upper().replace("-", ":")
        compact = mac.replace(":", "")
        if len(compact) == 12 and all(ch in "0123456789ABCDEF" for ch in compact):
            return ":".join(compact[i : i + 2] for i in range(0, 12, 2))
        return mac

    seen = set()
    rows = []
    for customer in (
        Customer.objects.exclude(hotspot_mac__isnull=True)
        .exclude(hotspot_mac="")
        .exclude(organization_id=None)
        .iterator()
    ):
        mac = normalize(customer.hotspot_mac)
        if not mac:
            continue
        key = (customer.organization_id, mac)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            CustomerDevice(
                organization_id=customer.organization_id,
                customer_id=customer.pk,
                mac=mac,
            )
        )
    if rows:
        CustomerDevice.objects.bulk_create(rows, ignore_conflicts=True)


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0046_networkequipment_discount_price"),
        ("billing", "0038_customer_phone_normalized_unique"),
    ]

    operations = [
        migrations.AddField(
            model_name="billingplan",
            name="max_devices",
            field=models.PositiveIntegerField(
                default=1,
                help_text=(
                    "How many devices this package allows. Hotspot: phones/laptops on one "
                    "paid account. PPPoE: CPEs that may dial this username (LAN behind one "
                    "CPE is already unlimited)."
                ),
                validators=[
                    django.core.validators.MinValueValidator(1),
                    django.core.validators.MaxValueValidator(50),
                ],
                verbose_name="Max devices",
            ),
        ),
        migrations.CreateModel(
            name="CustomerDevice",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("mac", models.CharField(db_index=True, max_length=17, verbose_name="Device MAC")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_seen_at", models.DateTimeField(blank=True, null=True)),
                (
                    "customer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="devices",
                        to="billing.customer",
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="customer_devices",
                        to="accounts.organization",
                    ),
                ),
            ],
            options={
                "db_table": "billing_customer_device",
                "ordering": ["id"],
            },
        ),
        migrations.AddIndex(
            model_name="customerdevice",
            index=models.Index(fields=["customer", "mac"], name="bill_cust_dev_cust_mac_idx"),
        ),
        migrations.AddConstraint(
            model_name="customerdevice",
            constraint=models.UniqueConstraint(
                fields=("organization", "mac"),
                name="bill_cust_dev_org_mac_uniq",
            ),
        ),
        migrations.RunPython(backfill_customer_devices, migrations.RunPython.noop),
    ]
