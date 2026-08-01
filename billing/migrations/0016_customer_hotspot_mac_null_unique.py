from django.db import migrations, models


def normalize_hotspot_macs(apps, schema_editor):
    """Convert empty Hotspot MACs to NULL and collapse remaining duplicates."""
    Customer = apps.get_model("billing", "Customer")
    seen = set()
    qs = (
        Customer.objects.exclude(hotspot_mac__isnull=True)
        .exclude(hotspot_mac="")
        .order_by("organization_id", "hotspot_mac", "id")
    )
    for customer in qs.iterator():
        key = (customer.organization_id, (customer.hotspot_mac or "").upper())
        if key in seen:
            customer.hotspot_mac = None
            customer.save(update_fields=["hotspot_mac"])
        else:
            seen.add(key)
    Customer.objects.filter(hotspot_mac="").update(hotspot_mac=None)


def drop_legacy_constraint(apps, schema_editor):
    """
    Drop the conditional unique constraint if the backend created it.

    MariaDB never installs conditioned UniqueConstraints, so a hard
    RemoveConstraint would fail there.
    """
    connection = schema_editor.connection
    table = "billing_customer"
    name = "bill_cust_org_hotspot_mac_uniq"
    with connection.cursor() as cursor:
        if connection.vendor in {"mysql", "mariadb"}:
            cursor.execute(
                """
                SELECT 1
                FROM information_schema.statistics
                WHERE table_schema = DATABASE()
                  AND table_name = %s
                  AND index_name = %s
                LIMIT 1
                """,
                [table, name],
            )
            if cursor.fetchone():
                cursor.execute(f"DROP INDEX `{name}` ON `{table}`")
            return
        if connection.vendor == "postgresql":
            cursor.execute(f'ALTER TABLE "{table}" DROP CONSTRAINT IF EXISTS "{name}"')
            return
        if connection.vendor == "sqlite":
            # SQLite recreates tables for constraint changes; state-only is enough.
            return


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0015_customer_hotspot_mac_unique"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.RemoveConstraint(
                    model_name="customer",
                    name="bill_cust_org_hotspot_mac_uniq",
                ),
            ],
            database_operations=[
                migrations.RunPython(drop_legacy_constraint, migrations.RunPython.noop),
            ],
        ),
        migrations.AlterField(
            model_name="customer",
            name="hotspot_mac",
            field=models.CharField(
                blank=True,
                db_index=True,
                default=None,
                help_text="Device authorized automatically after a successful Hotspot payment.",
                max_length=17,
                null=True,
                verbose_name="Hotspot device MAC",
            ),
        ),
        migrations.RunPython(normalize_hotspot_macs, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="customer",
            constraint=models.UniqueConstraint(
                fields=("organization", "hotspot_mac"),
                name="bill_cust_org_hotspot_mac_uniq",
            ),
        ),
    ]
