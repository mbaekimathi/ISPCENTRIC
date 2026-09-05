from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0053_alter_organization_login_code"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="adverts_enabled",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When enabled, Hotspot and PPPoE pay / pause pages show a "
                    "“Click to earn” link to this ISP’s subscriber adverts page."
                ),
                verbose_name="Show Click to earn on captive pages",
            ),
        ),
        migrations.CreateModel(
            name="SubscriberAdvertisement",
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
                ("title", models.CharField(max_length=120)),
                ("description", models.TextField(max_length=2000)),
                (
                    "contact_name",
                    models.CharField(blank=True, default="", max_length=120),
                ),
                ("contact_phone", models.CharField(max_length=30)),
                ("is_active", models.BooleanField(db_index=True, default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="subscriber_adverts",
                        to="accounts.organization",
                    ),
                ),
            ],
            options={
                "verbose_name": "Subscriber advertisement",
                "verbose_name_plural": "Subscriber advertisements",
                "db_table": "accounts_subscriber_advertisement",
                "ordering": ["-created_at"],
            },
        ),
    ]
