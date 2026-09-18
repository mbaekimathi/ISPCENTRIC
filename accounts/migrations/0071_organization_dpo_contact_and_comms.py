from django.db import migrations, models


DPO_EVENT_KEYS = (
    "isp_mikrotik_onboarding",
    "isp_mikrotik_onboarded",
    "isp_mikrotik_health_low",
    "isp_mikrotik_off",
    "isp_mikrotik_accessed",
    "isp_mikrotik_config_changed",
    "isp_pppoe_connected_not_surfing",
    "isp_mikrotik_usage_high",
)


def advance_mikrotik_client_events_to_dpo(apps, schema_editor):
    CommunicationSettings = apps.get_model("accounts", "CommunicationSettings")
    for row in CommunicationSettings.objects.all().iterator():
        prefs = row.enabled_messages
        if not isinstance(prefs, dict) or not prefs:
            continue
        changed = False
        updated = dict(prefs)
        for key in DPO_EVENT_KEYS:
            rule = updated.get(key)
            if not isinstance(rule, dict):
                continue
            recipients = rule.get("recipients") or rule.get("recipient") or []
            if isinstance(recipients, str):
                recipients = [recipients]
            cleaned = []
            seen = set()
            for item in recipients:
                rid = str(item or "").strip()
                if rid == "organization_owner":
                    rid = "dpo"
                if rid and rid not in seen:
                    cleaned.append(rid)
                    seen.add(rid)
            if not cleaned:
                cleaned = ["dpo"]
            if cleaned != list(recipients):
                new_rule = dict(rule)
                new_rule["recipients"] = cleaned
                new_rule.pop("recipient", None)
                updated[key] = new_rule
                changed = True
        if changed:
            row.enabled_messages = updated
            row.save(update_fields=["enabled_messages"])


def revert_dpo_events_to_owner(apps, schema_editor):
    CommunicationSettings = apps.get_model("accounts", "CommunicationSettings")
    for row in CommunicationSettings.objects.all().iterator():
        prefs = row.enabled_messages
        if not isinstance(prefs, dict) or not prefs:
            continue
        changed = False
        updated = dict(prefs)
        for key in DPO_EVENT_KEYS:
            rule = updated.get(key)
            if not isinstance(rule, dict):
                continue
            recipients = rule.get("recipients") or rule.get("recipient") or []
            if isinstance(recipients, str):
                recipients = [recipients]
            cleaned = []
            seen = set()
            for item in recipients:
                rid = str(item or "").strip()
                if rid == "dpo":
                    rid = "organization_owner"
                if rid and rid not in seen:
                    cleaned.append(rid)
                    seen.add(rid)
            if cleaned != list(recipients):
                new_rule = dict(rule)
                new_rule["recipients"] = cleaned or ["organization_owner"]
                new_rule.pop("recipient", None)
                updated[key] = new_rule
                changed = True
        if changed:
            row.enabled_messages = updated
            row.save(update_fields=["enabled_messages"])


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0070_organization_hotspot_block_tethering_default_on"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="dpo_email",
            field=models.EmailField(
                blank=True,
                default="",
                help_text="Email for DPO alerts. Falls back to the organization owner when empty.",
                verbose_name="DPO email",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="dpo_name",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Data protection / ops contact who receives MikroTik and client alerts.",
                max_length=120,
                verbose_name="DPO name",
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="dpo_phone",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Phone for DPO SMS/WhatsApp alerts.",
                max_length=30,
                verbose_name="DPO phone",
            ),
        ),
        migrations.RunPython(
            advance_mikrotik_client_events_to_dpo,
            revert_dpo_events_to_owner,
        ),
    ]
