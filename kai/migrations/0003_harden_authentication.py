import hashlib

from django.db import migrations, models
import django.db.models.deletion


def hash_existing_tokens(apps, schema_editor):
    user_model = apps.get_model("kai", "User")
    for user in user_model.objects.exclude(api_token__isnull=True).exclude(api_token=""):
        user.api_token_digest = hashlib.sha256(user.api_token.encode()).hexdigest()
        user.api_token_prefix = user.api_token[:8]
        user.save(update_fields=["api_token_digest", "api_token_prefix"])


class Migration(migrations.Migration):
    dependencies = [
        ("kai", "0002_pcap_tshark_analysis"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="api_token_digest",
            field=models.CharField(blank=True, max_length=64, null=True, unique=True),
        ),
        migrations.AddField(
            model_name="user",
            name="api_token_prefix",
            field=models.CharField(blank=True, max_length=12, null=True),
        ),
        migrations.AddField(
            model_name="user",
            name="api_token_created_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="user",
            name="api_token_expires_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="user",
            name="api_token_last_used_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="user",
            name="auth_source",
            field=models.CharField(default="local", max_length=20),
        ),
        migrations.AddField(
            model_name="user",
            name="is_active",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="user",
            name="is_staff",
            field=models.BooleanField(default=False),
        ),
        migrations.RunPython(hash_existing_tokens, migrations.RunPython.noop),
        migrations.RemoveField(model_name="user", name="api_token"),
        migrations.CreateModel(
            name="SecurityEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("event", models.CharField(max_length=64)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("success", models.BooleanField(default=True)),
                ("details", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("user", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="kai.user")),
            ],
            options={
                "db_table": "security_events",
                "indexes": [models.Index(fields=["event", "created_at"], name="idx_security_event_time")],
            },
        ),
    ]
