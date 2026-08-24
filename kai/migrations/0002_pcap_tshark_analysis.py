from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("kai", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="pcap",
            name="tshark_analysis",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
