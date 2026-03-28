from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("servers", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="last_runtime_sync_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="serverprotocol",
            name="container_name",
            field=models.CharField(blank=True, max_length=120),
        ),
        migrations.AddField(
            model_name="serverprotocol",
            name="container_status",
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AddField(
            model_name="serverprotocol",
            name="last_sync_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="serverprotocol",
            name="runtime_metadata",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
