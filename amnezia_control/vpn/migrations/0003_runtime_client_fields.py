from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("vpn", "0002_remove_qr_payload"),
    ]

    operations = [
        migrations.AddField(
            model_name="vpnclient",
            name="imported_from_runtime",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="vpnclient",
            name="last_runtime_sync_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="vpnclient",
            name="runtime_address",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="vpnclient",
            name="runtime_peer_public_key",
            field=models.CharField(blank=True, max_length=128),
        ),
    ]
