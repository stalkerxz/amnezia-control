from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vpn", "0003_runtime_client_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="vpnclient",
            name="disable_reason",
            field=models.CharField(
                choices=[
                    ("none", "Нет"),
                    ("manual", "Вручную"),
                    ("expired", "Истек срок"),
                    ("traffic_exceeded", "Превышен лимит трафика"),
                ],
                default="none",
                max_length=24,
            ),
        ),
        migrations.AddField(
            model_name="vpnclient",
            name="expires_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="vpnclient",
            name="limit_state",
            field=models.CharField(
                choices=[
                    ("active", "Активен"),
                    ("expired", "Истек"),
                    ("traffic_exceeded", "Трафик превышен"),
                ],
                default="active",
                max_length=24,
            ),
        ),
        migrations.AddField(
            model_name="vpnclient",
            name="traffic_last_sync_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="vpnclient",
            name="traffic_limit_bytes",
            field=models.BigIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="vpnclient",
            name="traffic_sync_error",
            field=models.CharField(blank=True, max_length=160),
        ),
        migrations.AddField(
            model_name="vpnclient",
            name="traffic_used_bytes",
            field=models.BigIntegerField(default=0),
        ),
    ]
