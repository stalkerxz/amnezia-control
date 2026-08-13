from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "vpn",
            "0012_backfill_xhttpdevice_server",
        ),
    ]

    operations = [
        migrations.AlterField(
            model_name="vpnclient",
            name="disable_reason",
            field=models.CharField(
                choices=[
                    ("none", "Нет"),
                    ("manual", "Вручную"),
                    ("expired", "Истек срок"),
                    (
                        "traffic_exceeded",
                        "Превышен лимит трафика",
                    ),
                    (
                        "owner",
                        "Недоступен аккаунт/устройство",
                    ),
                ],
                default="none",
                max_length=24,
            ),
        ),
    ]
