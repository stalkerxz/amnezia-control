from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "servers",
            "0005_server_is_default_for_new_clients",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="accepts_new_vpn_clients",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "Разрешить автоматический и управляемый "
                    "выпуск новых VPN-клиентов на этот сервер."
                ),
            ),
        ),
    ]
