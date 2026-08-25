from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "servers",
            "0006_server_accepts_new_vpn_clients",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="vpn_pool_locked",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "Эксплуатационный запрет на включение "
                    "сервера в пул выпуска новых VPN-клиентов."
                ),
            ),
        ),
    ]
