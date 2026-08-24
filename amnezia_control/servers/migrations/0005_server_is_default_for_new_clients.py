from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("servers", "0004_server_runtime_backend"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="is_default_for_new_clients",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "Использовать этот сервер по умолчанию "
                    "при выпуске новых VPN-клиентов."
                ),
            ),
        ),
    ]
