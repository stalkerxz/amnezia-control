from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "vpn",
            "0016_xhttpdevice_performance_profile",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="clientconfigrevision",
            name="amneziavpn_blob_encrypted",
            field=models.TextField(
                blank=True,
                default="",
            ),
        ),
    ]
