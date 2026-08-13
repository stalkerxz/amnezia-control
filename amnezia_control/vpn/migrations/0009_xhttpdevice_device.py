import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("customers", "0002_legacy_vpn_clients"),
        ("vpn", "0008_vpnclient_device"),
    ]

    operations = [
        migrations.AddField(
            model_name="xhttpdevice",
            name="device",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="xhttp_devices",
                to="customers.clientdevice",
            ),
        ),
    ]
