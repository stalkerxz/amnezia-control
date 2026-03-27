from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("vpn", "0001_initial"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="clientconfigrevision",
            name="qr_payload",
        ),
    ]
