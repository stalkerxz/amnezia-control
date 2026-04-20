from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("vpn", "0004_vpnclient_limits"),
    ]

    operations = [
        migrations.AddField(
            model_name="vpnclient",
            name="contact_email",
            field=models.EmailField(blank=True, max_length=254),
        ),
    ]
