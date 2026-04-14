from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("portal", "0002_clientportalaccess_expires_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="clientportalaccess",
            name="token_encrypted",
            field=models.TextField(blank=True, null=True),
        ),
    ]
