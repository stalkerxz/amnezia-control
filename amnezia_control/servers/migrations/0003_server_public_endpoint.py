from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("servers", "0002_runtime_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="public_endpoint_host",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="server",
            name="public_endpoint_port",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]
