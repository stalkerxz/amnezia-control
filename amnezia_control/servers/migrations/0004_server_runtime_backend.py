from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("servers", "0003_server_public_endpoint"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="runtime_backend",
            field=models.CharField(
                choices=[
                    ("docker", "Docker / Amnezia container"),
                    ("awg_agent", "AWG agent over SSH"),
                ],
                default="docker",
                max_length=24,
            ),
        ),
    ]
