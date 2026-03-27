from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Server",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=120, unique=True)),
                ("host", models.CharField(default="127.0.0.1", max_length=255)),
                ("port", models.PositiveIntegerField(default=22)),
                ("ssh_username", models.CharField(default="amnezia", max_length=120)),
                ("ssh_private_key_path", models.CharField(blank=True, max_length=255)),
                ("is_enabled", models.BooleanField(default=True)),
                ("health_status", models.CharField(default="unknown", max_length=30)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="ServerProtocol",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("protocol_type", models.CharField(choices=[("awg", "AmneziaWG"), ("awg2", "AWG2")], max_length=16)),
                ("enabled", models.BooleanField(default=True)),
                ("server", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="protocols", to="servers.server")),
            ],
            options={"unique_together": {("server", "protocol_type")}},
        ),
        migrations.CreateModel(
            name="ProtocolProfile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=120)),
                ("protocol_type", models.CharField(choices=[("awg", "AmneziaWG"), ("awg2", "AWG2")], max_length=16)),
                ("config_template", models.TextField()),
                ("status", models.CharField(choices=[("active", "Active"), ("archived", "Archived")], default="active", max_length=16)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("server_protocol", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="profiles", to="servers.serverprotocol")),
            ],
            options={"unique_together": {("server_protocol", "name", "protocol_type")}},
        ),
    ]
