from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("servers", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="VPNClient",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=120)),
                ("protocol_type", models.CharField(choices=[("awg", "AmneziaWG"), ("awg2", "AWG2")], max_length=16)),
                ("status", models.CharField(choices=[("active", "Активен"), ("disabled", "Отключен"), ("deleted", "Удален")], default="active", max_length=16)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("created_by", models.ForeignKey(null=True, on_delete=models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ("profile", models.ForeignKey(on_delete=models.deletion.PROTECT, to="servers.protocolprofile")),
                ("server", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="clients", to="servers.server")),
            ],
            options={"unique_together": {("server", "name", "protocol_type")}},
        ),
        migrations.CreateModel(
            name="ClientConfigRevision",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("revision_number", models.PositiveIntegerField()),
                ("protocol_type", models.CharField(choices=[("awg", "AmneziaWG"), ("awg2", "AWG2")], max_length=16)),
                ("config_blob_encrypted", models.TextField()),
                ("config_hash", models.CharField(max_length=128)),
                ("qr_payload", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("client", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="revisions", to="vpn.vpnclient")),
            ],
            options={"ordering": ("-revision_number",), "unique_together": {("client", "revision_number", "protocol_type")}},
        ),
    ]
