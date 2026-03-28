from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from servers.models import ProtocolProfile, Server, ServerProtocol


class Command(BaseCommand):
    help = "Seed demo protocol/server data (optional demo admin with --with-demo-admin)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--with-demo-admin",
            action="store_true",
            help="Create demo admin/admin12345 (development only)",
        )

    def handle(self, *args, **options):
        if options["with_demo_admin"]:
            User = get_user_model()
            if not User.objects.filter(username="admin").exists():
                User.objects.create_superuser("admin", "admin@example.com", "admin12345")
                self.stdout.write(self.style.WARNING("Created demo admin/admin12345"))

        server, _ = Server.objects.get_or_create(name="Local VPS", defaults={"host": "127.0.0.1", "ssh_username": "amnezia"})
        awg_sp, _ = ServerProtocol.objects.get_or_create(server=server, protocol_type=ServerProtocol.ProtocolType.AWG)
        awg2_sp, _ = ServerProtocol.objects.get_or_create(server=server, protocol_type=ServerProtocol.ProtocolType.AWG2)

        ProtocolProfile.objects.get_or_create(
            server_protocol=awg_sp,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            name="default-awg",
            defaults={"config_template": "[Interface]\\n# {client_name}\\n# {protocol}\\nPrivateKey = changeme"},
        )
        ProtocolProfile.objects.get_or_create(
            server_protocol=awg2_sp,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            name="default-awg2",
            defaults={"config_template": "[Interface]\\n# {client_name}\\n# {protocol}\\nPrivateKey = changeme-awg2"},
        )
        self.stdout.write(self.style.SUCCESS("Demo protocol data ready"))
