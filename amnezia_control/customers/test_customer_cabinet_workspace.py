import hashlib

from cryptography.fernet import Fernet

from django.contrib.auth import get_user_model
from django.test import (
    TestCase,
    override_settings,
)
from django.urls import reverse

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)

from vpn.models import (
    ClientConfigRevision,
    VPNClient,
    XHTTPDevice,
)

from vpn.services import ConfigCryptoService

from .models import (
    ClientDevice,
    CustomerAccount,
)


@override_settings(
    CONFIG_ENCRYPTION_KEY=(
        Fernet.generate_key().decode()
    )
)
class CustomerCabinetWorkspaceTest(
    TestCase
):
    def setUp(self):
        User = get_user_model()

        self.user = User.objects.create_user(
            username="cabinet-workspace",
            password="customer-password",
            is_owner=False,
            is_staff=False,
            is_superuser=False,
        )

        self.account = (
            CustomerAccount.objects.create(
                display_name="Cabinet Customer",
                email="cabinet@example.com",
                user=self.user,
            )
        )

        self.device = (
            ClientDevice.objects.create(
                account=self.account,
                name="My MacBook",
                platform=(
                    ClientDevice.Platform.MACOS
                ),
            )
        )

        self.server = Server.objects.create(
            name="Technical Server Name",
        )

        self.protocol = (
            ServerProtocol.objects.create(
                server=self.server,
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                container_name="amnezia-awg2",
                enabled=True,
                runtime_metadata={
                    "udp_port": 51830,
                    "subnet": "10.77.0.0/24",
                },
            )
        )

        self.full_profile = (
            ProtocolProfile.objects.create(
                server_protocol=self.protocol,
                name="TECH-FULL-PROFILE",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template="[Interface]",
            )
        )

        self.select_profile = (
            ProtocolProfile.objects.create(
                server_protocol=self.protocol,
                name="TECH-SELECT-PROFILE",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template=(
                    "# routing-mode: selective\n"
                    "8.8.8.0/24\n"
                ),
            )
        )

        self.full = self._vpn(
            name="TECHNICAL-FULL-CLIENT",
            profile=self.full_profile,
            address="10.77.0.10",
        )

        self.selective = self._vpn(
            name="TECHNICAL-SELECT-CLIENT",
            profile=self.select_profile,
            address="10.77.0.11",
        )

        self.xhttp = (
            XHTTPDevice.objects.create(
                device=self.device,
                server=self.server,
                name="TECHNICAL-XHTTP-NAME",
                xray_email=(
                    "cabinet-workspace-"
                    "xhttp@example.invalid"
                ),
                status=(
                    XHTTPDevice.Status.ACTIVE
                ),
                config_blob_encrypted=(
                    ConfigCryptoService.encrypt(
                        '{"test":"xhttp"}\n'
                    )
                ),
                config_hash=hashlib.sha256(
                    b'{"test":"xhttp"}\n'
                ).hexdigest(),
            )
        )

        other_user = User.objects.create_user(
            username="other-cabinet-user",
            password="other-password",
        )

        other_account = (
            CustomerAccount.objects.create(
                display_name=(
                    "OTHER SECRET ACCOUNT"
                ),
                user=other_user,
            )
        )

        other_device = (
            ClientDevice.objects.create(
                account=other_account,
                name="OTHER SECRET DEVICE",
            )
        )

        VPNClient.objects.create(
            server=self.server,
            name="OTHER SECRET VPN",
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            profile=self.full_profile,
            device=other_device,
        )

    def _vpn(
        self,
        *,
        name,
        profile,
        address,
    ):
        client = VPNClient.objects.create(
            server=self.server,
            name=name,
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            status=VPNClient.Status.ACTIVE,
            profile=profile,
            device=self.device,
            runtime_peer_public_key=(
                name + "-PUBLIC"
            ),
            runtime_address=address,
        )

        plaintext = (
            "[Interface]\n"
            "PrivateKey = TEST-PRIVATE\n"
            f"Address = {address}/32\n"
            "\n"
            "[Peer]\n"
            "PublicKey = TEST-SERVER-PUBLIC\n"
            "AllowedIPs = 0.0.0.0/0\n"
            "Endpoint = vpn.example.com:51830\n"
        )

        ClientConfigRevision.objects.create(
            client=client,
            revision_number=1,
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            config_blob_encrypted=(
                ConfigCryptoService.encrypt(
                    plaintext
                )
            ),
            config_hash=hashlib.sha256(
                plaintext.encode()
            ).hexdigest(),
        )

        return client

    def _home(self):
        self.client.force_login(
            self.user
        )

        return self.client.get(
            reverse(
                "customer-portal-home"
            )
        )

    def test_cabinet_groups_connections_by_device(
        self,
    ):
        response = self._home()

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Мои устройства",
        )

        self.assertContains(
            response,
            "AWG2 FULL",
        )

        self.assertContains(
            response,
            "AWG2 SELECTIVE",
        )

        self.assertContains(
            response,
            "VLESS / XHTTP",
        )

        workspace = (
            response.context[
                "workspace"
            ]
        )

        self.assertEqual(
            workspace["device_total"],
            1,
        )

        self.assertEqual(
            workspace["connection_total"],
            3,
        )

        self.assertEqual(
            workspace["full_total"],
            1,
        )

        self.assertEqual(
            workspace["selective_total"],
            1,
        )

        self.assertEqual(
            workspace["xhttp_total"],
            1,
        )

    def test_cabinet_hides_technical_names(
        self,
    ):
        response = self._home()

        self.assertNotContains(
            response,
            "TECHNICAL-FULL-CLIENT",
        )

        self.assertNotContains(
            response,
            "TECHNICAL-SELECT-CLIENT",
        )

        self.assertNotContains(
            response,
            "TECH-FULL-PROFILE",
        )

        self.assertNotContains(
            response,
            "TECH-SELECT-PROFILE",
        )

        self.assertNotContains(
            response,
            "TECHNICAL-XHTTP-NAME",
        )

        self.assertNotContains(
            response,
            "Technical Server Name",
        )

    def test_cabinet_shows_own_download_links_only(
        self,
    ):
        response = self._home()

        self.assertContains(
            response,
            reverse(
                "customer-portal-vpn-download",
                args=[self.full.pk],
            ),
        )

        self.assertContains(
            response,
            reverse(
                "customer-portal-vpn-download",
                args=[self.selective.pk],
            ),
        )

        self.assertContains(
            response,
            reverse(
                "customer-portal-xhttp-download",
                args=[self.xhttp.pk],
            ),
        )

        self.assertNotContains(
            response,
            "OTHER SECRET ACCOUNT",
        )

        self.assertNotContains(
            response,
            "OTHER SECRET DEVICE",
        )

        self.assertNotContains(
            response,
            "OTHER SECRET VPN",
        )

    def test_disabled_connection_is_visible_but_not_downloadable(
        self,
    ):
        self.selective.status = (
            VPNClient.Status.DISABLED
        )

        self.selective.save(
            update_fields=["status"]
        )

        response = self._home()

        selective_url = reverse(
            "customer-portal-vpn-download",
            args=[self.selective.pk],
        )

        self.assertContains(
            response,
            "AWG2 SELECTIVE",
        )

        self.assertContains(
            response,
            "Подключение отключено.",
        )

        self.assertNotContains(
            response,
            selective_url,
        )

    def test_disabled_account_keeps_connections_visible_without_secrets(
        self,
    ):
        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        response = self._home()

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "AWG2 FULL",
        )

        self.assertContains(
            response,
            "AWG2 SELECTIVE",
        )

        self.assertContains(
            response,
            "VLESS / XHTTP",
        )

        self.assertContains(
            response,
            "Скачивание временно недоступно",
        )

        self.assertNotContains(
            response,
            reverse(
                "customer-portal-vpn-download",
                args=[self.full.pk],
            ),
        )

        self.assertNotContains(
            response,
            reverse(
                "customer-portal-vpn-download",
                args=[self.selective.pk],
            ),
        )

        self.assertNotContains(
            response,
            reverse(
                "customer-portal-xhttp-download",
                args=[self.xhttp.pk],
            ),
        )
