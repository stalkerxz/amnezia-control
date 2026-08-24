from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)

from .forms import (
    VPNClientCreateForm,
    client_creation_servers,
)
from .models import VPNClient


class MultiServerClientCreateTests(TestCase):
    def make_ready_server(
        self,
        *,
        name,
        host,
        is_default=False,
        is_enabled=True,
    ):
        server = Server.objects.create(
            name=name,
            host=host,
            public_endpoint_host=host,
            public_endpoint_port=12345,
            is_enabled=is_enabled,
            is_default_for_new_clients=is_default,
        )

        protocol = ServerProtocol.objects.create(
            server=server,
            protocol_type=(
                ServerProtocol.ProtocolType.AWG2
            ),
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
            runtime_metadata={
                "subnet": "10.8.1.0/24",
                "udp_port": 12345,
            },
        )

        ProtocolProfile.objects.create(
            server_protocol=protocol,
            name="FULL",
            protocol_type=(
                ServerProtocol.ProtocolType.AWG2
            ),
            config_template=(
                "# routing-mode: full\n"
            ),
            status=(
                ProtocolProfile.ProfileStatus.ACTIVE
            ),
        )

        return server

    def test_default_server_is_ordered_first(self):
        old = self.make_ready_server(
            name="Old",
            host="203.0.113.10",
        )
        new = self.make_ready_server(
            name="New",
            host="203.0.113.20",
            is_default=True,
        )

        ids = list(
            client_creation_servers()
            .values_list("id", flat=True)
        )

        self.assertEqual(ids[0], new.id)
        self.assertIn(old.id, ids)

    def test_disabled_default_server_is_excluded(self):
        disabled = self.make_ready_server(
            name="Disabled",
            host="203.0.113.30",
            is_default=True,
            is_enabled=False,
        )
        active = self.make_ready_server(
            name="Active",
            host="203.0.113.40",
        )

        ids = list(
            client_creation_servers()
            .values_list("id", flat=True)
        )

        self.assertNotIn(disabled.id, ids)
        self.assertEqual(ids, [active.id])

    def test_form_uses_selected_server(self):
        server = self.make_ready_server(
            name="Selected",
            host="203.0.113.50",
            is_default=True,
        )

        form = VPNClientCreateForm(
            data={
                "server": str(server.id),
                "name": "test-client",
                "contact_email": "",
                "protocol_type": (
                    VPNClient.ProtocolType.AWG2
                ),
                "routing_mode": "full",
                "expires_preset": "unlimited",
                "expires_at": "",
                "traffic_limit_preset": "unlimited",
                "traffic_custom_value": "",
                "traffic_custom_unit": "gb",
            },
            server=server,
        )

        self.assertTrue(
            form.is_valid(),
            form.errors.as_json(),
        )
        self.assertEqual(
            form.cleaned_data["server"],
            server,
        )

    def test_create_view_passes_selected_server(self):
        default = self.make_ready_server(
            name="Default",
            host="203.0.113.80",
            is_default=True,
        )
        selected = self.make_ready_server(
            name="Selected",
            host="203.0.113.81",
        )

        User = get_user_model()
        user = User.objects.create_user(
            username="operator",
            password="test-password",
            is_staff=True,
        )

        self.client.force_login(user)

        with (
            patch(
                "vpn.middleware."
                "ClientCreationPreflightService.check"
            ) as middleware_check,
            patch(
                "vpn.views."
                "VPNClientService.create_client"
            ) as create_client,
        ):
            middleware_check.return_value = {
                "ready": True,
                "checks": [],
            }

            created = type(
                "CreatedClient",
                (),
                {"id": 999},
            )()

            create_client.return_value = created

            response = self.client.post(
                reverse("clients-create"),
                {
                    "server": str(selected.id),
                    "name": "selected-server-client",
                    "contact_email": "",
                    "protocol_type": (
                        VPNClient.ProtocolType.AWG2
                    ),
                    "routing_mode": "full",
                    "expires_preset": "unlimited",
                    "expires_at": "",
                    "traffic_limit_preset": "unlimited",
                    "traffic_custom_value": "",
                    "traffic_custom_unit": "gb",
                },
            )

        self.assertEqual(response.status_code, 302)

        middleware_check.assert_called_once()

        middleware_kwargs = (
            middleware_check.call_args.kwargs
        )

        self.assertEqual(
            middleware_kwargs["server"],
            selected,
        )

        create_client.assert_called_once()

        kwargs = create_client.call_args.kwargs

        self.assertEqual(
            kwargs["server"],
            selected,
        )

        self.assertNotEqual(
            kwargs["server"],
            default,
        )

    def test_preflight_uses_selected_server(self):
        default = self.make_ready_server(
            name="Default",
            host="203.0.113.90",
            is_default=True,
        )
        selected = self.make_ready_server(
            name="Selected",
            host="203.0.113.91",
        )

        User = get_user_model()
        user = User.objects.create_user(
            username="preflight-operator",
            password="test-password",
            is_staff=True,
        )

        self.client.force_login(user)

        with patch(
            "vpn.preflight_views."
            "ClientCreationPreflightService.check"
        ) as check:
            check.return_value = {
                "ready": True,
                "checks": [],
            }

            response = self.client.get(
                reverse("clients-preflight"),
                {
                    "server_id": str(selected.id),
                    "protocol": (
                        VPNClient.ProtocolType.AWG2
                    ),
                },
            )

        self.assertEqual(response.status_code, 200)

        check.assert_called_once_with(
            server=selected,
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            include_live=True,
        )

        self.assertNotEqual(
            selected,
            default,
        )

    def test_form_initial_server_is_explicit(self):
        first = self.make_ready_server(
            name="First",
            host="203.0.113.60",
        )
        selected = self.make_ready_server(
            name="Selected",
            host="203.0.113.70",
            is_default=True,
        )

        form = VPNClientCreateForm(
            server=selected,
        )

        self.assertEqual(
            form.fields["server"].initial,
            selected.pk,
        )

        queryset_ids = set(
            form.fields["server"]
            .queryset
            .values_list("id", flat=True)
        )

        self.assertEqual(
            queryset_ids,
            {first.id, selected.id},
        )
