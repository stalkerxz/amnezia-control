from django import forms

from customers.models import ClientDevice, CustomerAccount
from servers.models import Server

from .models import VPNClient, XHTTPDevice


class XHTTPDeviceCreateForm(forms.Form):
    device = forms.ModelChoiceField(
        label="Устройство",
        queryset=ClientDevice.objects.none(),
        required=False,
    )

    server = forms.ModelChoiceField(
        label="Сервер",
        queryset=Server.objects.none(),
        required=False,
    )

    # Transitional compatibility field.
    # It is not rendered in the new UI, but keeps old POST/API callers
    # functional during Phase 4.
    client = forms.ModelChoiceField(
        label="Legacy VPN-клиент",
        queryset=VPNClient.objects.none(),
        required=False,
        widget=forms.HiddenInput(),
    )

    name = forms.CharField(
        label="Название подключения",
        max_length=120,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Например: VLESS CDN",
                "autocomplete": "off",
            }
        ),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["device"].queryset = (
            ClientDevice.objects
            .filter(
                status=ClientDevice.Status.ACTIVE,
                account__status=CustomerAccount.Status.ACTIVE,
            )
            .select_related("account")
            .order_by(
                "account__display_name",
                "name",
                "id",
            )
        )

        self.fields["server"].queryset = (
            Server.objects
            .filter(is_enabled=True)
            .order_by("name", "id")
        )

        self.fields["client"].queryset = (
            VPNClient.objects
            .exclude(status=VPNClient.Status.DELETED)
            .select_related("server", "device")
            .order_by("name", "id")
        )

    def clean(self):
        cleaned_data = super().clean()

        device = cleaned_data.get("device")
        server = cleaned_data.get("server")
        client = cleaned_data.get("client")

        name = (
            cleaned_data.get("name")
            or ""
        ).strip()

        cleaned_data["name"] = name

        if device is not None:
            if server is None:
                self.add_error(
                    "server",
                    "Выберите сервер XHTTP.",
                )

            if (
                device.account.expires_at is not None
                and device.account.expires_at
                <= __import__(
                    "django.utils.timezone",
                    fromlist=["now"],
                ).now()
            ):
                self.add_error(
                    "device",
                    "Срок действия аккаунта истёк.",
                )

            if (
                name
                and XHTTPDevice.objects.filter(
                    device=device,
                    name=name,
                ).exists()
            ):
                self.add_error(
                    "name",
                    "У этого устройства уже есть "
                    "XHTTP-подключение с таким названием.",
                )

        elif client is not None:
            if (
                name
                and XHTTPDevice.objects.filter(
                    client=client,
                    name=name,
                ).exists()
            ):
                self.add_error(
                    "name",
                    "У этого VPN-клиента уже есть "
                    "XHTTP-подключение с таким названием.",
                )

        else:
            self.add_error(
                "device",
                "Выберите устройство.",
            )

        return cleaned_data
