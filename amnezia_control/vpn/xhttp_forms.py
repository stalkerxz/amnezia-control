from django import forms
from django.utils import timezone

from customers.models import (
    ClientDevice,
    CustomerAccount,
)
from servers.models import Server

from .models import XHTTPDevice


class XHTTPDeviceCreateForm(forms.Form):
    device = forms.ModelChoiceField(
        label="Устройство",
        queryset=ClientDevice.objects.none(),
    )

    server = forms.ModelChoiceField(
        label="Сервер",
        queryset=Server.objects.none(),
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
        super().__init__(
            *args,
            **kwargs,
        )

        self.fields["device"].queryset = (
            ClientDevice.objects
            .filter(
                status=(
                    ClientDevice.Status.ACTIVE
                ),
                account__status=(
                    CustomerAccount.Status.ACTIVE
                ),
            )
            .select_related(
                "account",
            )
            .order_by(
                "account__display_name",
                "name",
                "id",
            )
        )

        self.fields["server"].queryset = (
            Server.objects
            .filter(
                is_enabled=True,
            )
            .order_by(
                "name",
                "id",
            )
        )

    def clean(self):
        cleaned_data = super().clean()

        device = cleaned_data.get(
            "device"
        )

        name = (
            cleaned_data.get("name")
            or ""
        ).strip()

        cleaned_data["name"] = name

        if device is None:
            return cleaned_data

        if (
            device.account.expires_at
            is not None
            and device.account.expires_at
            <= timezone.now()
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
                (
                    "У этого устройства уже есть "
                    "XHTTP-подключение "
                    "с таким названием."
                ),
            )

        return cleaned_data
