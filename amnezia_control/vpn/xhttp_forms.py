from django import forms

from .models import VPNClient, XHTTPDevice


class XHTTPDeviceCreateForm(forms.Form):
    client = forms.ModelChoiceField(
        label="Клиент",
        queryset=VPNClient.objects.none(),
    )
    name = forms.CharField(
        label="Название устройства",
        max_length=120,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Например: iPhone — резервный доступ",
                "autocomplete": "off",
            }
        ),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["client"].queryset = (
            VPNClient.objects.exclude(status=VPNClient.Status.DELETED)
            .select_related("server")
            .order_by("name", "id")
        )

    def clean(self):
        cleaned_data = super().clean()
        client = cleaned_data.get("client")
        name = (cleaned_data.get("name") or "").strip()
        cleaned_data["name"] = name
        if client and name and XHTTPDevice.objects.filter(client=client, name=name).exists():
            self.add_error("name", "У этого клиента уже есть XHTTP-устройство с таким названием.")
        return cleaned_data
