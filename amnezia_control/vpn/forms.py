from django import forms

from .models import VPNClient


class VPNClientCreateForm(forms.Form):
    name = forms.CharField(
        label="Имя клиента",
        max_length=120,
        help_text="Используйте короткое понятное имя для оператора (например, ivan-phone).",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Например: ivan-macbook"}),
    )
    protocol_type = forms.ChoiceField(
        label="Протокол",
        choices=VPNClient.ProtocolType.choices,
        help_text="AWG2 рекомендуется для новых клиентов. AWG оставлен для совместимости.",
        widget=forms.Select(attrs={"class": "form-select"}),
    )
