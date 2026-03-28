from django import forms

from .models import VPNClient


class VPNClientCreateForm(forms.Form):
    name = forms.CharField(label="Имя клиента", max_length=120)
    protocol_type = forms.ChoiceField(label="Протокол", choices=VPNClient.ProtocolType.choices)


class VPNClientListFilterForm(forms.Form):
    q = forms.CharField(required=False, label="Поиск", max_length=120)
    protocol = forms.ChoiceField(
        required=False,
        label="Протокол",
        choices=(("", "Все"),) + tuple(VPNClient.ProtocolType.choices),
    )
    status = forms.ChoiceField(
        required=False,
        label="Статус",
        choices=(("", "Все"),) + tuple(VPNClient.Status.choices),
    )
    source = forms.ChoiceField(
        required=False,
        label="Источник",
        choices=(
            ("", "Все"),
            ("imported", "Импорт"),
            ("manual", "Панель"),
        ),
    )
