from django import forms

from .models import VPNClient


class VPNClientCreateForm(forms.Form):
    name = forms.CharField(label="Имя клиента", max_length=120)
    protocol_type = forms.ChoiceField(label="Протокол", choices=VPNClient.ProtocolType.choices)
    expires_at = forms.DateTimeField(
        required=False,
        label="Ограничить по времени (до)",
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
        input_formats=["%Y-%m-%dT%H:%M"],
    )
    traffic_limit_bytes = forms.IntegerField(
        required=False,
        min_value=1,
        label="Лимит трафика (байт)",
        help_text="Оставьте пустым, если лимит трафика не нужен.",
    )


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
