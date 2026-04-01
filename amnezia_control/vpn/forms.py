from datetime import timedelta

from django import forms
from django.utils import timezone

from .models import VPNClient


class VPNClientCreateForm(forms.Form):
    EXPIRATION_PRESET_UNLIMITED = "unlimited"
    EXPIRATION_PRESET_CUSTOM = "custom"
    EXPIRATION_PRESET_TO_DELTA = {
        "1d": timedelta(days=1),
        "1w": timedelta(weeks=1),
        "1m": timedelta(days=30),
        "3m": timedelta(days=90),
        "6m": timedelta(days=180),
        "1y": timedelta(days=365),
    }

    TRAFFIC_PRESET_UNLIMITED = "unlimited"
    TRAFFIC_PRESET_CUSTOM = "custom"
    TRAFFIC_PRESET_TO_BYTES = {
        "1gb": 1024**3,
        "5gb": 5 * 1024**3,
        "10gb": 10 * 1024**3,
        "25gb": 25 * 1024**3,
        "50gb": 50 * 1024**3,
        "100gb": 100 * 1024**3,
    }

    TRAFFIC_UNIT_MB = "mb"
    TRAFFIC_UNIT_GB = "gb"
    TRAFFIC_UNIT_FACTORS = {
        TRAFFIC_UNIT_MB: 1024**2,
        TRAFFIC_UNIT_GB: 1024**3,
    }

    name = forms.CharField(label="Имя клиента", max_length=120)
    protocol_type = forms.ChoiceField(label="Протокол", choices=VPNClient.ProtocolType.choices)
    expires_preset = forms.ChoiceField(
        label="Срок действия",
        choices=(
            (EXPIRATION_PRESET_UNLIMITED, "Без ограничения"),
            ("1d", "1 день"),
            ("1w", "1 неделя"),
            ("1m", "1 месяц"),
            ("3m", "3 месяца"),
            ("6m", "6 месяцев"),
            ("1y", "1 год"),
            (EXPIRATION_PRESET_CUSTOM, "Свой срок"),
        ),
        initial=EXPIRATION_PRESET_UNLIMITED,
    )
    expires_at = forms.DateTimeField(
        required=False,
        label="Свой срок (дата и время)",
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
        input_formats=["%Y-%m-%dT%H:%M"],
    )
    traffic_limit_preset = forms.ChoiceField(
        label="Лимит трафика",
        choices=(
            (TRAFFIC_PRESET_UNLIMITED, "Без лимита"),
            ("1gb", "1 ГБ"),
            ("5gb", "5 ГБ"),
            ("10gb", "10 ГБ"),
            ("25gb", "25 ГБ"),
            ("50gb", "50 ГБ"),
            ("100gb", "100 ГБ"),
            (TRAFFIC_PRESET_CUSTOM, "Свой объём"),
        ),
        initial=TRAFFIC_PRESET_UNLIMITED,
    )
    traffic_custom_value = forms.IntegerField(
        required=False,
        min_value=1,
        label="Свой объём",
    )
    traffic_custom_unit = forms.ChoiceField(
        required=False,
        label="Единица",
        choices=((TRAFFIC_UNIT_MB, "МБ"), (TRAFFIC_UNIT_GB, "ГБ")),
        initial=TRAFFIC_UNIT_GB,
    )

    def clean(self):
        cleaned_data = super().clean()

        expires_preset = cleaned_data.get("expires_preset")
        custom_expires_at = cleaned_data.get("expires_at")
        if expires_preset == self.EXPIRATION_PRESET_CUSTOM:
            if not custom_expires_at:
                self.add_error("expires_at", "Укажите дату и время для собственного срока.")
            cleaned_data["expires_at"] = custom_expires_at
        elif expires_preset == self.EXPIRATION_PRESET_UNLIMITED:
            cleaned_data["expires_at"] = None
        else:
            delta = self.EXPIRATION_PRESET_TO_DELTA.get(expires_preset)
            if delta is None:
                self.add_error("expires_preset", "Выберите корректный пресет срока действия.")
            else:
                cleaned_data["expires_at"] = timezone.now() + delta

        traffic_preset = cleaned_data.get("traffic_limit_preset")
        custom_traffic_value = cleaned_data.get("traffic_custom_value")
        custom_traffic_unit = cleaned_data.get("traffic_custom_unit") or self.TRAFFIC_UNIT_GB
        if traffic_preset == self.TRAFFIC_PRESET_CUSTOM:
            if not custom_traffic_value:
                self.add_error("traffic_custom_value", "Укажите значение лимита для своего объёма.")
            else:
                factor = self.TRAFFIC_UNIT_FACTORS.get(custom_traffic_unit)
                if factor is None:
                    self.add_error("traffic_custom_unit", "Выберите корректную единицу измерения.")
                else:
                    cleaned_data["traffic_limit_bytes"] = custom_traffic_value * factor
        elif traffic_preset == self.TRAFFIC_PRESET_UNLIMITED:
            cleaned_data["traffic_limit_bytes"] = None
        else:
            bytes_value = self.TRAFFIC_PRESET_TO_BYTES.get(traffic_preset)
            if bytes_value is None:
                self.add_error("traffic_limit_preset", "Выберите корректный пресет лимита трафика.")
            else:
                cleaned_data["traffic_limit_bytes"] = bytes_value

        return cleaned_data


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
