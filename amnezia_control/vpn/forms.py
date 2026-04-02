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

    @classmethod
    def resolve_expires_at(cls, *, expires_preset, custom_expires_at):
        if expires_preset == cls.EXPIRATION_PRESET_CUSTOM:
            if not custom_expires_at:
                return None, "Укажите дату и время для собственного срока."
            return custom_expires_at, None
        if expires_preset == cls.EXPIRATION_PRESET_UNLIMITED:
            return None, None
        delta = cls.EXPIRATION_PRESET_TO_DELTA.get(expires_preset)
        if delta is None:
            return None, "Выберите корректный пресет срока действия."
        return timezone.now() + delta, None

    @classmethod
    def resolve_traffic_limit_bytes(cls, *, traffic_preset, custom_traffic_value, custom_traffic_unit):
        custom_traffic_unit = custom_traffic_unit or cls.TRAFFIC_UNIT_GB
        if traffic_preset == cls.TRAFFIC_PRESET_CUSTOM:
            if not custom_traffic_value:
                return None, "traffic_custom_value", "Укажите значение лимита для своего объёма."
            factor = cls.TRAFFIC_UNIT_FACTORS.get(custom_traffic_unit)
            if factor is None:
                return None, "traffic_custom_unit", "Выберите корректную единицу измерения."
            return custom_traffic_value * factor, None, None
        if traffic_preset == cls.TRAFFIC_PRESET_UNLIMITED:
            return None, None, None
        bytes_value = cls.TRAFFIC_PRESET_TO_BYTES.get(traffic_preset)
        if bytes_value is None:
            return None, "traffic_limit_preset", "Выберите корректный пресет лимита трафика."
        return bytes_value, None, None

    def _clean_limits(self, cleaned_data):
        expires_preset = cleaned_data.get("expires_preset")
        custom_expires_at = cleaned_data.get("expires_at")
        expires_at, expires_error = self.resolve_expires_at(expires_preset=expires_preset, custom_expires_at=custom_expires_at)
        if expires_error:
            self.add_error("expires_at" if expires_preset == self.EXPIRATION_PRESET_CUSTOM else "expires_preset", expires_error)
        cleaned_data["expires_at"] = expires_at

        traffic_preset = cleaned_data.get("traffic_limit_preset")
        custom_traffic_value = cleaned_data.get("traffic_custom_value")
        custom_traffic_unit = cleaned_data.get("traffic_custom_unit") or self.TRAFFIC_UNIT_GB
        traffic_limit_bytes, field_name, traffic_error = self.resolve_traffic_limit_bytes(
            traffic_preset=traffic_preset,
            custom_traffic_value=custom_traffic_value,
            custom_traffic_unit=custom_traffic_unit,
        )
        if traffic_error:
            self.add_error(field_name, traffic_error)
        cleaned_data["traffic_limit_bytes"] = traffic_limit_bytes

        return cleaned_data

    def clean(self):
        cleaned_data = super().clean()
        return self._clean_limits(cleaned_data)


class VPNClientLimitsUpdateForm(VPNClientCreateForm):
    name = None
    protocol_type = None

    def __init__(self, *args, client=None, **kwargs):
        super().__init__(*args, **kwargs)
        if client:
            self._init_from_client(client)

    def _init_from_client(self, client):
        if not self.is_bound:
            initial = self.initial
            if client.expires_at:
                initial["expires_preset"] = self.EXPIRATION_PRESET_CUSTOM
                local_dt = timezone.localtime(client.expires_at)
                initial["expires_at"] = local_dt.strftime("%Y-%m-%dT%H:%M")
            else:
                initial["expires_preset"] = self.EXPIRATION_PRESET_UNLIMITED

            if client.traffic_limit_bytes is None:
                initial["traffic_limit_preset"] = self.TRAFFIC_PRESET_UNLIMITED
            else:
                preset = next(
                    (key for key, value in self.TRAFFIC_PRESET_TO_BYTES.items() if value == client.traffic_limit_bytes),
                    self.TRAFFIC_PRESET_CUSTOM,
                )
                initial["traffic_limit_preset"] = preset
                if preset == self.TRAFFIC_PRESET_CUSTOM:
                    if client.traffic_limit_bytes % (1024**3) == 0:
                        initial["traffic_custom_unit"] = self.TRAFFIC_UNIT_GB
                        initial["traffic_custom_value"] = client.traffic_limit_bytes // (1024**3)
                    else:
                        initial["traffic_custom_unit"] = self.TRAFFIC_UNIT_MB
                        initial["traffic_custom_value"] = max(1, client.traffic_limit_bytes // (1024**2))

    def clean(self):
        cleaned_data = forms.Form.clean(self)
        return self._clean_limits(cleaned_data)


class VPNClientBulkLimitsUpdateForm(forms.Form):
    APPLY_KEEP = "keep"
    APPLY_SET = "set"
    APPLY_CLEAR = "clear"

    apply_expires = forms.ChoiceField(
        required=False,
        label="Срок действия",
        choices=(
            (APPLY_KEEP, "Не изменять"),
            (APPLY_SET, "Установить срок"),
            (APPLY_CLEAR, "Снять ограничение"),
        ),
        initial=APPLY_KEEP,
    )
    expires_preset = forms.ChoiceField(
        required=False,
        label="Пресет срока",
        choices=VPNClientCreateForm.base_fields["expires_preset"].choices,
        initial=VPNClientCreateForm.EXPIRATION_PRESET_UNLIMITED,
    )
    expires_at = forms.DateTimeField(
        required=False,
        label="Свой срок (дата и время)",
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
        input_formats=["%Y-%m-%dT%H:%M"],
    )

    apply_traffic = forms.ChoiceField(
        required=False,
        label="Лимит трафика",
        choices=(
            (APPLY_KEEP, "Не изменять"),
            (APPLY_SET, "Установить лимит"),
            (APPLY_CLEAR, "Снять ограничение"),
        ),
        initial=APPLY_KEEP,
    )
    traffic_limit_preset = forms.ChoiceField(
        required=False,
        label="Пресет трафика",
        choices=VPNClientCreateForm.base_fields["traffic_limit_preset"].choices,
        initial=VPNClientCreateForm.TRAFFIC_PRESET_UNLIMITED,
    )
    traffic_custom_value = forms.IntegerField(required=False, min_value=1, label="Свой объём")
    traffic_custom_unit = forms.ChoiceField(
        required=False,
        label="Единица",
        choices=VPNClientCreateForm.base_fields["traffic_custom_unit"].choices,
        initial=VPNClientCreateForm.TRAFFIC_UNIT_GB,
    )

    def clean(self):
        cleaned_data = super().clean()
        apply_expires = cleaned_data.get("apply_expires") or self.APPLY_KEEP
        apply_traffic = cleaned_data.get("apply_traffic") or self.APPLY_KEEP

        if apply_expires == self.APPLY_KEEP and apply_traffic == self.APPLY_KEEP:
            raise forms.ValidationError("Выберите хотя бы одно изменение лимитов.")

        if apply_expires == self.APPLY_SET:
            expires_at, error = VPNClientCreateForm.resolve_expires_at(
                expires_preset=cleaned_data.get("expires_preset"),
                custom_expires_at=cleaned_data.get("expires_at"),
            )
            if error:
                self.add_error(
                    "expires_at"
                    if cleaned_data.get("expires_preset") == VPNClientCreateForm.EXPIRATION_PRESET_CUSTOM
                    else "expires_preset",
                    error,
                )
            cleaned_data["resolved_expires_at"] = expires_at

        if apply_traffic == self.APPLY_SET:
            traffic_limit_bytes, field_name, error = VPNClientCreateForm.resolve_traffic_limit_bytes(
                traffic_preset=cleaned_data.get("traffic_limit_preset"),
                custom_traffic_value=cleaned_data.get("traffic_custom_value"),
                custom_traffic_unit=cleaned_data.get("traffic_custom_unit"),
            )
            if error:
                self.add_error(field_name, error)
            cleaned_data["resolved_traffic_limit_bytes"] = traffic_limit_bytes

        return cleaned_data


class VPNClientListFilterForm(forms.Form):
    STATUS_ALL = "__all__"

    QUICK_ACTIVE = "active"
    QUICK_DISABLED = "disabled"
    QUICK_EXPIRED = "expired"
    QUICK_TRAFFIC_EXCEEDED = "traffic_exceeded"
    QUICK_DELETED = "deleted"

    q = forms.CharField(required=False, label="Поиск", max_length=120)
    protocol = forms.ChoiceField(
        required=False,
        label="Протокол",
        choices=(("", "Все"),) + tuple(VPNClient.ProtocolType.choices),
    )
    status = forms.ChoiceField(
        required=False,
        label="Статус",
        choices=(
            ("", "Активные и отключенные"),
            (STATUS_ALL, "Все (включая удаленных)"),
        )
        + tuple(VPNClient.Status.choices),
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
    quick = forms.ChoiceField(
        required=False,
        label="Быстрый фильтр",
        choices=(
            ("", "Все"),
            (QUICK_ACTIVE, "Активные"),
            (QUICK_DISABLED, "Отключённые"),
            (QUICK_EXPIRED, "Просроченные"),
            (QUICK_TRAFFIC_EXCEEDED, "Трафик превышен"),
            (QUICK_DELETED, "Удалённые"),
        ),
    )
