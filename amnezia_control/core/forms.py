from django import forms

from .models import SystemSettings


class SystemSettingsForm(forms.ModelForm):
    class Meta:
        model = SystemSettings
        fields = ("portal_link_lifetime_days", "portal_renewal_cooldown_hours")
        labels = {
            "portal_link_lifetime_days": "Срок действия ссылки в кабинет (дней)",
            "portal_renewal_cooldown_hours": "Cooldown запроса продления (часов)",
        }
        widgets = {
            "portal_link_lifetime_days": forms.NumberInput(attrs={"class": "form-control", "min": 1, "max": 365}),
            "portal_renewal_cooldown_hours": forms.NumberInput(attrs={"class": "form-control", "min": 1, "max": 168}),
        }

