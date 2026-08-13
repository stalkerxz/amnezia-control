from django import forms

from .models import ClientDevice, CustomerAccount


class CustomerAccountCreateForm(forms.ModelForm):
    class Meta:
        model = CustomerAccount
        fields = (
            "display_name",
            "email",
            "expires_at",
        )
        labels = {
            "display_name": "Имя клиента",
            "email": "Email",
            "expires_at": "Срок аккаунта",
        }
        widgets = {
            "display_name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Например: Иван Иванов",
                    "autofocus": True,
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "client@example.com",
                }
            ),
            "expires_at": forms.DateTimeInput(
                attrs={
                    "class": "form-control",
                    "type": "datetime-local",
                },
                format="%Y-%m-%dT%H:%M",
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["expires_at"].required = False
        self.fields["expires_at"].input_formats = [
            "%Y-%m-%dT%H:%M",
        ]

    def clean_display_name(self):
        value = (self.cleaned_data.get("display_name") or "").strip()

        if not value:
            raise forms.ValidationError(
                "Укажите имя клиента."
            )

        return value

    def clean_email(self):
        return (self.cleaned_data.get("email") or "").strip()


class ClientDeviceCreateForm(forms.ModelForm):
    class Meta:
        model = ClientDevice
        fields = (
            "name",
            "platform",
            "notes",
        )
        labels = {
            "name": "Название устройства",
            "platform": "Платформа",
            "notes": "Заметка",
        }
        widgets = {
            "name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Например: iPhone 15 Pro",
                    "autofocus": True,
                }
            ),
            "platform": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "notes": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 3,
                    "placeholder": (
                        "Необязательно. Например: "
                        "основной телефон"
                    ),
                }
            ),
        }

    def clean_name(self):
        value = (self.cleaned_data.get("name") or "").strip()

        if not value:
            raise forms.ValidationError(
                "Укажите название устройства."
            )

        return value

    def clean_notes(self):
        return (self.cleaned_data.get("notes") or "").strip()
