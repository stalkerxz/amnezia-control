from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import (
    validate_password,
)
from django.core.exceptions import ValidationError

from .models import ClientDevice, CustomerAccount


User = get_user_model()


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


class CustomerAccountEditForm(forms.ModelForm):
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
                    "autofocus": True,
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control",
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
        value = (
            self.cleaned_data.get(
                "display_name"
            )
            or ""
        ).strip()

        if not value:
            raise forms.ValidationError(
                "Укажите имя клиента."
            )

        return value

    def clean_email(self):
        return (
            self.cleaned_data.get("email")
            or ""
        ).strip()


class ClientDeviceEditForm(forms.ModelForm):
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
                }
            ),
        }

    def clean_name(self):
        value = (
            self.cleaned_data.get("name")
            or ""
        ).strip()

        if not value:
            raise forms.ValidationError(
                "Укажите название устройства."
            )

        return value

    def clean_notes(self):
        return (
            self.cleaned_data.get("notes")
            or ""
        ).strip()

class CustomerOnboardingForm(forms.Form):
    display_name = forms.CharField(
        label="Имя клиента",
        max_length=200,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Например: Иван Иванов",
                "autofocus": True,
            }
        ),
    )

    email = forms.EmailField(
        label="Email",
        required=False,
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "client@example.com",
            }
        ),
    )

    expires_at = forms.DateTimeField(
        label="Срок аккаунта",
        required=False,
        input_formats=[
            "%Y-%m-%dT%H:%M",
        ],
        widget=forms.DateTimeInput(
            attrs={
                "class": "form-control",
                "type": "datetime-local",
            },
            format="%Y-%m-%dT%H:%M",
        ),
    )

    device_name = forms.CharField(
        label="Название устройства",
        max_length=200,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Например: iPhone 15 Pro",
            }
        ),
    )

    device_platform = forms.ChoiceField(
        label="Платформа",
        choices=ClientDevice.Platform.choices,
        widget=forms.Select(
            attrs={
                "class": "form-select",
            }
        ),
    )

    device_notes = forms.CharField(
        label="Заметка об устройстве",
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 2,
                "placeholder": (
                    "Необязательно. Например: основной телефон"
                ),
            }
        ),
    )

    create_login = forms.BooleanField(
        label="Создать личный кабинет",
        required=False,
        initial=True,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
            }
        ),
    )

    username = forms.CharField(
        label="Логин",
        required=False,
        max_length=150,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "autocomplete": "off",
                "placeholder": (
                    "Можно оставить пустым — будет использован Email"
                ),
            }
        ),
    )

    password1 = forms.CharField(
        label="Пароль",
        required=False,
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "new-password",
            }
        ),
    )

    password2 = forms.CharField(
        label="Повторите пароль",
        required=False,
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "new-password",
            }
        ),
    )

    def clean_display_name(self):
        value = (
            self.cleaned_data.get("display_name")
            or ""
        ).strip()

        if not value:
            raise forms.ValidationError(
                "Укажите имя клиента."
            )

        return value

    def clean_email(self):
        return (
            self.cleaned_data.get("email")
            or ""
        ).strip()

    def clean_device_name(self):
        value = (
            self.cleaned_data.get("device_name")
            or ""
        ).strip()

        if not value:
            raise forms.ValidationError(
                "Укажите название устройства."
            )

        return value

    def clean_device_notes(self):
        return (
            self.cleaned_data.get("device_notes")
            or ""
        ).strip()

    def clean(self):
        cleaned_data = super().clean()

        if not cleaned_data.get("create_login"):
            cleaned_data["username"] = ""
            return cleaned_data

        email = (
            cleaned_data.get("email")
            or ""
        ).strip()

        username = (
            cleaned_data.get("username")
            or email
        ).strip()

        if not username:
            self.add_error(
                "username",
                (
                    "Для личного кабинета укажите логин "
                    "или Email клиента."
                ),
            )

            return cleaned_data

        if User.objects.filter(
            username__iexact=username,
        ).exists():
            self.add_error(
                "username",
                "Пользователь с таким логином уже существует.",
            )

        cleaned_data["username"] = username

        password1 = cleaned_data.get(
            "password1"
        )

        password2 = cleaned_data.get(
            "password2"
        )

        if not password1:
            self.add_error(
                "password1",
                "Укажите пароль для личного кабинета.",
            )

        if not password2:
            self.add_error(
                "password2",
                "Повторите пароль.",
            )

        if (
            not password1
            or not password2
        ):
            return cleaned_data

        if password1 != password2:
            self.add_error(
                "password2",
                "Пароли не совпадают.",
            )

            return cleaned_data

        candidate = User(
            username=username,
            email=email,
            is_owner=False,
            is_staff=False,
            is_superuser=False,
        )

        try:
            validate_password(
                password1,
                user=candidate,
            )

        except ValidationError as exc:
            self.add_error(
                "password1",
                exc,
            )

        return cleaned_data
