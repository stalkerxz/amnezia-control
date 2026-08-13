from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import (
    validate_password,
)
from django.core.exceptions import ValidationError


User = get_user_model()


class CustomerAccessCreateForm(forms.Form):
    username = forms.CharField(
        label="Логин",
        max_length=150,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "autocomplete": "off",
                "autofocus": True,
            }
        ),
    )

    password1 = forms.CharField(
        label="Пароль",
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
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "new-password",
            }
        ),
    )

    def __init__(self, *args, account=None, **kwargs):
        super().__init__(*args, **kwargs)

        self.account = account

        if (
            not self.is_bound
            and account is not None
            and account.email
        ):
            self.fields["username"].initial = (
                account.email
            )

    def clean_username(self):
        username = (
            self.cleaned_data.get("username")
            or ""
        ).strip()

        if not username:
            raise forms.ValidationError(
                "Укажите логин."
            )

        if User.objects.filter(
            username__iexact=username,
        ).exists():
            raise forms.ValidationError(
                "Пользователь с таким логином уже существует."
            )

        return username

    def clean(self):
        cleaned_data = super().clean()

        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if not password1 or not password2:
            return cleaned_data

        if password1 != password2:
            self.add_error(
                "password2",
                "Пароли не совпадают.",
            )
            return cleaned_data

        username = (
            cleaned_data.get("username")
            or ""
        )

        candidate = User(
            username=username,
            email=(
                self.account.email
                if self.account is not None
                else ""
            ),
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
