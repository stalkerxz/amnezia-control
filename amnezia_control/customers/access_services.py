from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from audit.services import AuditService

from .models import CustomerAccount


User = get_user_model()


class CustomerAccessError(ValueError):
    pass


@transaction.atomic
def create_customer_login(
    *,
    account_id,
    username,
    password,
    actor,
):
    account = (
        CustomerAccount.objects
        .select_for_update()
        .get(pk=account_id)
    )

    if account.status == CustomerAccount.Status.DELETED:
        raise CustomerAccessError(
            "Нельзя создавать кабинет "
            "для удалённого аккаунта."
        )

    if account.user_id is not None:
        raise CustomerAccessError(
            "У аккаунта уже есть клиентский логин."
        )

    username = (username or "").strip()

    if not username:
        raise CustomerAccessError(
            "Логин не может быть пустым."
        )

    if User.objects.filter(
        username__iexact=username,
    ).exists():
        raise CustomerAccessError(
            "Пользователь с таким логином уже существует."
        )

    user = User(
        username=username,
        email=account.email or "",
        is_owner=False,
        is_staff=False,
        is_superuser=False,
        is_active=True,
    )

    user.set_password(password)
    user.save()

    account.user = user
    account.updated_at = timezone.now()

    account.save(
        update_fields=[
            "user",
            "updated_at",
        ]
    )

    AuditService.log(
        actor,
        "customer.login.create",
        "CustomerAccount",
        account.pk,
        {
            "user_id": user.pk,
            "username": user.username,
        },
    )

    return user


def _locked_customer_login(
    *,
    account_id,
):
    account = (
        CustomerAccount.objects
        .select_for_update()
        .get(pk=account_id)
    )

    if (
        account.status
        == CustomerAccount.Status.DELETED
    ):
        raise CustomerAccessError(
            "Удалённым аккаунтом управлять нельзя."
        )

    if account.user_id is None:
        raise CustomerAccessError(
            "У аккаунта нет клиентского логина."
        )

    user = (
        User.objects
        .select_for_update()
        .get(pk=account.user_id)
    )

    if (
        getattr(user, "is_owner", False)
        or user.is_staff
        or user.is_superuser
    ):
        raise CustomerAccessError(
            "К аккаунту привязана операторская "
            "учётная запись. Автоматическое "
            "управление запрещено."
        )

    return account, user


@transaction.atomic
def change_customer_password(
    *,
    account_id,
    password,
    actor,
):
    account, user = _locked_customer_login(
        account_id=account_id,
    )

    user.set_password(password)

    user.save(
        update_fields=[
            "password",
        ]
    )

    AuditService.log(
        actor,
        "customer.login.password_reset",
        "CustomerAccount",
        account.pk,
        {
            "user_id": user.pk,
            "username": user.username,
        },
    )

    return user


@transaction.atomic
def set_customer_login_enabled(
    *,
    account_id,
    enabled,
    actor,
):
    account, user = _locked_customer_login(
        account_id=account_id,
    )

    enabled = bool(enabled)

    if user.is_active != enabled:
        user.is_active = enabled

        user.save(
            update_fields=[
                "is_active",
            ]
        )

        AuditService.log(
            actor,
            (
                "customer.login.enable"
                if enabled
                else "customer.login.disable"
            ),
            "CustomerAccount",
            account.pk,
            {
                "user_id": user.pk,
                "username": user.username,
            },
        )

    return user


@transaction.atomic
def detach_customer_login(
    *,
    account_id,
    actor,
):
    account, user = _locked_customer_login(
        account_id=account_id,
    )

    user_id = user.pk
    username = user.username

    # Revoke the credentials first.
    user.is_active = False
    user.set_unusable_password()

    user.save(
        update_fields=[
            "is_active",
            "password",
        ]
    )

    # Then remove only the identity binding.
    # Devices and protocol configurations belong to CustomerAccount /
    # ClientDevice and are intentionally untouched.
    account.user = None
    account.updated_at = timezone.now()

    account.save(
        update_fields=[
            "user",
            "updated_at",
        ]
    )

    AuditService.log(
        actor,
        "customer.login.detach",
        "CustomerAccount",
        account.pk,
        {
            "user_id": user_id,
            "username": username,
        },
    )

    return user
