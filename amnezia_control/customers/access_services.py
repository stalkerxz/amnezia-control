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
