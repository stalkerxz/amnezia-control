from django.db import transaction
from django.utils import timezone

from .models import ClientDevice, CustomerAccount


class CustomerAccountOperationError(ValueError):
    pass


@transaction.atomic
def move_device_to_account(*, device_id, target_account_id):
    # Сначала определяем текущий аккаунт без блокировки.
    # Все изменяющие операции ниже используют единый порядок:
    # CustomerAccount -> ClientDevice.
    source_account_id = (
        ClientDevice.objects
        .values_list("account_id", flat=True)
        .get(pk=device_id)
    )

    locked_accounts = {
        account.pk: account
        for account in (
            CustomerAccount.objects
            .select_for_update()
            .filter(
                pk__in=[
                    source_account_id,
                    target_account_id,
                ]
            )
            .order_by("pk")
        )
    }

    if target_account_id not in locked_accounts:
        raise CustomerAccount.DoesNotExist(
            "Целевой аккаунт не существует."
        )

    target = locked_accounts[target_account_id]

    if target.status == CustomerAccount.Status.DELETED:
        raise CustomerAccountOperationError(
            "Нельзя переносить устройство в удалённый аккаунт."
        )

    device = (
        ClientDevice.objects
        .select_for_update()
        .get(pk=device_id)
    )

    # Если между первым чтением и получением блокировок устройство
    # успели перенести в третий аккаунт, не продолжаем операцию
    # с неполным набором блокировок.
    if device.account_id not in locked_accounts:
        raise CustomerAccountOperationError(
            "Устройство было перемещено параллельно. "
            "Повторите операцию."
        )

    if device.account_id == target.pk:
        return device

    device.account_id = target.pk
    device.updated_at = timezone.now()
    device.save(
        update_fields=[
            "account",
            "updated_at",
        ]
    )

    return device


@transaction.atomic
def merge_customer_accounts(*, source_account_id, target_account_id):
    if source_account_id == target_account_id:
        raise CustomerAccountOperationError(
            "Нельзя объединить аккаунт сам с собой."
        )

    locked_accounts = {
        account.pk: account
        for account in (
            CustomerAccount.objects
            .select_for_update()
            .filter(
                pk__in=[
                    source_account_id,
                    target_account_id,
                ]
            )
            .order_by("pk")
        )
    }

    if (
        source_account_id not in locked_accounts
        or target_account_id not in locked_accounts
    ):
        raise CustomerAccount.DoesNotExist(
            "Один из аккаунтов не существует."
        )

    source = locked_accounts[source_account_id]
    target = locked_accounts[target_account_id]

    if target.status == CustomerAccount.Status.DELETED:
        raise CustomerAccountOperationError(
            "Нельзя объединять в удалённый аккаунт."
        )

    # Пока клиентская авторизация ещё не перенесена на CustomerAccount,
    # не пытаемся автоматически решать конфликт владельцев логина.
    if source.user_id is not None:
        raise CustomerAccountOperationError(
            "Исходный аккаунт привязан к пользователю. "
            "Автоматическое объединение запрещено."
        )

    now = timezone.now()

    device_ids = list(
        ClientDevice.objects
        .select_for_update()
        .filter(account_id=source.pk)
        .order_by("pk")
        .values_list("pk", flat=True)
    )

    if device_ids:
        ClientDevice.objects.filter(
            pk__in=device_ids
        ).update(
            account_id=target.pk,
            updated_at=now,
        )

    # Исходный аккаунт сохраняем как tombstone.
    # Это позволяет видеть историю объединения и не уничтожает запись.
    source.status = CustomerAccount.Status.DELETED
    source.updated_at = now
    source.save(
        update_fields=[
            "status",
            "updated_at",
        ]
    )

    return len(device_ids)
