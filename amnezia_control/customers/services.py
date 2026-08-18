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
    """
    Merge one CustomerAccount into another without touching VPN identity.

    Target account becomes the canonical logical owner.

    Preserved:
    - VPNClient rows;
    - peer keys / runtime addresses;
    - config revisions;
    - XHTTP UUID/config identity;
    - renewal history;
    - legacy portal links.

    Reassigned:
    - ClientDevice.account;
    - ClientPortalAccess.account;
    - ClientRenewalRequest.account.

    Source account remains as a DELETED tombstone.
    """

    from portal.models import (
        ClientPortalAccess,
        ClientRenewalRequest,
    )

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

    source = locked_accounts[
        source_account_id
    ]

    target = locked_accounts[
        target_account_id
    ]

    if (
        source.status
        == CustomerAccount.Status.DELETED
    ):
        raise CustomerAccountOperationError(
            "Удалённый исходный аккаунт "
            "нельзя объединить повторно."
        )

    if (
        target.status
        == CustomerAccount.Status.DELETED
    ):
        raise CustomerAccountOperationError(
            "Нельзя объединять "
            "в удалённый аккаунт."
        )

    # Не решаем конфликт двух пользовательских кабинетов
    # автоматически.
    if source.user_id is not None:
        raise CustomerAccountOperationError(
            "Исходный аккаунт привязан "
            "к пользователю. "
            "Автоматическое объединение запрещено."
        )

    devices = list(
        ClientDevice.objects
        .select_for_update()
        .filter(
            account_id=source.pk,
        )
        .order_by("pk")
    )

    portal_accesses = list(
        ClientPortalAccess.objects
        .select_for_update()
        .filter(
            account_id=source.pk,
        )
        .order_by("pk")
    )

    renewal_rows = list(
        ClientRenewalRequest.objects
        .select_for_update()
        .filter(
            account_id__in=[
                source.pk,
                target.pk,
            ]
        )
        .order_by("pk")
    )

    open_statuses = {
        ClientRenewalRequest.Status.NEW,
        ClientRenewalRequest.Status.IN_PROGRESS,
    }

    source_open = [
        item
        for item in renewal_rows
        if (
            item.account_id == source.pk
            and item.status in open_statuses
        )
    ]

    target_open = [
        item
        for item in renewal_rows
        if (
            item.account_id == target.pk
            and item.status in open_statuses
        )
    ]

    # После merge существует уникальное ограничение:
    # один open renewal на account.
    #
    # Не выбираем победителя автоматически, потому что это
    # уже бизнес-решение оператора.
    if source_open and target_open:
        raise CustomerAccountOperationError(
            "У обоих аккаунтов есть открытые "
            "заявки на продление. "
            "Сначала обработайте одну из заявок."
        )

    now = timezone.now()

    # Используем save(), а не queryset.update(), чтобы
    # post_save lifecycle signals увидели смену владельца.
    for device in devices:
        device.account_id = target.pk
        device.updated_at = now

        device.save(
            update_fields=[
                "account",
                "updated_at",
            ]
        )

    if portal_accesses:
        ClientPortalAccess.objects.filter(
            pk__in=[
                item.pk
                for item in portal_accesses
            ]
        ).update(
            account_id=target.pk,
        )

    source_renewal_ids = [
        item.pk
        for item in renewal_rows
        if item.account_id == source.pk
    ]

    if source_renewal_ids:
        ClientRenewalRequest.objects.filter(
            pk__in=source_renewal_ids,
        ).update(
            account_id=target.pk,
            updated_at=now,
        )

    # Исходный аккаунт сохраняется как tombstone.
    source.status = (
        CustomerAccount.Status.DELETED
    )

    source.updated_at = now

    source.save(
        update_fields=[
            "status",
            "updated_at",
        ]
    )

    return len(devices)
