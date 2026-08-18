from django.db import transaction
from django.utils import timezone

from audit.services import AuditService
from vpn.tasks import (
    reconcile_vpn_account_task,
    reconcile_vpn_device_task,
    reconcile_xhttp_account_task,
    reconcile_xhttp_device_task,
)

from .models import (
    ClientDevice,
    CustomerAccount,
)


class CustomerStatusOperationError(
    RuntimeError
):
    pass


def _validate_result(
    *,
    label,
    result,
):
    errors = (
        result.get("errors")
        if isinstance(result, dict)
        else None
    )

    if errors:
        raise CustomerStatusOperationError(
            f"{label}: {errors}"
        )


def _reconcile_account(
    account_id,
):
    vpn = (
        reconcile_vpn_account_task
        .run(
            account_id
        )
    )

    _validate_result(
        label="VPN reconcile",
        result=vpn,
    )

    xhttp = (
        reconcile_xhttp_account_task
        .run(
            account_id
        )
    )

    _validate_result(
        label="XHTTP reconcile",
        result=xhttp,
    )

    return {
        "vpn": vpn,
        "xhttp": xhttp,
    }


def _reconcile_device(
    device_id,
):
    vpn = (
        reconcile_vpn_device_task
        .run(
            device_id
        )
    )

    _validate_result(
        label="VPN reconcile",
        result=vpn,
    )

    xhttp = (
        reconcile_xhttp_device_task
        .run(
            device_id
        )
    )

    _validate_result(
        label="XHTTP reconcile",
        result=xhttp,
    )

    return {
        "vpn": vpn,
        "xhttp": xhttp,
    }


def _restore_account_status(
    *,
    account_id,
    previous_status,
):
    with transaction.atomic():
        account = (
            CustomerAccount.objects
            .select_for_update()
            .get(
                pk=account_id
            )
        )

        account.status = (
            previous_status
        )

        account.updated_at = (
            timezone.now()
        )

        account.save(
            update_fields=[
                "status",
                "updated_at",
            ]
        )

    try:
        _reconcile_account(
            account_id
        )
    except Exception:
        pass


def _restore_device_status(
    *,
    device_id,
    previous_status,
):
    with transaction.atomic():
        device = (
            ClientDevice.objects
            .select_for_update()
            .get(
                pk=device_id
            )
        )

        device.status = (
            previous_status
        )

        device.updated_at = (
            timezone.now()
        )

        device.save(
            update_fields=[
                "status",
                "updated_at",
            ]
        )

    try:
        _reconcile_device(
            device_id
        )
    except Exception:
        pass


def set_customer_account_status(
    *,
    account_id,
    target_status,
    actor,
):
    allowed = {
        CustomerAccount.Status.ACTIVE,
        CustomerAccount.Status.DISABLED,
    }

    if target_status not in allowed:
        raise CustomerStatusOperationError(
            "Недопустимый статус аккаунта."
        )

    with transaction.atomic():
        account = (
            CustomerAccount.objects
            .select_for_update()
            .get(
                pk=account_id
            )
        )

        if (
            account.status
            == CustomerAccount.Status.DELETED
        ):
            raise CustomerStatusOperationError(
                "Удалённый аккаунт "
                "нельзя включить или отключить."
            )

        previous_status = (
            account.status
        )

        changed = bool(
            previous_status
            != target_status
        )

        if changed:
            account.status = (
                target_status
            )

            account.updated_at = (
                timezone.now()
            )

            account.save(
                update_fields=[
                    "status",
                    "updated_at",
                ]
            )

    try:
        reconcile = (
            _reconcile_account(
                account_id
            )
        )

    except Exception as exc:
        if changed:
            _restore_account_status(
                account_id=account_id,
                previous_status=(
                    previous_status
                ),
            )

        if isinstance(
            exc,
            CustomerStatusOperationError,
        ):
            raise

        raise CustomerStatusOperationError(
            f"Не удалось применить статус: {exc}"
        ) from exc

    AuditService.log(
        actor,
        "customer.account.status",
        "CustomerAccount",
        account_id,
        {
            "from_status": (
                previous_status
            ),
            "to_status": (
                target_status
            ),
            "changed": changed,
        },
    )

    account.refresh_from_db()

    return {
        "account": account,
        "changed": changed,
        **reconcile,
    }


def set_customer_device_status(
    *,
    device_id,
    target_status,
    actor,
):
    allowed = {
        ClientDevice.Status.ACTIVE,
        ClientDevice.Status.DISABLED,
    }

    if target_status not in allowed:
        raise CustomerStatusOperationError(
            "Недопустимый статус устройства."
        )

    with transaction.atomic():
        device = (
            ClientDevice.objects
            .select_for_update()
            .select_related(
                "account",
            )
            .get(
                pk=device_id
            )
        )

        if (
            device.status
            == ClientDevice.Status.DELETED
        ):
            raise CustomerStatusOperationError(
                "Удалённое устройство "
                "нельзя включить или отключить."
            )

        if (
            device.account.status
            == CustomerAccount.Status.DELETED
        ):
            raise CustomerStatusOperationError(
                "Устройство удалённого "
                "аккаунта недоступно."
            )

        previous_status = (
            device.status
        )

        changed = bool(
            previous_status
            != target_status
        )

        if changed:
            device.status = (
                target_status
            )

            device.updated_at = (
                timezone.now()
            )

            device.save(
                update_fields=[
                    "status",
                    "updated_at",
                ]
            )

        account_id = (
            device.account_id
        )

    try:
        reconcile = (
            _reconcile_device(
                device_id
            )
        )

    except Exception as exc:
        if changed:
            _restore_device_status(
                device_id=device_id,
                previous_status=(
                    previous_status
                ),
            )

        if isinstance(
            exc,
            CustomerStatusOperationError,
        ):
            raise

        raise CustomerStatusOperationError(
            f"Не удалось применить статус: {exc}"
        ) from exc

    AuditService.log(
        actor,
        "customer.device.status",
        "ClientDevice",
        device_id,
        {
            "account_id": (
                account_id
            ),
            "from_status": (
                previous_status
            ),
            "to_status": (
                target_status
            ),
            "changed": changed,
        },
    )

    device.refresh_from_db()

    return {
        "device": device,
        "changed": changed,
        **reconcile,
    }
