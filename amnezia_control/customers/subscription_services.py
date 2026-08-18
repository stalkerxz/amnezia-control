from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from audit.services import AuditService
from portal.models import ClientRenewalRequest
from vpn.models import VPNClient
from vpn.services import VPNClientService

from .models import CustomerAccount


class CustomerRenewalError(ValueError):
    pass


def _locked_account_and_request(
    *,
    account_id,
    renewal_request_id,
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
        raise CustomerRenewalError(
            "Удалённый аккаунт нельзя продлевать."
        )

    request_obj = (
        ClientRenewalRequest.objects
        .select_for_update()
        .get(
            pk=renewal_request_id,
            account=account,
        )
    )

    return account, request_obj


@transaction.atomic
def set_account_renewal_status(
    *,
    account_id,
    renewal_request_id,
    target_status,
    operator_note,
    actor,
):
    account, request_obj = (
        _locked_account_and_request(
            account_id=account_id,
            renewal_request_id=(
                renewal_request_id
            ),
        )
    )

    current = request_obj.status

    allowed = {
        ClientRenewalRequest.Status.NEW: {
            ClientRenewalRequest.Status.IN_PROGRESS,
            ClientRenewalRequest.Status.DISMISSED,
        },
        ClientRenewalRequest.Status.IN_PROGRESS: {
            ClientRenewalRequest.Status.DISMISSED,
        },
    }

    if target_status not in allowed.get(
        current,
        set(),
    ):
        raise CustomerRenewalError(
            "Недопустимый переход статуса заявки."
        )

    request_obj.status = target_status
    request_obj.operator_note = (
        operator_note or ""
    ).strip()

    request_obj.processed_by = actor

    if (
        target_status
        == ClientRenewalRequest.Status.DISMISSED
    ):
        request_obj.processed_at = (
            timezone.now()
        )
    else:
        request_obj.processed_at = None

    request_obj.save(
        update_fields=[
            "status",
            "operator_note",
            "processed_by",
            "processed_at",
            "updated_at",
        ]
    )

    AuditService.log(
        actor,
        (
            "customer.renewal."
            f"{target_status}"
        ),
        "CustomerAccount",
        account.pk,
        {
            "renewal_request_id": (
                request_obj.pk
            ),
            "from_status": current,
            "to_status": target_status,
            "operator_note": (
                request_obj.operator_note
            ),
        },
    )

    return request_obj


@transaction.atomic
def extend_account_from_renewal(
    *,
    account_id,
    renewal_request_id,
    extension_days,
    operator_note,
    actor,
):
    account, request_obj = (
        _locked_account_and_request(
            account_id=account_id,
            renewal_request_id=(
                renewal_request_id
            ),
        )
    )

    if request_obj.status not in {
        ClientRenewalRequest.Status.NEW,
        ClientRenewalRequest.Status.IN_PROGRESS,
    }:
        raise CustomerRenewalError(
            "Продлить можно только открытую заявку."
        )

    try:
        extension_days = int(
            extension_days
        )
    except (TypeError, ValueError):
        raise CustomerRenewalError(
            "Количество дней должно быть числом."
        )

    if (
        extension_days < 1
        or extension_days > 365
    ):
        raise CustomerRenewalError(
            "Продление должно быть "
            "от 1 до 365 дней."
        )

    old_expires_at = account.expires_at

    now = timezone.now()

    base = (
        account.expires_at
        if (
            account.expires_at
            and account.expires_at > now
        )
        else now
    )

    new_expires_at = (
        base
        + timedelta(
            days=extension_days
        )
    )

    account.expires_at = new_expires_at

    account.save(
        update_fields=[
            "expires_at",
            "updated_at",
        ]
    )

    vpn_clients = list(
        VPNClient.objects
        .select_for_update()
        .filter(
            device__account=account,
        )
        .exclude(
            status=VPNClient.Status.DELETED,
        )
        .order_by("pk")
    )

    for client in vpn_clients:
        client.expires_at = (
            new_expires_at
        )

        update_fields = [
            "expires_at",
        ]

        # Active clients can safely have their cached
        # limit state recalculated. Disabled expired
        # peers are restored separately in Phase 6C;
        # no runtime mutation is performed here.
        if (
            client.status
            == VPNClient.Status.ACTIVE
        ):
            client.limit_state = (
                VPNClientService
                .get_limit_state(
                    client
                )
            )

            update_fields.append(
                "limit_state"
            )

        client.save(
            update_fields=update_fields
        )

    request_obj.status = (
        ClientRenewalRequest.Status.DONE
    )

    request_obj.operator_note = (
        operator_note or ""
    ).strip()

    request_obj.processed_at = (
        timezone.now()
    )

    request_obj.processed_by = actor

    request_obj.save(
        update_fields=[
            "status",
            "operator_note",
            "processed_at",
            "processed_by",
            "updated_at",
        ]
    )

    AuditService.log(
        actor,
        "customer.renewal.extend",
        "CustomerAccount",
        account.pk,
        {
            "renewal_request_id": (
                request_obj.pk
            ),
            "extension_days": (
                extension_days
            ),
            "old_expires_at": (
                old_expires_at.isoformat()
                if old_expires_at
                else None
            ),
            "new_expires_at": (
                new_expires_at.isoformat()
            ),
            "vpn_clients_updated": len(
                vpn_clients
            ),
            "runtime_mutated": False,
        },
    )

    return (
        account,
        request_obj,
    )
