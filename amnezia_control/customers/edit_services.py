from django.db import transaction

from audit.services import AuditService
from vpn.models import VPNClient
from vpn.services import VPNClientService

from .models import ClientDevice, CustomerAccount


class CustomerMetadataEditError(ValueError):
    pass


@transaction.atomic
def update_customer_account_metadata(
    *,
    account_id,
    display_name,
    email,
    expires_at,
    actor,
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
        raise CustomerMetadataEditError(
            "Удалённый аккаунт нельзя редактировать."
        )

    display_name = (
        display_name or ""
    ).strip()

    email = (
        email or ""
    ).strip()

    if not display_name:
        raise CustomerMetadataEditError(
            "Имя клиента не может быть пустым."
        )

    old_display_name = account.display_name
    old_email = account.email
    old_expires_at = account.expires_at

    account.display_name = display_name
    account.email = email
    account.expires_at = expires_at

    account.save(
        update_fields=[
            "display_name",
            "email",
            "expires_at",
            "updated_at",
        ]
    )

    expiry_clients_updated = 0

    if old_expires_at != expires_at:
        vpn_clients = (
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
            client.expires_at = expires_at
            client.limit_state = (
                VPNClientService
                .get_limit_state(client)
            )

            client.save(
                update_fields=[
                    "expires_at",
                    "limit_state",
                ]
            )

            expiry_clients_updated += 1

    mirrored_clients = 0

    if old_email != email:
        mirrored_clients = (
            VPNClient.objects
            .filter(
                device__account=account,
            )
            .exclude(
                status=VPNClient.Status.DELETED,
            )
            .update(
                contact_email=email,
            )
        )

    AuditService.log(
        actor,
        "customer.metadata.update",
        "CustomerAccount",
        account.pk,
        {
            "old_display_name": old_display_name,
            "new_display_name": display_name,
            "email_changed": old_email != email,
            "expires_at_changed": (
                old_expires_at != expires_at
            ),
            "old_expires_at": (
                old_expires_at.isoformat()
                if old_expires_at
                else None
            ),
            "new_expires_at": (
                expires_at.isoformat()
                if expires_at
                else None
            ),
            "vpn_contact_email_updated": (
                mirrored_clients
            ),
            "vpn_expiry_updated": (
                expiry_clients_updated
            ),
            "runtime_mutated": False,
        },
    )

    return account


@transaction.atomic
def update_customer_device_metadata(
    *,
    device_id,
    name,
    platform,
    notes,
    actor,
):
    device = (
        ClientDevice.objects
        .select_for_update()
        .select_related("account")
        .get(pk=device_id)
    )

    if (
        device.status
        == ClientDevice.Status.DELETED
        or device.account.status
        == CustomerAccount.Status.DELETED
    ):
        raise CustomerMetadataEditError(
            "Удалённое устройство нельзя редактировать."
        )

    name = (
        name or ""
    ).strip()

    notes = (
        notes or ""
    ).strip()

    if not name:
        raise CustomerMetadataEditError(
            "Название устройства не может быть пустым."
        )

    valid_platforms = {
        value
        for value, _
        in ClientDevice.Platform.choices
    }

    if platform not in valid_platforms:
        raise CustomerMetadataEditError(
            "Некорректная платформа устройства."
        )

    old_name = device.name
    old_platform = device.platform
    old_notes = device.notes

    device.name = name
    device.platform = platform
    device.notes = notes

    device.save(
        update_fields=[
            "name",
            "platform",
            "notes",
            "updated_at",
        ]
    )

    AuditService.log(
        actor,
        "customer.device.metadata.update",
        "ClientDevice",
        device.pk,
        {
            "account_id": device.account_id,
            "name_changed": old_name != name,
            "platform_changed": (
                old_platform != platform
            ),
            "notes_changed": old_notes != notes,
            "runtime_mutated": False,
        },
    )

    return device
