from django.db import migrations


LEGACY_MARKER_PREFIX = "legacy-vpn-client:"


def migrate_legacy_vpn_clients(apps, schema_editor):
    CustomerAccount = apps.get_model("customers", "CustomerAccount")
    ClientDevice = apps.get_model("customers", "ClientDevice")
    VPNClient = apps.get_model("vpn", "VPNClient")

    valid_statuses = {"active", "disabled", "deleted"}

    queryset = (
        VPNClient.objects
        .filter(device__isnull=True)
        .order_by("pk")
    )

    for client in queryset.iterator():
        # Preserve the existing VPNClient state exactly when possible.
        # An unknown legacy value is treated conservatively as disabled.
        status = (
            client.status
            if client.status in valid_statuses
            else "disabled"
        )

        account = CustomerAccount.objects.create(
            display_name=client.name,
            email=client.contact_email or "",
            status=status,
            expires_at=client.expires_at,
            created_by_id=client.created_by_id,
        )

        device = ClientDevice.objects.create(
            account_id=account.pk,
            name=client.name,
            platform="unknown",
            status=status,
            notes=f"{LEGACY_MARKER_PREFIX}{client.pk}",
        )

        VPNClient.objects.filter(
            pk=client.pk,
            device__isnull=True,
        ).update(device_id=device.pk)


def reverse_legacy_vpn_clients(apps, schema_editor):
    CustomerAccount = apps.get_model("customers", "CustomerAccount")
    ClientDevice = apps.get_model("customers", "ClientDevice")
    VPNClient = apps.get_model("vpn", "VPNClient")

    queryset = (
        VPNClient.objects
        .exclude(device__isnull=True)
        .order_by("pk")
    )

    for client in queryset.iterator():
        marker = f"{LEGACY_MARKER_PREFIX}{client.pk}"

        device = (
            ClientDevice.objects
            .filter(
                pk=client.device_id,
                notes=marker,
            )
            .first()
        )

        # Do not touch devices/accounts that are no longer exactly the
        # migration-created legacy wrapper.
        if device is None:
            continue

        account_id = device.account_id

        # If this migration-created device has since become shared with
        # another VPN configuration, it is no longer a disposable legacy
        # wrapper. Preserve it rather than risking destructive rollback.
        has_other_vpn_clients = (
            VPNClient.objects
            .filter(device_id=device.pk)
            .exclude(pk=client.pk)
            .exists()
        )
        if has_other_vpn_clients:
            continue

        VPNClient.objects.filter(
            pk=client.pk,
            device_id=device.pk,
        ).update(device_id=None)

        device.delete()

        # Delete the wrapper account only when nothing else has been
        # attached to it since the migration.
        if not ClientDevice.objects.filter(account_id=account_id).exists():
            CustomerAccount.objects.filter(
                pk=account_id,
                user__isnull=True,
            ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("customers", "0001_initial"),
        ("vpn", "0008_vpnclient_device"),
    ]

    operations = [
        migrations.RunPython(
            migrate_legacy_vpn_clients,
            reverse_legacy_vpn_clients,
        ),
    ]
