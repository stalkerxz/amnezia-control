from django.db import migrations


def _backfill_model(Model):
    rows = (
        Model.objects
        .filter(
            account__isnull=True,
        )
        .exclude(
            client__device__isnull=True,
        )
        .exclude(
            client__device__account__isnull=True,
        )
        .order_by("pk")
        .values_list(
            "pk",
            "client__device__account_id",
        )
    )

    for row_id, account_id in rows.iterator():
        if account_id is None:
            continue

        Model.objects.filter(
            pk=row_id,
            account__isnull=True,
        ).update(
            account_id=account_id,
        )


def backfill_account_ownership(
    apps,
    schema_editor,
):
    ClientPortalAccess = apps.get_model(
        "portal",
        "ClientPortalAccess",
    )

    ClientRenewalRequest = apps.get_model(
        "portal",
        "ClientRenewalRequest",
    )

    _backfill_model(
        ClientPortalAccess
    )

    _backfill_model(
        ClientRenewalRequest
    )


def _reverse_model(Model):
    rows = (
        Model.objects
        .exclude(
            account__isnull=True,
        )
        .exclude(
            client__device__isnull=True,
        )
        .order_by("pk")
        .values_list(
            "pk",
            "account_id",
            "client__device__account_id",
        )
    )

    for (
        row_id,
        account_id,
        current_client_account_id,
    ) in rows.iterator():
        # Clear only links that still exactly match the legacy path.
        # If an operator moved a device/account meanwhile, do not make
        # assumptions about manually corrected ownership.
        if (
            current_client_account_id is not None
            and account_id
            == current_client_account_id
        ):
            Model.objects.filter(
                pk=row_id,
                account_id=account_id,
            ).update(
                account_id=None,
            )


def reverse_account_ownership(
    apps,
    schema_editor,
):
    ClientPortalAccess = apps.get_model(
        "portal",
        "ClientPortalAccess",
    )

    ClientRenewalRequest = apps.get_model(
        "portal",
        "ClientRenewalRequest",
    )

    _reverse_model(
        ClientPortalAccess
    )

    _reverse_model(
        ClientRenewalRequest
    )


class Migration(migrations.Migration):

    dependencies = [
        (
            "portal",
            "0009_account_ownership_bridge",
        ),
    ]

    operations = [
        migrations.RunPython(
            backfill_account_ownership,
            reverse_account_ownership,
        ),
    ]
