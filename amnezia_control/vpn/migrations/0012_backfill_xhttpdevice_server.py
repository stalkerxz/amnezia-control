from django.db import migrations


def backfill_xhttp_server(apps, schema_editor):
    XHTTPDevice = apps.get_model(
        "vpn",
        "XHTTPDevice",
    )

    rows = (
        XHTTPDevice.objects
        .filter(
            server__isnull=True,
        )
        .exclude(
            client__isnull=True,
        )
        .order_by("pk")
        .values_list(
            "pk",
            "client__server_id",
        )
    )

    for xhttp_id, server_id in rows.iterator():
        if server_id is None:
            continue

        XHTTPDevice.objects.filter(
            pk=xhttp_id,
            server__isnull=True,
        ).update(
            server_id=server_id,
        )


def reverse_backfill_xhttp_server(apps, schema_editor):
    XHTTPDevice = apps.get_model(
        "vpn",
        "XHTTPDevice",
    )

    rows = (
        XHTTPDevice.objects
        .exclude(
            server__isnull=True,
        )
        .exclude(
            client__isnull=True,
        )
        .order_by("pk")
        .values_list(
            "pk",
            "server_id",
            "client__server_id",
        )
    )

    for xhttp_id, server_id, client_server_id in rows.iterator():
        if (
            client_server_id is not None
            and server_id == client_server_id
        ):
            XHTTPDevice.objects.filter(
                pk=xhttp_id,
                server_id=server_id,
            ).update(
                server_id=None,
            )


class Migration(migrations.Migration):

    dependencies = [
        ("vpn", "0011_xhttpdevice_device_ownership"),
    ]

    operations = [
        migrations.RunPython(
            backfill_xhttp_server,
            reverse_backfill_xhttp_server,
        ),
    ]
