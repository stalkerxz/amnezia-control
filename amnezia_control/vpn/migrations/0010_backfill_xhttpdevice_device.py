from django.db import migrations


def backfill_xhttp_devices(apps, schema_editor):
    XHTTPDevice = apps.get_model(
        "vpn",
        "XHTTPDevice",
    )

    rows = (
        XHTTPDevice.objects
        .filter(device__isnull=True)
        .exclude(client__device__isnull=True)
        .order_by("pk")
        .values_list(
            "pk",
            "client__device_id",
        )
    )

    for xhttp_id, client_device_id in rows.iterator():
        if client_device_id is None:
            continue

        XHTTPDevice.objects.filter(
            pk=xhttp_id,
            device__isnull=True,
        ).update(
            device_id=client_device_id,
        )


def reverse_backfill_xhttp_devices(apps, schema_editor):
    XHTTPDevice = apps.get_model(
        "vpn",
        "XHTTPDevice",
    )

    # Be conservative on rollback:
    # remove only links that still exactly match client.device.
    rows = (
        XHTTPDevice.objects
        .exclude(device__isnull=True)
        .order_by("pk")
        .values_list(
            "pk",
            "device_id",
            "client__device_id",
        )
    )

    for xhttp_id, device_id, client_device_id in rows.iterator():
        if (
            client_device_id is not None
            and device_id == client_device_id
        ):
            XHTTPDevice.objects.filter(
                pk=xhttp_id,
                device_id=device_id,
            ).update(
                device_id=None,
            )


class Migration(migrations.Migration):

    dependencies = [
        ("vpn", "0009_xhttpdevice_device"),
    ]

    operations = [
        migrations.RunPython(
            backfill_xhttp_devices,
            reverse_backfill_xhttp_devices,
        ),
    ]
