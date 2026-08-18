import django.db.models.deletion
from django.db import migrations, models


def assert_xhttp_rows_are_finalizable(
    apps,
    schema_editor,
):
    XHTTPDevice = apps.get_model(
        "vpn",
        "XHTTPDevice",
    )

    missing_device = (
        XHTTPDevice.objects
        .filter(device__isnull=True)
        .count()
    )

    missing_server = (
        XHTTPDevice.objects
        .filter(server__isnull=True)
        .count()
    )

    if missing_device or missing_server:
        raise RuntimeError(
            "Cannot finalize XHTTP ownership: "
            f"{missing_device} row(s) without ClientDevice, "
            f"{missing_server} row(s) without Server."
        )


class Migration(migrations.Migration):

    dependencies = [
        (
            "vpn",
            "0013_alter_vpnclient_disable_reason",
        ),
    ]

    operations = [
        migrations.RunPython(
            assert_xhttp_rows_are_finalizable,
            migrations.RunPython.noop,
        ),
        migrations.RemoveConstraint(
            model_name="xhttpdevice",
            name=(
                "unique_xhttp_device_name_per_client"
            ),
        ),
        migrations.RemoveField(
            model_name="xhttpdevice",
            name="client",
        ),
        migrations.AlterField(
            model_name="xhttpdevice",
            name="device",
            field=models.ForeignKey(
                on_delete=(
                    django.db.models.deletion.PROTECT
                ),
                related_name="xhttp_devices",
                to="customers.clientdevice",
            ),
        ),
        migrations.AlterField(
            model_name="xhttpdevice",
            name="server",
            field=models.ForeignKey(
                on_delete=(
                    django.db.models.deletion.PROTECT
                ),
                related_name="xhttp_devices",
                to="servers.server",
            ),
        ),
    ]
