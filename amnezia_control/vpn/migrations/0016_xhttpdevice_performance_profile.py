from django.db import migrations, models


def backfill_turbo_profiles(apps, schema_editor):
    XHTTPDevice = apps.get_model("vpn", "XHTTPDevice")
    XHTTPDevice.objects.filter(
        name__icontains="turbo",
    ).update(
        performance_profile="turbo",
    )


class Migration(migrations.Migration):
    dependencies = [
        ("vpn", "0015_allow_parent_delete_after_connection_cleanup"),
    ]

    operations = [
        migrations.AddField(
            model_name="xhttpdevice",
            name="performance_profile",
            field=models.CharField(
                choices=[
                    ("standard", "Standard"),
                    ("turbo", "Turbo"),
                ],
                default="standard",
                max_length=16,
            ),
        ),
        migrations.RunPython(
            backfill_turbo_profiles,
            migrations.RunPython.noop,
        ),
    ]
