import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "customers",
            "0002_legacy_vpn_clients",
        ),
        (
            "portal",
            "0008_clientrenewalrequest_attachment_original_name",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="clientportalaccess",
            name="account",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="legacy_portal_accesses",
                to="customers.customeraccount",
            ),
        ),
        migrations.AddField(
            model_name="clientrenewalrequest",
            name="account",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="renewal_requests",
                to="customers.customeraccount",
            ),
        ),
    ]
