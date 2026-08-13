import django.db.models.deletion
from django.db import migrations, models
from django.db.models import Q


class Migration(migrations.Migration):

    dependencies = [
        (
            "portal",
            "0010_backfill_account_ownership",
        ),
    ]

    operations = [
        migrations.AlterField(
            model_name="clientrenewalrequest",
            name="client",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="renewal_requests",
                to="vpn.vpnclient",
            ),
        ),
        migrations.AddConstraint(
            model_name="clientrenewalrequest",
            constraint=models.UniqueConstraint(
                fields=("account",),
                condition=Q(
                    account__isnull=False,
                    status__in=[
                        "new",
                        "in_progress",
                    ],
                ),
                name=(
                    "uniq_open_renewal_request_per_account"
                ),
            ),
        ),
    ]
