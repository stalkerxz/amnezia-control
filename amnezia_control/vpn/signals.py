from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from customers.models import (
    ClientDevice,
    CustomerAccount,
)


def _safe_delay(task, *args):
    try:
        task.delay(*args)
    except Exception:
        # Periodic reconciliation remains the fallback.
        return


@receiver(post_save, sender=ClientDevice)
def schedule_device_xhttp_reconciliation(
    sender,
    instance: ClientDevice,
    raw=False,
    update_fields=None,
    **kwargs,
):
    if raw:
        return

    relevant_fields = {
        "status",
        "account",
    }

    if (
        update_fields is not None
        and not (
            set(update_fields)
            & relevant_fields
        )
    ):
        return

    device_id = instance.pk

    def enqueue():
        from .tasks import (
            reconcile_vpn_device_task,
            reconcile_xhttp_device_task,
        )

        _safe_delay(
            reconcile_vpn_device_task,
            device_id,
        )

        _safe_delay(
            reconcile_xhttp_device_task,
            device_id,
        )

    transaction.on_commit(enqueue)


@receiver(post_save, sender=CustomerAccount)
def schedule_account_xhttp_reconciliation(
    sender,
    instance: CustomerAccount,
    raw=False,
    update_fields=None,
    **kwargs,
):
    if raw:
        return

    relevant_fields = {
        "status",
        "expires_at",
    }

    if (
        update_fields is not None
        and not (
            set(update_fields)
            & relevant_fields
        )
    ):
        return

    account_id = instance.pk

    def enqueue():
        from .tasks import (
            reconcile_vpn_account_task,
            reconcile_xhttp_account_task,
        )

        _safe_delay(
            reconcile_vpn_account_task,
            account_id,
        )

        _safe_delay(
            reconcile_xhttp_account_task,
            account_id,
        )

    transaction.on_commit(enqueue)
