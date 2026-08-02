from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import VPNClient


@receiver(post_save, sender=VPNClient)
def schedule_xhttp_reconciliation(sender, instance: VPNClient, raw=False, update_fields=None, **kwargs):
    if raw:
        return
    relevant_fields = {
        "status",
        "limit_state",
        "expires_at",
        "traffic_limit_bytes",
        "traffic_used_bytes",
    }
    if update_fields is not None and not (set(update_fields) & relevant_fields):
        return

    client_id = instance.pk

    def enqueue():
        from .tasks import reconcile_xhttp_client_task

        try:
            reconcile_xhttp_client_task.delay(client_id)
        except Exception:
            # Periodic reconciliation in enforce_client_limits_task remains the fallback.
            return

    transaction.on_commit(enqueue)
