from django.core.management.base import BaseCommand
from django.db.models import Q

from jobs.models import JobEvent


SENSITIVE_ACTION_PREFIXES = (
    "runtime.inspect.",
    "runtime.conf.",
    "runtime.peers.",
)

SENSITIVE_ACTIONS = {
    "awg.list",
    "awg2.list",
    "awg2.list_all",
    "awg2.list_fallback_conf",
}


def sensitive_event_queryset():
    action_filter = Q(job__action__in=SENSITIVE_ACTIONS)
    for prefix in SENSITIVE_ACTION_PREFIXES:
        action_filter |= Q(job__action__startswith=prefix)
    return JobEvent.objects.filter(action_filter).exclude(stdout="", stderr="")


class Command(BaseCommand):
    help = (
        "Redact historical stdout/stderr for runtime jobs that may contain "
        "VPN private keys, preshared keys, container env values, or AWG secrets."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report how many events would be redacted without changing data.",
        )

    def handle(self, *args, **options):
        queryset = sensitive_event_queryset()
        count = queryset.count()

        if options["dry_run"]:
            self.stdout.write(f"Would redact {count} sensitive runtime JobEvent(s).")
            return

        updated = queryset.update(stdout="", stderr="")
        self.stdout.write(
            self.style.SUCCESS(
                f"Redacted {updated} sensitive runtime JobEvent(s)."
            )
        )
