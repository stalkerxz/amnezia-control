from django.core.management.base import BaseCommand

from vpn.expiration_reminders import ClientExpirationReminderService


class Command(BaseCommand):
    help = "Send grouped admin email reminders for active VPN clients close to expiration."

    def handle(self, *args, **options):
        result = ClientExpirationReminderService.send_reminders()
        self.stdout.write(
            self.style.SUCCESS(
                "Expiration reminders completed: "
                f"enabled={result.get('enabled')} "
                f"emails_sent={result.get('emails_sent', 0)} "
                f"clients={result.get('clients', 0)} "
                f"logs_created={result.get('logs_created', 0)}"
            )
        )
