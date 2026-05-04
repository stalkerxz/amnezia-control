from django.core.management.base import BaseCommand

from vpn.expiration_reminders import ClientExpirationReminderService


class Command(BaseCommand):
    help = "Send grouped admin reminders for active VPN clients close to expiration."

    def handle(self, *args, **options):
        result = ClientExpirationReminderService.send_reminders()
        self.stdout.write(
            self.style.SUCCESS(
                "Expiration reminders completed: "
                f"enabled={result.get('enabled')} "
                f"clients={result.get('clients', 0)} "
                f"logs_created={result.get('logs_created', 0)} "
                f"email_sent={result.get('channels', {}).get('email', {}).get('sent', False)} "
                f"telegram_sent={result.get('channels', {}).get('telegram', {}).get('sent', False)}"
            )
        )
