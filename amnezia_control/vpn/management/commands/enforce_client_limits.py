from django.core.management.base import BaseCommand

from vpn.services import VPNClientLimitsService


class Command(BaseCommand):
    help = "Синхронизирует трафик клиентов и применяет лимиты по времени/квоте"

    def handle(self, *args, **options):
        traffic = VPNClientLimitsService.sync_traffic_usage(actor=None)
        limits = VPNClientLimitsService.enforce_limits(actor=None)
        self.stdout.write(
            self.style.SUCCESS(
                "Готово: синхронизировано={synced}, недоступно={unavailable}, "
                "обработано={processed}, истекло={expired}, трафик превышен={traffic_exceeded}".format(
                    synced=traffic["synced"],
                    unavailable=traffic["unavailable"],
                    processed=limits["processed"],
                    expired=limits["expired"],
                    traffic_exceeded=limits["traffic_exceeded"],
                )
            )
        )
