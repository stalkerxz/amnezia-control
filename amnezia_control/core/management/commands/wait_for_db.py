import time
from django.core.management.base import BaseCommand
from django.db import connections
from django.db.utils import OperationalError


class Command(BaseCommand):
    help = "Wait until default database is available"

    def handle(self, *args, **options):
        self.stdout.write("Waiting for database...")
        for _ in range(60):
            try:
                conn = connections["default"]
                conn.cursor()
                self.stdout.write(self.style.SUCCESS("Database is ready"))
                return
            except OperationalError:
                time.sleep(1)
        raise OperationalError("Database is not reachable after timeout")
