import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "amnezia_control.settings")

app = Celery("amnezia_control")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
