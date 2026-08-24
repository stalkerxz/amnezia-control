from django.apps import AppConfig


class VpnConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "vpn"

    def ready(self):
        from .xhttp_runtime_recovery import (
            install_runtime_recovery,
        )

        install_runtime_recovery()

        from . import signals  # noqa: F401
