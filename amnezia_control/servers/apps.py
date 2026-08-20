from django.apps import AppConfig


class ServersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "servers"

    def ready(self):
        from .agent_backend import install_agent_backend
        from .agent_vpn_hooks import install_agent_vpn_hooks

        install_agent_backend()
        install_agent_vpn_hooks()
