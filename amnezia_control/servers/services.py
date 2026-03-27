from jobs.services import JobService
from .models import Server


class ServerService:
    @staticmethod
    def update_health(server: Server, status: str) -> Server:
        server.health_status = status
        server.save(update_fields=["health_status", "updated_at"])
        return server

    @staticmethod
    def refresh_health_with_job(server: Server, actor):
        return JobService.create_job(
            server=server,
            actor=actor,
            action="server.health_check",
            payload={"server_id": server.id},
        )
