from .models import AuditLog


class AuditService:
    @staticmethod
    def log(actor, action: str, entity_type: str, entity_id: str, details: dict | None = None):
        return AuditLog.objects.create(
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id),
            details=details or {},
        )
