from django.utils import timezone
from .models import Job, JobEvent


class JobService:
    @staticmethod
    def create_job(server, actor, action: str, payload: dict | None = None) -> Job:
        return Job.objects.create(server=server, actor=actor, action=action, payload=payload or {})

    @staticmethod
    def mark_running(job: Job):
        job.status = Job.Status.RUNNING
        job.started_at = timezone.now()
        job.save(update_fields=["status", "started_at"])

    @staticmethod
    def mark_done(job: Job, ok: bool):
        job.status = Job.Status.SUCCESS if ok else Job.Status.FAILED
        job.finished_at = timezone.now()
        job.save(update_fields=["status", "finished_at"])

    @staticmethod
    def event(job: Job, message: str, level: str = "info", stdout: str = "", stderr: str = "", exit_code: int | None = None):
        return JobEvent.objects.create(job=job, level=level, message=message, stdout=stdout[:4000], stderr=stderr[:4000], exit_code=exit_code)
