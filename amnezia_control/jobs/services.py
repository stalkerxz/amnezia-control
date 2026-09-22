import re

from django.utils import timezone
from .models import Job, JobEvent


DEGRADED_MARKERS = (
    "degraded",
    "fallback",
    "runtime telemetry unavailable",
    "config file fallback",
)


SENSITIVE_OUTPUT_PATTERNS = (
    re.compile(
        r"(?im)\b(?:PrivateKey|PresharedKey|HeaderProtectionKey)"
        r"\s*=\s*[^\r\n]+"
    ),
    re.compile(
        r'(?i)"(?:PrivateKey|PresharedKey|HeaderProtectionKey)"'
        r'\s*:\s*"[^"]+"'
    ),
    re.compile(
        r"(?i)\b[A-Z0-9_]*(?:PRIVATE_?KEY|PRESHARED(?:_?KEY)?|PSK|"
        r"PASSWORD|TOKEN|SECRET|HEADER_?PROTECTION_?KEY)[A-Z0-9_]*="
        r'[^,\s"\]]+'
    ),
)

SENSITIVE_OUTPUT_PLACEHOLDER = (
    "[REDACTED: sensitive runtime output]"
)


def contains_sensitive_output(text: str) -> bool:
    value = text or ""
    return any(
        pattern.search(value)
        for pattern in SENSITIVE_OUTPUT_PATTERNS
    )


def protect_job_output(text: str) -> str:
    value = text or ""
    if contains_sensitive_output(value):
        return SENSITIVE_OUTPUT_PLACEHOLDER
    return value


def _contains_degraded_marker(text: str) -> bool:
    normalized = (text or "").lower()
    return any(marker in normalized for marker in DEGRADED_MARKERS)


def classify_job_signal(job: Job, events: list[JobEvent] | None = None) -> str:
    ordered_events = events if events is not None else list(job.events.all())
    has_warning = any(event.level == "warning" for event in ordered_events)
    has_degraded_warning = any(
        event.level == "warning"
        and (
            _contains_degraded_marker(event.message)
            or _contains_degraded_marker(event.stdout)
            or _contains_degraded_marker(event.stderr)
        )
        for event in ordered_events
    )

    if job.status == Job.Status.FAILED:
        return "failed"
    if has_degraded_warning and job.status == Job.Status.SUCCESS:
        return "degraded_success"
    if has_warning:
        return "warning"
    if job.status == Job.Status.SUCCESS:
        return "success"
    return "in_progress"


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
        protected_stdout = protect_job_output(stdout)
        protected_stderr = protect_job_output(stderr)
        return JobEvent.objects.create(
            job=job,
            level=level,
            message=message,
            stdout=protected_stdout[:4000],
            stderr=protected_stderr[:4000],
            exit_code=exit_code,
        )
