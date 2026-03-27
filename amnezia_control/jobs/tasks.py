from celery import shared_task
from servers.models import Server
from .executors import SafeSSHExecutor
from .models import Job
from .services import JobService


@shared_task
def run_job(job_id: int):
    job = Job.objects.select_related("server").get(id=job_id)
    JobService.mark_running(job)

    executor = SafeSSHExecutor(
        host=job.server.host,
        username=job.server.ssh_username,
        port=job.server.port,
        key_path=job.server.ssh_private_key_path or None,
    )

    action_map = {
        "server.health_check": "systemctl is-active amnezia-awg",
    }
    command = action_map.get(job.action)
    if not command:
        JobService.event(job, "Unknown action", level="error")
        JobService.mark_done(job, ok=False)
        return

    try:
        result = executor.run(command)
        ok = result.exit_code == 0
        JobService.event(job, f"Executed {command}", stdout=result.stdout, stderr=result.stderr, exit_code=result.exit_code)
        JobService.mark_done(job, ok=ok)
    except Exception as exc:  # pragma: no cover
        JobService.event(job, f"Execution failed: {exc}", level="error")
        JobService.mark_done(job, ok=False)
