"""Transport recovery for managed XHTTP runtime operations.

The remote XHTTP helper is intentionally idempotent for add/remove/check.
That lets us safely retry the exact same operation when the SSH transport
fails before the caller receives a result. Command failures returned by the
helper are not retried.
"""

import paramiko

from jobs.services import JobService

from .services import RuntimeCommandService
from .xhttp_services import XHTTPRuntimeAdapter


class XHTTPRuntimeTransportError(RuntimeError):
    """The SSH transport failed before a trustworthy command result arrived."""


class ResilientXHTTPRuntimeAdapter(XHTTPRuntimeAdapter):
    """XHTTP adapter with one idempotent retry for SSH transport failures."""

    MAX_TRANSPORT_ATTEMPTS = 2
    TRANSPORT_EXCEPTIONS = (
        EOFError,
        OSError,
        TimeoutError,
        paramiko.SSHException,
    )

    def _record_executor_exception(
        self,
        *,
        job,
        action: str,
        transport: bool,
    ):
        JobService.event(
            job,
            (
                f"Transport failure during xhttp.{action}"
                if transport
                else f"Runtime failure during xhttp.{action}"
            ),
            level="error",
            # XHTTP helper output is sensitive. Do not persist exception
            # details here because SSH/auth exceptions may contain paths,
            # hosts, or other operational metadata.
            stderr="",
            exit_code=None,
        )
        JobService.mark_done(job, ok=False)

    def _execute_once(
        self,
        *,
        action: str,
        command: str,
        actor,
    ):
        job = JobService.create_job(
            server=self.server,
            actor=actor,
            action=f"xhttp.{action}",
            payload={"command": "[REDACTED]"},
        )
        JobService.mark_running(job)

        try:
            result = (
                RuntimeCommandService
                .executor_for_server(self.server)
                .run(command)
            )
        except self.TRANSPORT_EXCEPTIONS as exc:
            # RuntimeCommandService.run currently cannot mark a Job failed
            # when its SSH executor raises before returning ExecutionResult.
            # Close the Job explicitly so transport failures never remain
            # indefinitely in the RUNNING state.
            self._record_executor_exception(
                job=job,
                action=action,
                transport=True,
            )
            raise XHTTPRuntimeTransportError(
                f"XHTTP transport failed during {action}."
            ) from exc
        except Exception:
            # Validation/configuration failures are deterministic. They still
            # need a closed Job, but retrying them could only repeat the same
            # failure and is therefore intentionally forbidden.
            self._record_executor_exception(
                job=job,
                action=action,
                transport=False,
            )
            raise

        JobService.event(
            job,
            f"Executed xhttp.{action}",
            stdout="",
            stderr="",
            exit_code=result.exit_code,
            level=(
                "info"
                if result.exit_code == 0
                else "error"
            ),
        )
        JobService.mark_done(
            job,
            ok=result.exit_code == 0,
        )

        if result.exit_code != 0:
            # A real helper error is deterministic and must not be retried.
            raise RuntimeError(
                result.stderr
                or f"command failed: xhttp.{action}"
            )

        return result

    def _run(
        self,
        *,
        action: str,
        client_uuid,
        xray_email: str,
        actor,
    ):
        if action not in {"add", "remove", "check"}:
            raise ValueError(
                "Недопустимое действие XHTTP runtime."
            )

        uuid_text = self._validate_identity(
            client_uuid,
            xray_email,
        )
        command = (
            f"sudo -n {self.HELPER_PATH} "
            f"{action} {uuid_text} {xray_email}"
        )

        last_transport_error = None

        for attempt in range(
            1,
            self.MAX_TRANSPORT_ATTEMPTS + 1,
        ):
            try:
                return self._execute_once(
                    action=action,
                    command=command,
                    actor=actor,
                )
            except XHTTPRuntimeTransportError as exc:
                last_transport_error = exc

                if (
                    attempt
                    >= self.MAX_TRANSPORT_ATTEMPTS
                ):
                    break

        raise RuntimeError(
            "XHTTP runtime transport failed after "
            "one safe idempotent retry."
        ) from last_transport_error


def install_runtime_recovery():
    """Install the resilient adapter into the existing XHTTP service module."""

    from . import xhttp_services

    xhttp_services.XHTTPRuntimeAdapter = (
        ResilientXHTTPRuntimeAdapter
    )
