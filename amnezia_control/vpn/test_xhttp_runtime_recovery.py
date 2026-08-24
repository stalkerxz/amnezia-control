import uuid
from unittest.mock import Mock, call, patch

from django.test import SimpleTestCase

from jobs.executors import ExecutionResult
from vpn.xhttp_runtime_recovery import (
    ResilientXHTTPRuntimeAdapter,
)


class XHTTPRuntimeRecoveryTest(SimpleTestCase):
    def setUp(self):
        self.server = object()
        self.actor = object()
        self.client_uuid = uuid.uuid4()
        self.xray_email = (
            f"xhttp-{self.client_uuid.hex}"
        )
        self.adapter = ResilientXHTTPRuntimeAdapter(
            self.server
        )

    def _success_result(self):
        return ExecutionResult(
            command="helper",
            exit_code=0,
            stdout='{"ok": true}',
            stderr="",
        )

    def _failure_result(self):
        return ExecutionResult(
            command="helper",
            exit_code=1,
            stdout="",
            stderr="helper rejected operation",
        )

    @patch(
        "vpn.xhttp_runtime_recovery."
        "RuntimeCommandService.executor_for_server"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.mark_done"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.event"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.mark_running"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.create_job"
    )
    def test_transport_failure_retries_once(
        self,
        create_job,
        mark_running,
        event,
        mark_done,
        executor_for_server,
    ):
        first_job = object()
        second_job = object()
        create_job.side_effect = [
            first_job,
            second_job,
        ]

        executor = Mock()
        executor.run.side_effect = [
            OSError("connection reset"),
            self._success_result(),
        ]
        executor_for_server.return_value = executor

        result = self.adapter.add(
            client_uuid=self.client_uuid,
            xray_email=self.xray_email,
            actor=self.actor,
        )

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(executor.run.call_count, 2)
        self.assertEqual(create_job.call_count, 2)
        self.assertEqual(mark_running.call_count, 2)
        self.assertEqual(event.call_count, 2)
        self.assertEqual(
            mark_done.call_args_list,
            [
                call(first_job, ok=False),
                call(second_job, ok=True),
            ],
        )

        first_command = (
            executor.run.call_args_list[0].args[0]
        )
        second_command = (
            executor.run.call_args_list[1].args[0]
        )
        self.assertEqual(
            first_command,
            second_command,
        )

    @patch(
        "vpn.xhttp_runtime_recovery."
        "RuntimeCommandService.executor_for_server"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.mark_done"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.event"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.mark_running"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.create_job"
    )
    def test_helper_nonzero_is_not_retried(
        self,
        create_job,
        mark_running,
        event,
        mark_done,
        executor_for_server,
    ):
        job = object()
        create_job.return_value = job

        executor = Mock()
        executor.run.return_value = (
            self._failure_result()
        )
        executor_for_server.return_value = executor

        with self.assertRaisesRegex(
            RuntimeError,
            "helper rejected operation",
        ):
            self.adapter.remove(
                client_uuid=self.client_uuid,
                xray_email=self.xray_email,
                actor=self.actor,
            )

        self.assertEqual(executor.run.call_count, 1)
        self.assertEqual(create_job.call_count, 1)
        mark_running.assert_called_once_with(job)
        mark_done.assert_called_once_with(
            job,
            ok=False,
        )
        event.assert_called_once()

    @patch(
        "vpn.xhttp_runtime_recovery."
        "RuntimeCommandService.executor_for_server"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.mark_done"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.event"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.mark_running"
    )
    @patch(
        "vpn.xhttp_runtime_recovery."
        "JobService.create_job"
    )
    def test_persistent_transport_failure_marks_both_jobs_failed(
        self,
        create_job,
        mark_running,
        event,
        mark_done,
        executor_for_server,
    ):
        first_job = object()
        second_job = object()
        create_job.side_effect = [
            first_job,
            second_job,
        ]

        executor = Mock()
        executor.run.side_effect = [
            TimeoutError("timeout one"),
            OSError("connection lost"),
        ]
        executor_for_server.return_value = executor

        with self.assertRaisesRegex(
            RuntimeError,
            "one safe idempotent retry",
        ):
            self.adapter.check(
                client_uuid=self.client_uuid,
                xray_email=self.xray_email,
                actor=self.actor,
            )

        self.assertEqual(executor.run.call_count, 2)
        self.assertEqual(
            mark_done.call_args_list,
            [
                call(first_job, ok=False),
                call(second_job, ok=False),
            ],
        )
        self.assertEqual(event.call_count, 2)

    def test_invalid_action_is_rejected_before_runtime(self):
        with self.assertRaisesRegex(
            ValueError,
            "Недопустимое действие",
        ):
            self.adapter._run(
                action="restart",
                client_uuid=self.client_uuid,
                xray_email=self.xray_email,
                actor=self.actor,
            )
