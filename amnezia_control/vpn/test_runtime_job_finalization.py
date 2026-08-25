from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import TestCase

from jobs.models import Job
from servers.models import Server
from vpn.services import RuntimeCommandService


class RuntimeJobFinalizationTests(TestCase):
    def setUp(self):
        self.server = Server.objects.create(
            name="runtime-finalization-test",
            host="203.0.113.50",
        )

    def _executor_raising(self):
        executor = Mock()
        executor.run.side_effect = RuntimeError(
            "ssh unavailable"
        )
        return executor

    @patch.object(
        RuntimeCommandService,
        "executor_for_server",
    )
    def test_run_executor_exception_marks_job_failed(
        self,
        executor_for_server,
    ):
        executor_for_server.return_value = (
            self._executor_raising()
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "ssh unavailable",
        ):
            RuntimeCommandService.run(
                self.server,
                None,
                "runtime.ps_all",
                "docker ps",
            )

        job = Job.objects.get()

        self.assertEqual(
            job.status,
            Job.Status.FAILED,
        )
        self.assertIsNotNone(
            job.started_at
        )
        self.assertIsNotNone(
            job.finished_at
        )

        event = job.events.get()

        self.assertEqual(
            event.level,
            "error",
        )
        self.assertIn(
            "Execution failed",
            event.message,
        )

    @patch.object(
        RuntimeCommandService,
        "executor_for_server",
    )
    def test_expected_failure_wrapper_executor_exception_marks_failed(
        self,
        executor_for_server,
    ):
        executor_for_server.return_value = (
            self._executor_raising()
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "ssh unavailable",
        ):
            RuntimeCommandService.run_with_expected_failure(
                self.server,
                None,
                "awg2.list_all",
                "docker exec awg wg show",
                expected_error_patterns=(
                    "expected runtime error",
                ),
                fallback_message="fallback",
            )

        job = Job.objects.get()

        self.assertEqual(
            job.status,
            Job.Status.FAILED,
        )
        self.assertIsNotNone(
            job.finished_at
        )
        self.assertEqual(
            job.events.count(),
            1,
        )

    @patch.object(
        RuntimeCommandService,
        "executor_for_server",
    )
    def test_success_remains_success(
        self,
        executor_for_server,
    ):
        executor = Mock()

        executor.run.return_value = (
            SimpleNamespace(
                exit_code=0,
                stdout="ok",
                stderr="",
            )
        )

        executor_for_server.return_value = (
            executor
        )

        result = RuntimeCommandService.run(
            self.server,
            None,
            "runtime.ps_all",
            "docker ps",
        )

        self.assertEqual(
            result.exit_code,
            0,
        )

        job = Job.objects.get()

        self.assertEqual(
            job.status,
            Job.Status.SUCCESS,
        )
        self.assertIsNotNone(
            job.finished_at
        )
        self.assertEqual(
            job.events.count(),
            1,
        )

    @patch.object(
        RuntimeCommandService,
        "executor_for_server",
    )
    def test_nonzero_exit_is_terminal_failed(
        self,
        executor_for_server,
    ):
        executor = Mock()

        executor.run.return_value = (
            SimpleNamespace(
                exit_code=1,
                stdout="",
                stderr="command failed",
            )
        )

        executor_for_server.return_value = (
            executor
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "command failed",
        ):
            RuntimeCommandService.run(
                self.server,
                None,
                "runtime.ps_all",
                "docker ps",
            )

        job = Job.objects.get()

        self.assertEqual(
            job.status,
            Job.Status.FAILED,
        )
        self.assertIsNotNone(
            job.finished_at
        )
        self.assertEqual(
            job.events.get().exit_code,
            1,
        )

    @patch.object(
        RuntimeCommandService,
        "executor_for_server",
    )
    def test_expected_runtime_failure_is_terminal_success(
        self,
        executor_for_server,
    ):
        executor = Mock()

        executor.run.return_value = (
            SimpleNamespace(
                exit_code=1,
                stdout="",
                stderr="known harmless condition",
            )
        )

        executor_for_server.return_value = (
            executor
        )

        result = (
            RuntimeCommandService
            .run_with_expected_failure(
                self.server,
                None,
                "awg2.list_all",
                "docker exec awg wg show",
                expected_error_patterns=(
                    "known harmless condition",
                ),
                fallback_message=(
                    "using fallback"
                ),
            )
        )

        self.assertIsNone(result)

        job = Job.objects.get()

        self.assertEqual(
            job.status,
            Job.Status.SUCCESS,
        )
        self.assertIsNotNone(
            job.finished_at
        )

        event = job.events.get()

        self.assertEqual(
            event.level,
            "warning",
        )
        self.assertEqual(
            event.message,
            "using fallback",
        )
