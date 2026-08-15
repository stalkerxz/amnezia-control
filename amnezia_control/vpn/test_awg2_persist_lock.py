
from types import SimpleNamespace
from unittest.mock import Mock

from django.test import SimpleTestCase

from vpn.services import (
    AWG2Adapter,
    AWGLegacyAdapter,
)


class AWG2PersistLockTest(
    SimpleTestCase
):

    @staticmethod
    def _awg2_adapter(
        *,
        config_path=(
            "/opt/amnezia/awg/"
            "awg0.conf"
        ),
        container=(
            "amnezia-awg2"
        ),
    ):
        adapter = object.__new__(
            AWG2Adapter
        )

        adapter.server = (
            SimpleNamespace()
        )

        adapter.protocol = (
            SimpleNamespace(
                container_name=(
                    container
                ),
                runtime_metadata={
                    "config_path": (
                        config_path
                    ),
                },
            )
        )

        adapter._run = Mock()

        return adapter

    def test_awg2_persist_uses_host_flock(
        self,
    ):
        adapter = (
            self._awg2_adapter()
        )

        actor = object()

        adapter._persist_runtime(
            actor
        )

        adapter._run.assert_called_once()

        call = (
            adapter
            ._run
            .call_args
        )

        self.assertEqual(
            call.args[0],
            actor,
        )

        self.assertEqual(
            call.args[1],
            "awg2.save_runtime",
        )

        self.assertEqual(
            call.args[2],
            (
                "flock "
                "-x "
                "-w 30 "
                "/run/lock/"
                "amnezia-control-awg2-save.lock "
                "docker exec "
                "amnezia-awg2 "
                "awg-quick save "
                "/opt/amnezia/awg/"
                "awg0.conf"
            ),
        )

        self.assertEqual(
            call.kwargs,
            {
                "sensitive_output": True,
            },
        )

    def test_multiple_adapters_use_same_lock(
        self,
    ):
        first = (
            self._awg2_adapter()
        )

        second = (
            self._awg2_adapter()
        )

        first._persist_runtime(
            None
        )

        second._persist_runtime(
            None
        )

        first_command = (
            first
            ._run
            .call_args
            .args[2]
        )

        second_command = (
            second
            ._run
            .call_args
            .args[2]
        )

        self.assertEqual(
            first_command,
            second_command,
        )

        self.assertIn(
            (
                "/run/lock/"
                "amnezia-control-"
                "awg2-save.lock"
            ),
            first_command,
        )

    def test_missing_config_path_is_noop(
        self,
    ):
        adapter = (
            self._awg2_adapter(
                config_path=""
            )
        )

        adapter._persist_runtime(
            None
        )

        adapter._run.assert_not_called()

    def test_unsafe_config_path_is_rejected(
        self,
    ):
        adapter = (
            self._awg2_adapter(
                config_path=(
                    "/tmp/unsafe.conf"
                )
            )
        )

        with self.assertRaises(
            RuntimeError
        ):
            adapter._persist_runtime(
                None
            )

        adapter._run.assert_not_called()

    def test_legacy_awg_does_not_persist_here(
        self,
    ):
        adapter = object.__new__(
            AWGLegacyAdapter
        )

        adapter.server = (
            SimpleNamespace()
        )

        adapter.protocol = (
            SimpleNamespace(
                container_name=(
                    "legacy-awg"
                ),
                runtime_metadata={
                    "config_path": (
                        "/opt/amnezia/awg/"
                        "wg0.conf"
                    ),
                },
            )
        )

        adapter._run = Mock()

        adapter._persist_runtime(
            None
        )

        adapter._run.assert_not_called()
