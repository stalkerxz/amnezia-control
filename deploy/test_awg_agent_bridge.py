#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parent
    / "awg_agent_bridge.py"
)

spec = importlib.util.spec_from_file_location(
    "awg_agent_bridge",
    MODULE_PATH,
)

if spec is None or spec.loader is None:
    raise RuntimeError(
        "Cannot import awg_agent_bridge"
    )

bridge = importlib.util.module_from_spec(
    spec
)

spec.loader.exec_module(
    bridge
)


class RuntimeInfoPortTests(
    unittest.TestCase
):
    def setUp(self):
        self.original_spec = dict(
            bridge.AGENTS["awg4"]
        )

        self.original_forward = (
            bridge.forward
        )

    def tearDown(self):
        bridge.AGENTS["awg4"] = (
            self.original_spec
        )

        bridge.forward = (
            self.original_forward
        )

    def _health(self):
        return {
            "interface": "awg4",
            "interface_up": True,
            "listen_port": 51831,
            "reservation_count": 0,
        }

    def test_public_port_can_differ_from_listen_port(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            config = root / "awg4.conf"
            env = root / "awg4-agent.env"

            config.write_text(
                "[Interface]\n"
                "ListenPort = 51831\n"
                "Address = 10.78.0.1/24\n",
                encoding="utf-8",
            )

            env.write_text(
                "AWG_ENDPOINT="
                "201.10.72.6:51832\n",
                encoding="utf-8",
            )

            bridge.AGENTS["awg4"] = {
                "socket": root / "agent.sock",
                "config": config,
                "endpoint_env": env,
                "interface": "awg4",
            }

            bridge.forward = (
                lambda agent_name, payload:
                self._health()
            )

            info = bridge.local_runtime_info(
                "awg4"
            )

            self.assertEqual(
                info["listen_port"],
                51831,
            )

            self.assertEqual(
                info["udp_port"],
                51832,
            )

            self.assertEqual(
                info["peer_count"],
                0,
            )

    def test_missing_public_endpoint_falls_back_to_listen_port(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            config = root / "awg4.conf"

            config.write_text(
                "[Interface]\n"
                "ListenPort = 51831\n"
                "Address = 10.78.0.1/24\n",
                encoding="utf-8",
            )

            bridge.AGENTS["awg4"] = {
                "socket": root / "agent.sock",
                "config": config,
                "interface": "awg4",
            }

            bridge.forward = (
                lambda agent_name, payload:
                self._health()
            )

            info = bridge.local_runtime_info(
                "awg4"
            )

            self.assertEqual(
                info["listen_port"],
                51831,
            )

            self.assertEqual(
                info["udp_port"],
                51831,
            )


if __name__ == "__main__":
    unittest.main(
        verbosity=2,
    )
