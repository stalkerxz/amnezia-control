import importlib.machinery
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


HELPER_PATH = Path(__file__).with_name("amnezia-control-xhttp")
loader = importlib.machinery.SourceFileLoader("xhttp_helper", str(HELPER_PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


def base_config(clients=None):
    return {
        "api": {
            "tag": "api",
            "listen": "127.0.0.1:10085",
            "services": ["HandlerService"],
        },
        "inbounds": [
            {
                "tag": "vless-xhttp-yandex",
                "listen": "127.0.0.1",
                "port": 8080,
                "protocol": "vless",
                "settings": {"clients": list(clients or [])},
                "streamSettings": {
                    "network": "xhttp",
                    "xhttpSettings": {
                        "path": "/api/ad4f850643d5e660f09d31f9",
                    },
                },
            }
        ],
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
            }
        ],
    }


UUID = "11111111-2222-4333-8444-555555555555"
EMAIL = "xhttp-11111111222243338444555555555555"
TARGET = {"id": UUID, "email": EMAIL}


class HelperTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        helper.CONFIG_PATH = self.root / "config.json"
        helper.BACKUP_DIR = self.root / "backups"
        helper.CONFIG_PATH.write_text(
            json.dumps(base_config()),
            encoding="utf-8",
        )
        self.runtime = []

        self.patches = [
            patch.object(helper, "ensure_service_active", lambda: None),
            patch.object(helper, "test_config", lambda path: None),
            patch.object(
                helper,
                "runtime_users",
                lambda: [dict(item) for item in self.runtime],
            ),
            patch.object(helper, "hot_add", self.hot_add),
            patch.object(helper, "hot_remove", self.hot_remove),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()

    def read_clients(self):
        cfg = json.loads(
            helper.CONFIG_PATH.read_text(encoding="utf-8")
        )
        return cfg["inbounds"][0]["settings"]["clients"]

    def hot_add(self, config, uuid_text, email):
        if any(
            item["id"] == uuid_text or item["email"] == email
            for item in self.runtime
        ):
            raise AssertionError("duplicate runtime add")
        self.runtime.append({"id": uuid_text, "email": email})

    def hot_remove(self, email):
        matches = [
            item for item in self.runtime if item["email"] == email
        ]
        if len(matches) != 1:
            raise AssertionError(
                "runtime remove expected exactly one user"
            )
        self.runtime.remove(matches[0])

    def test_add_updates_file_and_runtime_without_restart(self):
        changed, backup = helper.apply_action("add", UUID, EMAIL)
        self.assertTrue(changed)
        self.assertIsNotNone(backup)
        self.assertEqual(self.read_clients(), [TARGET])
        self.assertEqual(self.runtime, [TARGET])

    def test_remove_updates_file_and_runtime(self):
        helper.CONFIG_PATH.write_text(
            json.dumps(base_config([TARGET])),
            encoding="utf-8",
        )
        self.runtime[:] = [dict(TARGET)]

        changed, backup = helper.apply_action("remove", UUID, EMAIL)

        self.assertTrue(changed)
        self.assertIsNotNone(backup)
        self.assertEqual(self.read_clients(), [])
        self.assertEqual(self.runtime, [])

    def test_add_heals_runtime_only_state_without_duplicate_add(self):
        self.runtime[:] = [dict(TARGET)]

        with patch.object(
            helper,
            "hot_add",
            side_effect=AssertionError("must not add"),
        ):
            changed, _ = helper.apply_action("add", UUID, EMAIL)

        self.assertTrue(changed)
        self.assertEqual(self.read_clients(), [TARGET])
        self.assertEqual(self.runtime, [TARGET])

    def test_remove_heals_file_only_state_without_runtime_remove(self):
        helper.CONFIG_PATH.write_text(
            json.dumps(base_config([TARGET])),
            encoding="utf-8",
        )

        with patch.object(
            helper,
            "hot_remove",
            side_effect=AssertionError("must not remove"),
        ):
            changed, _ = helper.apply_action("remove", UUID, EMAIL)

        self.assertTrue(changed)
        self.assertEqual(self.read_clients(), [])
        self.assertEqual(self.runtime, [])

    def test_check_requires_persisted_and_runtime(self):
        helper.CONFIG_PATH.write_text(
            json.dumps(base_config([TARGET])),
            encoding="utf-8",
        )
        self.runtime[:] = [dict(TARGET)]

        changed, backup = helper.apply_action("check", UUID, EMAIL)

        self.assertFalse(changed)
        self.assertIsNone(backup)

        self.runtime[:] = []
        with self.assertRaises(helper.ManagedError):
            helper.apply_action("check", UUID, EMAIL)

    def test_failed_hot_add_restores_file_and_runtime(self):
        original = json.loads(
            helper.CONFIG_PATH.read_text(encoding="utf-8")
        )

        with patch.object(
            helper,
            "hot_add",
            side_effect=helper.ManagedError("boom"),
        ):
            with self.assertRaises(helper.ManagedError):
                helper.apply_action("add", UUID, EMAIL)

        self.assertEqual(
            json.loads(
                helper.CONFIG_PATH.read_text(encoding="utf-8")
            ),
            original,
        )
        self.assertEqual(self.runtime, [])

    def test_source_contains_no_xray_restart(self):
        source = HELPER_PATH.read_text(encoding="utf-8")
        self.assertNotIn('systemctl", "restart', source)
        self.assertNotIn("systemctl', 'restart", source)
        self.assertIn('"api",\n                "adu"', source)
        self.assertIn('"api",\n            "rmu"', source)


if __name__ == "__main__":
    unittest.main()
