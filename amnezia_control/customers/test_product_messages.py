import ast
from pathlib import Path

from django.test import SimpleTestCase


class ProductMessageCopyTest(
    SimpleTestCase
):

    def test_python_user_copy_is_productized(
        self,
    ):
        root = Path(__file__).resolve().parent

        views = (
            root / "views.py"
        ).read_text()

        portal = (
            root / "portal_views.py"
        ).read_text()

        def semantic_strings(source):
            tree = ast.parse(source)

            return [
                node.value
                for node in ast.walk(tree)
                if isinstance(
                    node,
                    ast.Constant,
                )
                and isinstance(
                    node.value,
                    str,
                )
            ]

        view_strings = semantic_strings(
            views
        )

        portal_strings = semantic_strings(
            portal
        )

        old_operator_copy = (
            "FULL, SELECTIVE или ",
            "VLESS/XHTTP-подключения ",
            (
                "XHTTP-подключение можно "
                "создавать "
            ),
            (
                "Активный XHTTP-сервер "
                "не настроен."
            ),
            "VLESS/XHTTP-подключение ",
            "VLESS/XHTTP-подключение: ",
            "XHTTP runtime проверен.",
            "XHTTP-подключение отключено.",
            "XHTTP-подключение включено.",
            "XHTTP UUID перевыпущен.",
            "Нужно скачать новый конфиг.",
            "XHTTP-подключение удалено.",
            "Неизвестное действие XHTTP.",
            "Операция XHTTP ",
            "AWG2-подключение режима ",
        )

        for marker in old_operator_copy:
            self.assertFalse(
                any(
                    marker in value
                    for value in view_strings
                ),
                msg=(
                    "Old operator user-facing "
                    f"copy survived: {marker}"
                ),
            )

        old_portal_copy = (
            (
                "VLESS/XHTTP-подключение "
                "недоступно."
            ),
            "сохранённого JSON-конфига.",
        )

        for marker in old_portal_copy:
            self.assertFalse(
                any(
                    marker in value
                    for value in portal_strings
                ),
                msg=(
                    "Old portal user-facing "
                    f"copy survived: {marker}"
                ),
            )

        required_operator_copy = (
            (
                "Теперь добавьте нужные "
                "подключения"
            ),
            (
                "Альтернативное подключение "
                "можно создавать"
            ),
            (
                "Сервер для альтернативного "
                "подключения"
            ),
            (
                "Альтернативное подключение "
                "отключено."
            ),
            (
                "Альтернативное подключение "
                "включено."
            ),
            (
                "Параметры альтернативного "
                "подключения"
            ),
            (
                "Операция с альтернативным "
                "подключением"
            ),
            (
                "«Только выбранные сервисы»"
            ),
            (
                "«Весь интернет через VPN»"
            ),
        )

        for marker in required_operator_copy:
            self.assertTrue(
                any(
                    marker in value
                    for value in view_strings
                ),
                msg=(
                    "Required operator "
                    f"product copy missing: {marker}"
                ),
            )

        required_portal_copy = (
            (
                "Альтернативное подключение "
                "недоступно."
            ),
            (
                "сохранённой конфигурации."
            ),
        )

        for marker in required_portal_copy:
            self.assertTrue(
                any(
                    marker in value
                    for value in portal_strings
                ),
                msg=(
                    "Required portal "
                    f"product copy missing: {marker}"
                ),
            )

        # Internal implementation must remain.
        internal_views = (
            "VPNClient.ProtocolType.AWG2",
            (
                "VPNClientCreateForm."
                "ROUTING_MODE_FULL"
            ),
            (
                "VPNClientCreateForm."
                "ROUTING_MODE_SELECTIVE"
            ),
            "XHTTPDeviceService",
            "VPNClientService",
            "_device_vpn_client_name",
            'else "FULL"',
            '"SELECT"',
        )

        for marker in internal_views:
            self.assertIn(
                marker,
                views,
            )

        internal_portal = (
            "XHTTPDeviceService",
            "VPNClientService",
            "XHTTPDevice",
            "VPNClient",
            '"amneziawg"',
        )

        for marker in internal_portal:
            self.assertIn(
                marker,
                portal,
            )
