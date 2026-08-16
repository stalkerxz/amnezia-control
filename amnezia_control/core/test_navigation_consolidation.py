from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class OperatorNavigationConsolidationTest(
    TestCase
):
    def setUp(self):
        self.operator = (
            get_user_model()
            .objects
            .create_user(
                username=(
                    "navigation-consolidation-operator"
                ),
                password="test-password",
                is_staff=True,
                is_owner=True,
            )
        )

        self.client.force_login(
            self.operator
        )

    @staticmethod
    def _primary_navigation(
        response,
    ):
        html = response.content.decode(
            "utf-8"
        )

        start_marker = (
            '<nav class="nav flex-column" '
            'aria-label="Разделы приложения">'
        )

        end_marker = "</nav>"

        start = html.index(
            start_marker
        )

        end = html.index(
            end_marker,
            start,
        )

        return html[
            start:end
        ]

    @staticmethod
    def _technical_navigation(
        response,
    ):
        html = response.content.decode(
            "utf-8"
        )

        start_marker = (
            '<nav class="nav flex-column '
            'sidebar-nav-aux" '
            'aria-label="Технические разделы">'
        )

        end_marker = "</nav>"

        start = html.index(
            start_marker
        )

        end = html.index(
            end_marker,
            start,
        )

        return html[
            start:end
        ]

    def test_primary_navigation_uses_accounts_only(
        self,
    ):
        response = self.client.get(
            reverse(
                "customers-list"
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        primary = (
            self._primary_navigation(
                response
            )
        )

        self.assertIn(
            ">Аккаунты<",
            primary.replace(
                "\n",
                "",
            ).replace(
                " ",
                "",
            ),
        )

        self.assertNotIn(
            'href="/clients/"',
            primary,
        )

        self.assertNotIn(
            'href="/xhttp/"',
            primary,
        )

    def test_legacy_links_live_in_technical_navigation(
        self,
    ):
        response = self.client.get(
            reverse(
                "customers-list"
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        technical = (
            self._technical_navigation(
                response
            )
        )

        self.assertIn(
            'href="/clients/"',
            technical,
        )

        self.assertIn(
            "Legacy · Клиенты",
            technical,
        )

        self.assertIn(
            'href="/xhttp/"',
            technical,
        )

        self.assertIn(
            "Legacy · XHTTP CDN",
            technical,
        )

    def test_legacy_clients_url_remains_available(
        self,
    ):
        response = self.client.get(
            reverse(
                "clients-list"
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Legacy · Клиенты",
        )

        self.assertContains(
            response,
            (
                "Технический резервный "
                "интерфейс VPN-конфигураций"
            ),
        )

    def test_legacy_xhttp_url_remains_available(
        self,
    ):
        response = self.client.get(
            reverse(
                "xhttp-devices"
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Legacy · XHTTP CDN",
        )

        self.assertContains(
            response,
            (
                "Технический резервный "
                "интерфейс XHTTP"
            ),
        )
