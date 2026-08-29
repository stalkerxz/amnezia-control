import re
from pathlib import Path
from types import SimpleNamespace

from django.template.loader import render_to_string
from django.test import SimpleTestCase
from django.urls import reverse


class MobileOperatorShellTests(SimpleTestCase):

    def render_shell(
        self,
        *,
        path="/",
        url_name="dashboard",
        authenticated=True,
    ):
        request = SimpleNamespace(
            path=path,
            resolver_match=SimpleNamespace(
                url_name=url_name,
            ),
        )

        user = SimpleNamespace(
            is_authenticated=authenticated,
            username="operator",
        )

        return render_to_string(
            "partials/base.html",
            {
                "request": request,
                "user": user,
                "messages": [],
            },
        )

    def test_authenticated_shell_has_mobile_navigation(self):
        html = self.render_shell()

        self.assertIn(
            'class="mobile-bottom-nav"',
            html,
        )

        self.assertIn(
            'id="mobileMoreToggle"',
            html,
        )

        self.assertIn(
            "viewport-fit=cover",
            html,
        )

        self.assertIn(
            "css/app-mobile-v1.css",
            html,
        )

        self.assertIn(
            (
                f'href="'
                f'{reverse("customers-onboarding")}'
                f'"'
            ),
            html,
        )

    def test_anonymous_shell_has_no_mobile_operator_navigation(self):
        html = self.render_shell(
            authenticated=False,
        )

        self.assertNotIn(
            'class="mobile-bottom-nav"',
            html,
        )

        self.assertNotIn(
            'id="mobileMoreToggle"',
            html,
        )

    def test_onboarding_marks_create_as_current_mobile_destination(self):
        path = reverse(
            "customers-onboarding"
        )

        html = self.render_shell(
            path=path,
            url_name="customers-onboarding",
        )

        self.assertIn(
            (
                'class="mobile-nav-item '
                'mobile-nav-create active"'
            ),
            html,
        )

        self.assertIn(
            'aria-current="page"',
            html,
        )

    def test_rendered_shell_has_no_duplicate_ids(self):
        html = self.render_shell()

        ids = re.findall(
            r'\sid="([^"]+)"',
            html,
        )

        self.assertEqual(
            len(ids),
            len(set(ids)),
        )

    def test_mobile_assets_include_safe_area_and_more_menu_contract(self):
        root = (
            Path(__file__)
            .resolve()
            .parents[1]
        )

        css = (
            root
            / "static"
            / "css"
            / "app-mobile-v1.css"
        ).read_text(
            encoding="utf-8"
        )

        js = (
            root
            / "static"
            / "js"
            / "app-shell.js"
        ).read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "safe-area-inset-bottom",
            css,
        )

        self.assertIn(
            ".mobile-bottom-nav",
            css,
        )

        self.assertIn(
            "mobileMoreToggle",
            js,
        )

        self.assertIn(
            "sidebar-open",
            js,
        )
