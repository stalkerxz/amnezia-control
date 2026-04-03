from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import AuditLog


class AuditListViewTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin", password="123", is_staff=True)
        self.other = get_user_model().objects.create_user("other-admin", password="123", is_staff=True)
        AuditLog.objects.create(
            actor=self.user,
            action="vpn.client.reissue",
            entity_type="vpn_client",
            entity_id="10",
            details={"client": "operator-laptop"},
        )
        AuditLog.objects.create(
            actor=self.other,
            action="server.sync_runtime",
            entity_type="server",
            entity_id="1",
            details={"status": "ok"},
        )

    def test_audit_list_renders_filters_and_details_panel(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("audit-list"))
        self.assertContains(response, "Журнал аудита")
        self.assertContains(response, "Тип сущности")
        self.assertContains(response, "Показать")

    def test_audit_list_filters_by_entity_type(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("audit-list"), {"entity_type": "vpn_client"})
        self.assertContains(response, "vpn.client.reissue")
        self.assertNotContains(response, "server.sync_runtime")

    def test_audit_list_filters_by_my_actions(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("audit-list"), {"operator_scope": "mine"})
        self.assertContains(response, "vpn.client.reissue")
        self.assertNotContains(response, "server.sync_runtime")

    def test_audit_list_shows_operator_labels(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("audit-list"))
        self.assertContains(response, "Моё")
        self.assertContains(response, "Другой админ")
