from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .models import ProtocolProfile, Server, ServerProtocol


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "host",
        "port",
        "public_endpoint_host",
        "public_endpoint_port",
        "is_enabled",
        "health_status",
        "last_runtime_sync_at",
        "updated_at",
    )
    search_fields = ("name", "host", "public_endpoint_host", "ssh_username")
    list_filter = ("is_enabled", "health_status", "created_at", "updated_at")
    readonly_fields = ("last_runtime_sync_at", "created_at", "updated_at")
    ordering = ("name",)
    fieldsets = (
        (_("Подключение"), {"fields": ("name", "host", "port", "ssh_username", "ssh_private_key_path")}),
        (_("Публичная точка доступа"), {"fields": ("public_endpoint_host", "public_endpoint_port")}),
        (_("Состояние"), {"fields": ("is_enabled", "health_status", "last_runtime_sync_at")}),
        (_("Техническое"), {"fields": ("created_at", "updated_at")}),
    )


@admin.register(ServerProtocol)
class ServerProtocolAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "server",
        "protocol_type",
        "enabled",
        "container_name",
        "container_status",
        "last_sync_at",
    )
    search_fields = ("server__name", "container_name", "container_status")
    list_filter = ("protocol_type", "enabled", "container_status", "last_sync_at")
    autocomplete_fields = ("server",)
    readonly_fields = ("runtime_metadata", "last_sync_at")
    ordering = ("server__name", "protocol_type")
    fieldsets = (
        (_("Базовые"), {"fields": ("server", "protocol_type", "enabled")}),
        (_("Контейнер"), {"fields": ("container_name", "container_status", "last_sync_at")}),
        (_("Метаданные рантайма"), {"fields": ("runtime_metadata",)}),
    )


@admin.register(ProtocolProfile)
class ProtocolProfileAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "server_protocol", "protocol_type", "status", "created_at")
    search_fields = ("name", "server_protocol__server__name")
    list_filter = ("protocol_type", "status", "created_at")
    autocomplete_fields = ("server_protocol",)
    readonly_fields = ("created_at",)
    ordering = ("-created_at",)
    fieldsets = (
        (_("Профиль"), {"fields": ("name", "server_protocol", "protocol_type", "status")}),
        (_("Шаблон"), {"fields": ("config_template",)}),
        (_("Техническое"), {"fields": ("created_at",)}),
    )
