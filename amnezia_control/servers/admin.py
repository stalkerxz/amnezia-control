from django.contrib import admin

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
        ("Подключение", {"fields": ("name", "host", "port", "ssh_username", "ssh_private_key_path")}),
        ("Публичный endpoint", {"fields": ("public_endpoint_host", "public_endpoint_port")}),
        ("Состояние", {"fields": ("is_enabled", "health_status", "last_runtime_sync_at")}),
        ("Техническое", {"fields": ("created_at", "updated_at")}),
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
        ("Базовые", {"fields": ("server", "protocol_type", "enabled")}),
        ("Контейнер", {"fields": ("container_name", "container_status", "last_sync_at")}),
        ("Runtime metadata", {"fields": ("runtime_metadata",)}),
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
        ("Профиль", {"fields": ("name", "server_protocol", "protocol_type", "status")}),
        ("Шаблон", {"fields": ("config_template",)}),
        ("Техническое", {"fields": ("created_at",)}),
    )
