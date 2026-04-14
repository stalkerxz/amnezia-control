from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from .models import ClientConfigRevision, VPNClient


@admin.register(VPNClient)
class VPNClientAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "server",
        "protocol_type",
        "status",
        "limit_state",
        "disable_reason",
        "runtime_peer_public_key",
        "runtime_address",
        "created_at",
    )
    list_filter = ("protocol_type", "status", "limit_state", "disable_reason", "server", "imported_from_runtime")
    search_fields = ("name", "runtime_peer_public_key", "runtime_address", "server__name")
    autocomplete_fields = ("server", "profile", "created_by")
    readonly_fields = (
        "imported_from_runtime",
        "runtime_peer_public_key",
        "runtime_address",
        "last_runtime_sync_at",
        "traffic_used_bytes",
        "traffic_last_sync_at",
        "traffic_sync_error",
        "created_at",
    )
    ordering = ("-created_at",)
    fieldsets = (
        (_("Базовые"), {"fields": ("server", "name", "protocol_type", "profile", "created_by")}),
        (_("Статус"), {"fields": ("status", "limit_state", "disable_reason")}),
        (
            _("Лимиты"),
            {
                "fields": ("expires_at", "traffic_limit_bytes", "traffic_used_bytes", "traffic_last_sync_at", "traffic_sync_error")
            },
        ),
        (_("Серверные данные"), {"fields": ("imported_from_runtime", "runtime_peer_public_key", "runtime_address", "last_runtime_sync_at")}),
        (_("Техническое"), {"fields": ("created_at",)}),
    )


@admin.register(ClientConfigRevision)
class ClientConfigRevisionAdmin(admin.ModelAdmin):
    list_display = ("id", "client", "revision_number", "protocol_type", "config_hash", "created_at")
    search_fields = ("client__name", "config_hash")
    list_filter = ("protocol_type", "created_at")
    ordering = ("-created_at",)
    autocomplete_fields = ("client",)
    readonly_fields = ("client", "revision_number", "protocol_type", "config_hash", "created_at")
    exclude = ("config_blob_encrypted",)
