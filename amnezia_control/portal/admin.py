from django.contrib import admin

from .models import ClientPortalAccess


@admin.register(ClientPortalAccess)
class ClientPortalAccessAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "client",
        "enabled",
        "expires_at",
        "last_access_at",
        "created_at",
        "revoked_at",
        "token_hash_short",
    )
    search_fields = ("client__name", "client__runtime_peer_public_key", "client__runtime_address", "token_hash")
    list_filter = ("enabled", "created_at", "expires_at", "revoked_at")
    autocomplete_fields = ("client",)
    readonly_fields = (
        "client",
        "token_hash",
        "token_hash_short",
        "token_encrypted",
        "created_at",
        "expires_at",
        "last_access_at",
        "revoked_at",
    )
    ordering = ("-created_at",)
    fieldsets = (
        ("Доступ", {"fields": ("client", "enabled", "created_at", "expires_at", "last_access_at", "revoked_at")}),
        ("Токен (только для аудита)", {"fields": ("token_hash_short", "token_hash", "token_encrypted")}),
    )

    def token_hash_short(self, obj):
        value = obj.token_hash or ""
        if len(value) <= 16:
            return value
        return f"{value[:8]}…{value[-8:]}"

    token_hash_short.short_description = "Token hash"
