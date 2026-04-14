from django.contrib import admin

from .models import ClientPortalAccess


@admin.register(ClientPortalAccess)
class ClientPortalAccessAdmin(admin.ModelAdmin):
    list_display = ("id", "client", "enabled", "expires_at", "last_access_at", "created_at", "revoked_at")
    search_fields = ("client__name",)
    readonly_fields = ("token_hash", "token_encrypted", "created_at", "expires_at", "last_access_at", "revoked_at")
