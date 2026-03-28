from django.contrib import admin
from .models import ClientConfigRevision, VPNClient


@admin.register(VPNClient)
class VPNClientAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "protocol_type", "status", "server", "created_at")
    list_filter = ("protocol_type", "status", "server")
    search_fields = ("name",)


@admin.register(ClientConfigRevision)
class ClientConfigRevisionAdmin(admin.ModelAdmin):
    list_display = ("id", "client", "revision_number", "protocol_type", "config_hash", "created_at")
    readonly_fields = ("client", "revision_number", "protocol_type", "config_hash", "created_at")
    exclude = ("config_blob_encrypted",)
