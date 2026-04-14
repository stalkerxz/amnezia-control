from django.contrib import admin

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("id", "created_at", "action", "entity_type", "entity_id", "actor")
    search_fields = ("action", "entity_type", "entity_id", "actor__username")
    list_filter = ("action", "entity_type", "created_at")
    autocomplete_fields = ("actor",)
    readonly_fields = ("actor", "action", "entity_type", "entity_id", "details", "created_at")
    ordering = ("-created_at",)
    fieldsets = (
        ("Событие", {"fields": ("created_at", "action", "actor")}),
        ("Объект", {"fields": ("entity_type", "entity_id")}),
        ("Детали", {"fields": ("details",)}),
    )
