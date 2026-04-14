from django.contrib import admin

from .models import SystemSettings


@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = ("id", "portal_link_lifetime_days", "portal_renewal_cooldown_hours", "updated_at")
    readonly_fields = ("created_at", "updated_at")

    def has_add_permission(self, request):
        if SystemSettings.objects.exists():
            return False
        return super().has_add_permission(request)
