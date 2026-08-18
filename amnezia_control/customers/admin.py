from django.contrib import admin

from .models import ClientDevice, CustomerAccount


class ClientDeviceInline(admin.TabularInline):
    model = ClientDevice
    extra = 0
    fields = ("name", "platform", "status", "created_at")
    readonly_fields = ("created_at",)


@admin.register(CustomerAccount)
class CustomerAccountAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "display_name",
        "email",
        "status",
        "expires_at",
        "user",
        "created_at",
    )
    list_filter = ("status", "expires_at")
    search_fields = ("display_name", "email")
    autocomplete_fields = ("user", "created_by")
    readonly_fields = ("created_at", "updated_at")
    inlines = (ClientDeviceInline,)


@admin.register(ClientDevice)
class ClientDeviceAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "account",
        "platform",
        "status",
        "created_at",
    )
    list_filter = ("platform", "status")
    search_fields = ("name", "account__display_name", "account__email")
    autocomplete_fields = ("account",)
    readonly_fields = ("created_at", "updated_at")
