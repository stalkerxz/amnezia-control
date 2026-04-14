from django.contrib import admin

from .models import Job, JobEvent


class JobEventInline(admin.TabularInline):
    model = JobEvent
    extra = 0
    fields = ("created_at", "level", "message", "exit_code")
    readonly_fields = ("created_at", "level", "message", "stdout", "stderr", "exit_code")
    show_change_link = True


@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    list_display = ("id", "created_at", "action", "status", "server", "actor", "started_at", "finished_at")
    search_fields = ("action", "server__name", "actor__username")
    list_filter = ("status", "action", "server", "created_at")
    autocomplete_fields = ("server", "actor")
    readonly_fields = ("created_at", "started_at", "finished_at")
    ordering = ("-created_at",)
    inlines = (JobEventInline,)
    fieldsets = (
        ("Задача", {"fields": ("action", "status", "server", "actor")}),
        ("Payload", {"fields": ("payload",)}),
        ("Время", {"fields": ("created_at", "started_at", "finished_at")}),
    )


@admin.register(JobEvent)
class JobEventAdmin(admin.ModelAdmin):
    list_display = ("id", "created_at", "job", "level", "exit_code", "message")
    search_fields = ("job__action", "job__server__name", "message", "stderr", "stdout")
    list_filter = ("level", "created_at")
    autocomplete_fields = ("job",)
    readonly_fields = ("created_at",)
    ordering = ("-created_at",)
    fieldsets = (
        ("Событие", {"fields": ("job", "level", "message", "exit_code", "created_at")}),
        ("Потоки", {"fields": ("stdout", "stderr")}),
    )
