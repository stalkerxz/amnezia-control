from django.contrib import admin, messages
from django.contrib.admin.utils import unquote
from django.core.exceptions import PermissionDenied
from django.http import (
    HttpResponseNotAllowed,
    HttpResponseRedirect,
)
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.translation import gettext_lazy as _

from .models import (
    ClientConfigRevision,
    ClientExpirationReminderLog,
    VPNClient,
    XHTTPDevice,
)
from .xhttp_forms import XHTTPDeviceCreateForm
from .xhttp_services import XHTTPDeviceService


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


@admin.register(ClientExpirationReminderLog)
class ClientExpirationReminderLogAdmin(admin.ModelAdmin):
    list_display = ("id", "client", "threshold_days", "expires_at_snapshot", "sent_at")
    list_filter = ("threshold_days", "sent_at")
    search_fields = ("client__name", "client__id")
    autocomplete_fields = ("client",)
    readonly_fields = ("client", "threshold_days", "expires_at_snapshot", "sent_at", "recipient_hash")
    ordering = ("-sent_at",)


@admin.register(XHTTPDevice)
class XHTTPDeviceAdmin(admin.ModelAdmin):
    add_form_template = (
        "admin/vpn/xhttpdevice/add_form.html"
    )

    change_form_template = (
        "admin/vpn/xhttpdevice/change_form.html"
    )

    list_display = (
        "id",
        "name",
        "device",
        "server",
        "status",
        "disable_reason",
        "client_uuid",
        "last_applied_at",
        "updated_at",
    )

    list_filter = (
        "status",
        "disable_reason",
        "server",
    )

    search_fields = (
        "name",
        "device__name",
        "device__account__display_name",
        "server__name",
        "=client_uuid",
        "xray_email",
    )

    exclude = (
        "config_blob_encrypted",
    )

    ordering = (
        "-created_at",
    )

    def get_readonly_fields(
        self,
        request,
        obj=None,
    ):
        return tuple(
            field.name
            for field in self.model._meta.fields
            if field.name
            != "config_blob_encrypted"
        )

    def has_add_permission(
        self,
        request,
    ):
        return super().has_add_permission(
            request
        )

    def has_delete_permission(
        self,
        request,
        obj=None,
    ):
        allowed = (
            super().has_delete_permission(
                request,
                obj,
            )
        )

        if not allowed:
            return False

        if (
            obj is not None
            and obj.status
            == XHTTPDevice.Status.DELETED
        ):
            return False

        return True

    def get_actions(
        self,
        request,
    ):
        actions = super().get_actions(
            request
        )

        # Never allow Django's raw bulk DELETE.
        actions.pop(
            "delete_selected",
            None,
        )

        return actions

    def get_urls(
        self,
    ):
        urls = super().get_urls()

        custom_urls = [
            path(
                (
                    "<int:object_id>/"
                    "lifecycle/<str:action>/"
                ),
                self.admin_site.admin_view(
                    self.lifecycle_view
                ),
                name=(
                    "vpn_xhttpdevice_lifecycle"
                ),
            ),
        ]

        return custom_urls + urls

    def add_view(
        self,
        request,
        form_url="",
        extra_context=None,
    ):
        if not self.has_add_permission(
            request
        ):
            raise PermissionDenied

        if request.method == "POST":
            form = XHTTPDeviceCreateForm(
                request.POST
            )

            if form.is_valid():
                try:
                    device = (
                        XHTTPDeviceService
                        .create_device(
                            device=(
                                form.cleaned_data[
                                    "device"
                                ]
                            ),
                            server=(
                                form.cleaned_data[
                                    "server"
                                ]
                            ),
                            name=(
                                form.cleaned_data[
                                    "name"
                                ]
                            ),
                            actor=request.user,
                        )
                    )

                except Exception as exc:
                    form.add_error(
                        None,
                        (
                            "XHTTP-подключение "
                            "не создано: "
                            f"{exc}"
                        ),
                    )

                else:
                    self.message_user(
                        request,
                        (
                            "XHTTP-подключение "
                            "создано безопасно "
                            "через runtime-сервис."
                        ),
                        level=messages.SUCCESS,
                    )

                    return HttpResponseRedirect(
                        reverse(
                            (
                                "admin:"
                                "vpn_xhttpdevice_change"
                            ),
                            args=[
                                device.pk
                            ],
                            current_app=(
                                self.admin_site.name
                            ),
                        )
                    )

        else:
            form = XHTTPDeviceCreateForm()

        context = {
            **self.admin_site.each_context(
                request
            ),
            "title": (
                "Добавить XHTTP-подключение"
            ),
            "opts": self.model._meta,
            "form": form,
            "media": (
                self.media
                + form.media
            ),
            "has_view_permission": (
                self.has_view_permission(
                    request
                )
            ),
        }

        if extra_context:
            context.update(
                extra_context
            )

        return TemplateResponse(
            request,
            self.add_form_template,
            context,
        )

    def lifecycle_view(
        self,
        request,
        object_id,
        action,
    ):
        if request.method != "POST":
            return HttpResponseNotAllowed(
                ["POST"]
            )

        device = self.get_object(
            request,
            object_id,
        )

        if device is None:
            return HttpResponseRedirect(
                reverse(
                    (
                        "admin:"
                        "vpn_xhttpdevice_changelist"
                    ),
                    current_app=(
                        self.admin_site.name
                    ),
                )
            )

        if not self.has_change_permission(
            request,
            device,
        ):
            raise PermissionDenied

        actions = {
            "check": (
                XHTTPDeviceService
                .check_runtime,
                (
                    "Runtime XHTTP "
                    "проверен."
                ),
            ),
            "disable": (
                XHTTPDeviceService.disable,
                (
                    "XHTTP-подключение "
                    "отключено."
                ),
            ),
            "enable": (
                XHTTPDeviceService.enable,
                (
                    "XHTTP-подключение "
                    "включено."
                ),
            ),
            "rotate": (
                XHTTPDeviceService.rotate,
                (
                    "XHTTP-подключение "
                    "перевыпущено. "
                    "Клиенту потребуется "
                    "новая конфигурация."
                ),
            ),
        }

        item = actions.get(
            action
        )

        if item is None:
            return HttpResponseNotAllowed(
                ["POST"]
            )

        callback, success_message = (
            item
        )

        try:
            callback(
                device=device,
                actor=request.user,
            )

        except Exception as exc:
            self.message_user(
                request,
                (
                    "Операция XHTTP "
                    "не выполнена: "
                    f"{exc}"
                ),
                level=messages.ERROR,
            )

        else:
            self.message_user(
                request,
                success_message,
                level=messages.SUCCESS,
            )

        return HttpResponseRedirect(
            reverse(
                (
                    "admin:"
                    "vpn_xhttpdevice_change"
                ),
                args=[
                    device.pk
                ],
                current_app=(
                    self.admin_site.name
                ),
            )
        )

    def delete_view(
        self,
        request,
        object_id,
        extra_context=None,
    ):
        # GET keeps Django's normal confirmation page.
        if request.method != "POST":
            return super().delete_view(
                request,
                object_id,
                extra_context=extra_context,
            )

        device = self.get_object(
            request,
            unquote(object_id),
        )

        if device is None:
            return super().delete_view(
                request,
                object_id,
                extra_context=extra_context,
            )

        if not self.has_delete_permission(
            request,
            device,
        ):
            raise PermissionDenied

        try:
            XHTTPDeviceService.soft_delete(
                device=device,
                actor=request.user,
            )

        except Exception as exc:
            self.message_user(
                request,
                (
                    "XHTTP-подключение "
                    "не удалено: "
                    f"{exc}"
                ),
                level=messages.ERROR,
            )

            return HttpResponseRedirect(
                reverse(
                    (
                        "admin:"
                        "vpn_xhttpdevice_change"
                    ),
                    args=[
                        device.pk
                    ],
                    current_app=(
                        self.admin_site.name
                    ),
                )
            )

        self.message_user(
            request,
            (
                "XHTTP-подключение "
                "удалено из runtime "
                "и помечено удалённым."
            ),
            level=messages.SUCCESS,
        )

        return HttpResponseRedirect(
            reverse(
                (
                    "admin:"
                    "vpn_xhttpdevice_changelist"
                ),
                current_app=(
                    self.admin_site.name
                ),
            )
        )
