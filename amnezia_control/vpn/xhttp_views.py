from django.contrib import messages
from django.contrib.auth.decorators import (
    login_required,
    user_passes_test,
)
from django.http import (
    HttpResponse,
    HttpResponseNotAllowed,
)
from django.shortcuts import (
    get_object_or_404,
    redirect,
    render,
)
from django.utils.text import slugify
from django.views.decorators.http import require_GET

from servers.models import Server

from .models import XHTTPDevice
from .xhttp_forms import XHTTPDeviceCreateForm
from .xhttp_services import XHTTPDeviceService


def _admin_required(user):
    return (
        user.is_authenticated
        and (
            getattr(
                user,
                "is_owner",
                False,
            )
            or user.is_staff
        )
    )


@login_required
@user_passes_test(_admin_required)
def xhttp_devices_view(request):
    if request.method == "POST":
        form = XHTTPDeviceCreateForm(
            request.POST
        )

        if form.is_valid():
            try:
                xhttp_device = (
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

                messages.success(
                    request,
                    (
                        "XHTTP-подключение "
                        f"«{xhttp_device.name}» "
                        "создано."
                    ),
                )

                return redirect(
                    "xhttp-devices"
                )

            except Exception as exc:
                messages.error(
                    request,
                    (
                        "Не удалось создать "
                        "XHTTP-подключение: "
                        f"{exc}"
                    ),
                )

    else:
        initial = {}

        device_id = (
            request.GET.get(
                "device"
            )
            or ""
        ).strip()

        if device_id.isdigit():
            initial["device"] = int(
                device_id
            )

        server = (
            Server.objects
            .filter(
                is_enabled=True,
            )
            .order_by("pk")
            .first()
        )

        if server is not None:
            initial["server"] = (
                server.pk
            )

        form = XHTTPDeviceCreateForm(
            initial=initial,
        )

    devices = (
        XHTTPDevice.objects
        .select_related(
            "device",
            "device__account",
            "server",
        )
        .exclude(
            status=(
                XHTTPDevice.Status.DELETED
            ),
        )
        .order_by(
            "device__account__display_name",
            "device__name",
            "name",
            "id",
        )
    )

    return render(
        request,
        "vpn/xhttp_devices.html",
        {
            "form": form,
            "devices": devices,
        },
    )


@login_required
@user_passes_test(_admin_required)
@require_GET
def xhttp_device_download_view(
    request,
    pk: int,
):
    device = get_object_or_404(
        XHTTPDevice.objects.select_related(
            "device",
            "device__account",
            "server",
        ),
        pk=pk,
    )

    if (
        device.status
        == XHTTPDevice.Status.DELETED
    ):
        messages.error(
            request,
            (
                "Конфигурация удалённого "
                "подключения недоступна."
            ),
        )

        return redirect(
            "xhttp-devices"
        )

    config = (
        XHTTPDeviceService.latest_config(
            device
        )
    )

    owner_name = (
        f"{device.device.account.display_name}-"
        f"{device.device.name}"
    )

    filename_base = (
        slugify(
            f"{owner_name}-{device.name}"
        )
        or f"xhttp-device-{device.id}"
    )

    response = HttpResponse(
        config,
        content_type=(
            "application/json; charset=utf-8"
        ),
    )

    response["Content-Disposition"] = (
        "attachment; "
        f'filename="{filename_base}.json"'
    )

    response["Cache-Control"] = (
        "no-store, max-age=0"
    )

    response["Pragma"] = "no-cache"

    response[
        "X-Content-Type-Options"
    ] = "nosniff"

    return response


@login_required
@user_passes_test(_admin_required)
def xhttp_device_action_view(
    request,
    pk: int,
    action: str,
):
    if request.method != "POST":
        return HttpResponseNotAllowed(
            ["POST"]
        )

    device = get_object_or_404(
        XHTTPDevice.objects.select_related(
            "device",
            "device__account",
            "server",
        ),
        pk=pk,
    )

    actions = {
        "rotate": (
            XHTTPDeviceService.rotate,
            (
                "UUID перевыпущен. "
                "Скачайте новый конфиг."
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
        "delete": (
            XHTTPDeviceService.soft_delete,
            (
                "XHTTP-подключение "
                "удалено."
            ),
        ),
        "check": (
            XHTTPDeviceService.check_runtime,
            (
                "UUID присутствует в Xray, "
                "конфигурация корректна."
            ),
        ),
    }

    handler = actions.get(
        action
    )

    if not handler:
        messages.error(
            request,
            "Неизвестное действие XHTTP.",
        )

        return redirect(
            "xhttp-devices"
        )

    callback, success_message = (
        handler
    )

    try:
        callback(
            device=device,
            actor=request.user,
        )

        if device.last_error:
            device.last_error = ""

            device.save(
                update_fields=[
                    "last_error",
                    "updated_at",
                ]
            )

        messages.success(
            request,
            success_message,
        )

    except Exception as exc:
        device.last_error = str(
            exc
        )[:255]

        device.save(
            update_fields=[
                "last_error",
                "updated_at",
            ]
        )

        messages.error(
            request,
            (
                "Операция XHTTP "
                "не выполнена: "
                f"{exc}"
            ),
        )

    return redirect(
        "xhttp-devices"
    )
