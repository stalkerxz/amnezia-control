from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpResponse, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.text import slugify
from django.views.decorators.http import require_GET

from .models import XHTTPDevice
from .xhttp_forms import XHTTPDeviceCreateForm
from .xhttp_services import XHTTPDeviceService


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def xhttp_devices_view(request):
    if request.method == "POST":
        form = XHTTPDeviceCreateForm(request.POST)
        if form.is_valid():
            try:
                device = XHTTPDeviceService.create_device(
                    client=form.cleaned_data["client"],
                    name=form.cleaned_data["name"],
                    actor=request.user,
                )
                messages.success(request, f"XHTTP-устройство «{device.name}» создано.")
                return redirect("xhttp-devices")
            except Exception as exc:
                messages.error(request, f"Не удалось создать XHTTP-устройство: {exc}")
    else:
        initial = {}
        client_id = (request.GET.get("client") or "").strip()
        if client_id.isdigit():
            initial["client"] = int(client_id)
        form = XHTTPDeviceCreateForm(initial=initial)

    devices = (
        XHTTPDevice.objects.select_related("client", "client__server")
        .exclude(status=XHTTPDevice.Status.DELETED)
        .order_by("client__name", "name", "id")
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
def xhttp_device_download_view(request, pk: int):
    device = get_object_or_404(
        XHTTPDevice.objects.select_related("client"),
        pk=pk,
    )
    if device.status == XHTTPDevice.Status.DELETED:
        messages.error(request, "Конфигурация удалённого устройства недоступна.")
        return redirect("xhttp-devices")

    config = XHTTPDeviceService.latest_config(device)
    filename_base = slugify(f"{device.client.name}-{device.name}") or f"xhttp-device-{device.id}"
    response = HttpResponse(config, content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename_base}.json"'
    response["Cache-Control"] = "no-store, max-age=0"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@login_required
@user_passes_test(_admin_required)
def xhttp_device_action_view(request, pk: int, action: str):
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    device = get_object_or_404(
        XHTTPDevice.objects.select_related("client", "client__server"),
        pk=pk,
    )
    actions = {
        "rotate": (XHTTPDeviceService.rotate, "UUID перевыпущен. Скачайте новый конфиг."),
        "disable": (XHTTPDeviceService.disable, "XHTTP-устройство отключено."),
        "enable": (XHTTPDeviceService.enable, "XHTTP-устройство включено."),
        "delete": (XHTTPDeviceService.soft_delete, "XHTTP-устройство удалено."),
        "check": (XHTTPDeviceService.check_runtime, "UUID присутствует в Xray, конфигурация корректна."),
    }
    handler = actions.get(action)
    if not handler:
        messages.error(request, "Неизвестное действие XHTTP.")
        return redirect("xhttp-devices")

    callback, success_message = handler
    try:
        callback(device=device, actor=request.user)
        if device.last_error:
            device.last_error = ""
            device.save(update_fields=["last_error", "updated_at"])
        messages.success(request, success_message)
    except Exception as exc:
        device.last_error = str(exc)[:255]
        device.save(update_fields=["last_error", "updated_at"])
        messages.error(request, f"Операция XHTTP не выполнена: {exc}")
    return redirect("xhttp-devices")
