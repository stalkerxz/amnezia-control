from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST, require_http_methods

from servers.models import Server
from vpn.models import XHTTPDevice
from vpn.xhttp_forms import XHTTPDeviceCreateForm
from vpn.xhttp_services import XHTTPDeviceService

from .models import ClientDevice, CustomerAccount
from .views import operator_required


@login_required
@operator_required
@require_http_methods(["GET", "POST"])
def customer_device_xhttp_create_view(request, device_id):
    device = get_object_or_404(
        ClientDevice.objects.select_related("account"),
        pk=device_id,
    )
    account = device.account

    if account.status != CustomerAccount.Status.ACTIVE:
        return HttpResponseForbidden(
            "Альтернативное подключение можно создавать только для активного аккаунта."
        )

    if device.status != ClientDevice.Status.ACTIVE:
        return HttpResponseForbidden(
            "Альтернативное подключение можно создавать только для активного устройства."
        )

    if account.expires_at and account.expires_at <= timezone.now():
        return HttpResponseForbidden("Срок действия аккаунта истёк.")

    if device.expires_at and device.expires_at <= timezone.now():
        return HttpResponseForbidden("Срок действия устройства истёк.")

    default_server = (
        Server.objects.filter(is_enabled=True)
        .order_by("pk")
        .first()
    )

    if default_server is None:
        return HttpResponseBadRequest(
            "Сервер для альтернативного подключения не настроен."
        )

    if request.method == "POST":
        data = request.POST.copy()

        # Device ownership comes exclusively from URL context,
        # never from user input.
        data["device"] = str(device.pk)

        form = XHTTPDeviceCreateForm(data)

        if form.is_valid():
            try:
                xhttp = XHTTPDeviceService.create_device(
                    device=device,
                    server=form.cleaned_data["server"],
                    name=form.cleaned_data["name"],
                    performance_profile=form.cleaned_data[
                        "performance_profile"
                    ],
                    actor=request.user,
                )

                messages.success(
                    request,
                    (
                        "Альтернативное подключение "
                        f"«{xhttp.name}» создано: "
                        f"{xhttp.get_performance_profile_display()}."
                    ),
                )

                return redirect(
                    "customers-detail",
                    pk=account.pk,
                )

            except Exception as exc:
                form.add_error(
                    None,
                    (
                        "Не удалось создать альтернативное подключение: "
                        f"{exc}"
                    ),
                )

    else:
        form = XHTTPDeviceCreateForm(
            initial={
                "device": device.pk,
                "server": default_server.pk,
                "performance_profile": (
                    XHTTPDevice.PerformanceProfile.STANDARD
                ),
            }
        )

    return render(
        request,
        "customers/xhttp_connection_form.html",
        {
            "account": account,
            "device": device,
            "form": form,
        },
    )


@login_required
@operator_required
@require_POST
def customer_xhttp_action_view(request, pk, action):
    xhttp = get_object_or_404(
        XHTTPDevice.objects.select_related(
            "device",
            "device__account",
            "server",
        ),
        pk=pk,
    )

    account_id = xhttp.device.account_id

    actions = {
        "check": (
            XHTTPDeviceService.check_runtime,
            "Состояние альтернативного подключения проверено.",
        ),
        "disable": (
            XHTTPDeviceService.disable,
            "Альтернативное подключение отключено.",
        ),
        "enable": (
            XHTTPDeviceService.enable,
            "Альтернативное подключение включено.",
        ),
        "delete": (
            XHTTPDeviceService.soft_delete,
            "Альтернативное подключение удалено.",
        ),
    }

    try:
        if action == "rotate":
            requested_profile = (
                request.POST.get("performance_profile")
                or xhttp.performance_profile
            ).strip()

            if requested_profile not in XHTTPDevice.PerformanceProfile.values:
                raise ValueError("Некорректный XHTTP-профиль.")

            XHTTPDeviceService.rotate(
                device=xhttp,
                actor=request.user,
                performance_profile=requested_profile,
            )

            xhttp.refresh_from_db()

            success_message = (
                "Параметры альтернативного подключения обновлены. "
                f"Профиль: {xhttp.get_performance_profile_display()}. "
                "Нужно скачать новую конфигурацию."
            )

        else:
            handler = actions.get(action)

            if handler is None:
                return HttpResponseBadRequest(
                    "Неизвестное действие с альтернативным подключением."
                )

            callback, success_message = handler
            callback(device=xhttp, actor=request.user)
            xhttp.refresh_from_db()

        if xhttp.last_error:
            xhttp.last_error = ""
            xhttp.save(
                update_fields=[
                    "last_error",
                    "updated_at",
                ]
            )

        messages.success(request, success_message)

    except Exception as exc:
        xhttp.refresh_from_db()
        xhttp.last_error = str(exc)[:255]
        xhttp.save(
            update_fields=[
                "last_error",
                "updated_at",
            ]
        )

        messages.error(
            request,
            (
                "Операция с альтернативным подключением не выполнена: "
                f"{exc}"
            ),
        )

    return redirect(
        "customers-detail",
        pk=account_id,
    )
