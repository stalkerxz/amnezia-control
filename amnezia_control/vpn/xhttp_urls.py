from django.urls import path

from .xhttp_views import (
    xhttp_device_action_view,
    xhttp_device_download_view,
    xhttp_devices_view,
)


urlpatterns = [
    path("", xhttp_devices_view, name="xhttp-devices"),
    path("<int:pk>/download/", xhttp_device_download_view, name="xhttp-device-download"),
    path("<int:pk>/action/<str:action>/", xhttp_device_action_view, name="xhttp-device-action"),
]
