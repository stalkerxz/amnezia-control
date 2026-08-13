from django.urls import path

from .access_views import (
    customer_access_create_view,
)
from .views import (
    customer_create_view,
    customer_detail_view,
    customer_device_create_view,
    customer_device_vpn_create_view,
    customers_list_view,
    merge_customer_view,
    move_device_view,
)

urlpatterns = [
    path("", customers_list_view, name="customers-list"),
    path(
        "new/",
        customer_create_view,
        name="customers-create",
    ),
    path(
        "<int:pk>/devices/new/",
        customer_device_create_view,
        name="customers-device-create",
    ),
    path(
        "devices/<int:device_id>/vpn/new/",
        customer_device_vpn_create_view,
        name="customers-device-vpn-create",
    ),
    path(
        "devices/<int:device_id>/move/",
        move_device_view,
        name="customers-device-move",
    ),
    path(
        "<int:pk>/access/",
        customer_access_create_view,
        name="customers-access-create",
    ),
    path(
        "<int:pk>/merge/",
        merge_customer_view,
        name="customers-merge",
    ),
    path("<int:pk>/", customer_detail_view, name="customers-detail"),
]
