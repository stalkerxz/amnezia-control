from django.urls import path

from .access_views import (
    customer_access_create_view,
    customer_access_manage_view,
)
from .renewal_views import (
    customer_renewal_action_view,
)
from .views import (
    customer_create_view,
    customer_detail_view,
    customer_device_create_view,
    customer_device_edit_view,
    customer_device_status_view,
    customer_device_vpn_create_view,
    customer_edit_view,
    customer_status_view,
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
        "<int:pk>/edit/",
        customer_edit_view,
        name="customers-edit",
    ),
    path(
        "<int:pk>/status/",
        customer_status_view,
        name="customers-status",
    ),
    path(
        "devices/<int:device_id>/vpn/new/",
        customer_device_vpn_create_view,
        name="customers-device-vpn-create",
    ),
    path(
        "devices/<int:device_id>/edit/",
        customer_device_edit_view,
        name="customers-device-edit",
    ),
    path(
        "devices/<int:device_id>/status/",
        customer_device_status_view,
        name="customers-device-status",
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
        "<int:pk>/access/manage/",
        customer_access_manage_view,
        name="customers-access-manage",
    ),
    path(
        "<int:pk>/renewal/action/",
        customer_renewal_action_view,
        name="customers-renewal-action",
    ),
    path(
        "<int:pk>/merge/",
        merge_customer_view,
        name="customers-merge",
    ),
    path("<int:pk>/", customer_detail_view, name="customers-detail"),
]
