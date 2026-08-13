from django.urls import path

from .views import (
    customer_detail_view,
    customers_list_view,
    merge_customer_view,
    move_device_view,
)

urlpatterns = [
    path("", customers_list_view, name="customers-list"),
    path(
        "devices/<int:device_id>/move/",
        move_device_view,
        name="customers-device-move",
    ),
    path(
        "<int:pk>/merge/",
        merge_customer_view,
        name="customers-merge",
    ),
    path("<int:pk>/", customer_detail_view, name="customers-detail"),
]
