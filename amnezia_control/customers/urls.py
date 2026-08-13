from django.urls import path

from .views import (
    customer_detail_view,
    customers_list_view,
)

urlpatterns = [
    path("", customers_list_view, name="customers-list"),
    path("<int:pk>/", customer_detail_view, name="customers-detail"),
]
