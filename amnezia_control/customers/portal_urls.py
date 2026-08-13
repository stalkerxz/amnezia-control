from django.urls import path

from .portal_views import (
    CustomerLoginView,
    CustomerLogoutView,
    customer_portal_home_view,
)


urlpatterns = [
    path(
        "login/",
        CustomerLoginView.as_view(),
        name="customer-portal-login",
    ),
    path(
        "logout/",
        CustomerLogoutView.as_view(),
        name="customer-portal-logout",
    ),
    path(
        "",
        customer_portal_home_view,
        name="customer-portal-home",
    ),
]
