from django.urls import path

from .portal_views import (
    CustomerLoginView,
    CustomerLogoutView,
    customer_portal_home_view,
    customer_renewal_request_view,
    customer_vpn_download_view,
    customer_vpn_qr_view,
    customer_xhttp_download_view,
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
        "renewal/request/",
        customer_renewal_request_view,
        name="customer-portal-renewal-request",
    ),
    path(
        "vpn/<int:pk>/download/",
        customer_vpn_download_view,
        name="customer-portal-vpn-download",
    ),
    path(
        "vpn/<int:pk>/qr/",
        customer_vpn_qr_view,
        name="customer-portal-vpn-qr",
    ),
    path(
        "xhttp/<int:pk>/download/",
        customer_xhttp_download_view,
        name="customer-portal-xhttp-download",
    ),
    path(
        "",
        customer_portal_home_view,
        name="customer-portal-home",
    ),
]
