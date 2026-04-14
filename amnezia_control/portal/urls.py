from django.urls import path

from .views import (
    portal_download_config_view,
    portal_home_view,
    portal_qr_view,
    portal_reissue_config_view,
    portal_request_renewal_view,
)

urlpatterns = [
    path("<str:token>/", portal_home_view, name="portal-home"),
    path("<str:token>/config/", portal_download_config_view, name="portal-config"),
    path("<str:token>/qr/", portal_qr_view, name="portal-qr"),
    path("<str:token>/request-renewal/", portal_request_renewal_view, name="portal-request-renewal"),
    path("<str:token>/reissue-config/", portal_reissue_config_view, name="portal-reissue-config"),
]
