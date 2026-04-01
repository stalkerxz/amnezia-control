from django.urls import path
from .views import (
    client_action_view,
    client_download_config_view,
    client_qr_modal_view,
    clients_create_view,
    clients_detail_view,
    clients_import_view,
    clients_list_view,
    client_update_limits_view,
)

urlpatterns = [
    path("", clients_list_view, name="clients-list"),
    path("new/", clients_create_view, name="clients-create"),
    path("import/", clients_import_view, name="clients-import"),
    path("<int:pk>/", clients_detail_view, name="clients-detail"),
    path("<int:pk>/download/", client_download_config_view, name="clients-download"),
    path("<int:pk>/qr-modal/", client_qr_modal_view, name="clients-qr-modal"),
    path("<int:pk>/action/<str:action>/", client_action_view, name="clients-action"),
    path("<int:pk>/limits/update/", client_update_limits_view, name="clients-limits-update"),
]
