from django.urls import path
from .views import (
    server_create_client_view,
    server_detail_view,
    server_import_peers_view,
    server_list_view,
    server_sync_runtime_view,
)

urlpatterns = [
    path("", server_list_view, name="servers-list"),
    path("<int:pk>/", server_detail_view, name="servers-detail"),
    path("<int:pk>/sync-runtime/", server_sync_runtime_view, name="servers-sync-runtime"),
    path("<int:pk>/import-peers/", server_import_peers_view, name="servers-import-peers"),
    path("<int:pk>/create-client/<str:protocol_type>/", server_create_client_view, name="servers-create-client"),
]
