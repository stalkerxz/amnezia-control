from django.urls import path
from .views import server_detail_view, server_list_view, server_sync_runtime_view

urlpatterns = [
    path("", server_list_view, name="servers-list"),
    path("<int:pk>/", server_detail_view, name="servers-detail"),
    path("<int:pk>/sync-runtime/", server_sync_runtime_view, name="servers-sync-runtime"),
]
