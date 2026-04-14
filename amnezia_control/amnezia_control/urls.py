from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path
from core.views import dashboard_view, health_view

urlpatterns = [
    path("admin/", admin.site.urls),
    path("login/", auth_views.LoginView.as_view(template_name="registration/login.html"), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", dashboard_view, name="dashboard"),
    path("health/", health_view, name="health"),
    path("servers/", include("servers.urls")),
    path("clients/", include("vpn.urls")),
    path("audit/", include("audit.urls")),
    path("jobs/", include("jobs.urls")),
    path("portal/", include("portal.urls")),
]
