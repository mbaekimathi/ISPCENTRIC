from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("core.urls")),
    path("", include("accounts.role_urls")),
    path("accounts/", include("accounts.urls")),
    path("billing/", include("billing.urls")),
]

if settings.DEBUG or getattr(settings, "SERVE_MEDIA", False):
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

admin.site.site_header = "ISPCENTRIC Admin"
admin.site.site_title = "ISPCENTRIC"
admin.site.index_title = "ISPCENTRIC administration"
