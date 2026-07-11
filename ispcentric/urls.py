from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.decorators.cache import cache_control
from django.views.static import serve

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("core.urls")),
    path("", include("accounts.role_urls")),
    path("accounts/", include("accounts.urls")),
    path("billing/", include("billing.urls")),
]

# django.conf.urls.static.static() is a no-op when DEBUG=False, so hosted
# media must use an explicit serve view. Long cache headers keep avatars cheap.
_media_serve = cache_control(public=True, max_age=60 * 60 * 24 * 30)(serve)

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
elif getattr(settings, "SERVE_MEDIA", False):
    urlpatterns += [
        re_path(
            r"^media/(?P<path>.*)$",
            _media_serve,
            {"document_root": str(settings.MEDIA_ROOT)},
        ),
    ]

admin.site.site_header = "ISPCENTRIC Admin"
admin.site.site_title = "ISPCENTRIC"
admin.site.index_title = "ISPCENTRIC administration"
