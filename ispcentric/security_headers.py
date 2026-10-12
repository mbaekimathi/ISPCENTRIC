"""Security headers: Referrer-Policy, Permissions-Policy, baseline CSP."""

from __future__ import annotations


class SecurityHeadersMiddleware:
    """
    Extra response headers for production hardening.

    CSP allows unsafe-inline because captive pay pages and staff dashboards rely
    on inline scripts/styles. Tighten later once assets are nonced.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from ispcentric.middleware import is_captive_portal_path

        response = self.get_response(request)
        captive = is_captive_portal_path(request.path or "")
        if captive and "Strict-Transport-Security" in response:
            del response["Strict-Transport-Security"]
        response.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(self), payment=()",
        )
        # Captive sheets must not upgrade http→https (walled garden is :80 only).
        if captive:
            response["Content-Security-Policy"] = (
                "default-src 'self' http: https: data: blob:; "
                "script-src 'self' 'unsafe-inline' http: https:; "
                "style-src 'self' 'unsafe-inline' http: https:; "
                "img-src 'self' data: blob: http: https:; "
                "font-src 'self' data: http: https:; "
                "connect-src 'self' http: https:; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self' http: https:"
            )
        else:
            # Baseline CSP — permissive enough not to break existing templates.
            response.setdefault(
                "Content-Security-Policy",
                (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline' https://maps.googleapis.com "
                    "https://maps.gstatic.com https://cdn.jsdelivr.net; "
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                    "img-src 'self' data: blob: https:; "
                    "font-src 'self' data: https://fonts.gstatic.com; "
                    "connect-src 'self' https://maps.googleapis.com "
                    "https://cdn.jsdelivr.net; "
                    "frame-ancestors 'none'; "
                    "base-uri 'self'; "
                    "form-action 'self'"
                ),
            )
        return response
