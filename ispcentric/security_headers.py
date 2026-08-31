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
        response = self.get_response(request)
        response.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(self), payment=()",
        )
        # Baseline CSP — permissive enough not to break existing templates.
        response.setdefault(
            "Content-Security-Policy",
            (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://maps.googleapis.com "
                "https://maps.gstatic.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "img-src 'self' data: blob: https:; "
                "font-src 'self' data: https://fonts.gstatic.com; "
                "connect-src 'self' https://maps.googleapis.com; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            ),
        )
        return response
