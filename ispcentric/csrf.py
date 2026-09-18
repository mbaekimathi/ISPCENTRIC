"""CSRF failure handling that returns JSON for API / captive-portal fetches."""

from __future__ import annotations

from django.http import HttpResponseForbidden, JsonResponse
from django.middleware.csrf import REASON_NO_CSRF_COOKIE, REASON_NO_REFERER


def csrf_failure(request, reason: str = ""):
    """
    Prefer JSON when the client asked for it (Hotspot/PPPoE pay fetch calls).

    Captive browsers often lose the CSRF cookie; returning HTML made
    ``response.json()`` throw "Unexpected token '<' ... is not valid JSON".
    """
    wants_json = "application/json" in (request.headers.get("Accept") or "")
    if not wants_json and request.headers.get("X-Requested-With") == "XMLHttpRequest":
        wants_json = True
    if not wants_json:
        path = request.path or ""
        if "/pay/" in path or path.endswith("/voucher/") or "/voucher/" in path:
            wants_json = True

    message = "Security check failed. Refresh the page and try again."
    if reason in {REASON_NO_CSRF_COOKIE, "CSRF cookie not set."}:
        message = "Session expired. Refresh the page and try again."
    elif reason == REASON_NO_REFERER:
        message = "Security check failed (missing referer). Refresh and try again."

    if wants_json:
        return JsonResponse({"ok": False, "error": message}, status=403)

    return HttpResponseForbidden(message)
