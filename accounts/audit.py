"""Security audit helpers — privileged actions and sensitive downloads."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def client_ip(request) -> str:
    return (getattr(request, "META", {}) or {}).get("REMOTE_ADDR") or ""


def record_audit(
    *,
    action: str,
    request=None,
    actor=None,
    target: str = "",
    detail: dict[str, Any] | None = None,
) -> None:
    """
    Persist a security audit row. Never raises into the request path.
    """
    try:
        from accounts.models import SecurityAuditLog

        user = actor
        if user is None and request is not None:
            user = getattr(request, "user", None)
            if user is not None and not getattr(user, "is_authenticated", False):
                user = None

        ip = client_ip(request) if request is not None else ""
        SecurityAuditLog.objects.create(
            action=(action or "")[:64],
            actor=user if getattr(user, "pk", None) else None,
            actor_ip=(ip or "")[:64],
            target=(target or "")[:255],
            detail=detail or {},
        )
    except Exception:
        logger.exception("Failed to write security audit log for action=%s", action)
