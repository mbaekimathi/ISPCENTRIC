"""Environment helpers for local vs hosted (cPanel / Passenger) detection."""

from __future__ import annotations

import os
from pathlib import Path


def env_flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes", "on")


def is_hosted(base_dir: Path | None = None) -> bool:
    """
    Detect cPanel / Passenger hosting.

    DJANGO_HOSTED=true|false overrides auto-detection.
    DJANGO_HOSTED=auto (default) uses Passenger env or /home* paths.
    """
    mode = (os.getenv("DJANGO_HOSTED", "auto") or "auto").strip().lower()
    if mode in ("1", "true", "yes", "on", "hosted", "production", "prod"):
        return True
    if mode in ("0", "false", "no", "off", "local", "dev"):
        return False

    if os.environ.get("PASSENGER_APP_ENV") or os.environ.get("PASSENGER_BASE_URI"):
        return True
    if os.environ.get("IN_PASSENGER") or os.environ.get("WSGI_ENV") == "passenger":
        return True

    root = base_dir or Path(__file__).resolve().parent.parent
    path = str(root).replace("\\", "/")
    if path.startswith("/home/") or path.startswith("/home3/") or path.startswith("/home2/"):
        return True
    return False
