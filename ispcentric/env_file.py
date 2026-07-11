"""Load .env safely on Windows / cPanel editors (BOM, encoding)."""

from __future__ import annotations

import logging
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

_LOADED: set[str] = set()


def load_project_env(base_dir: Path | str, *, override: bool = False) -> bool:
    """
    Load BASE_DIR/.env with utf-8-sig so Notepad/cPanel BOM does not break line 1.

    Returns True if the file existed and was loaded (even with warnings).
    """
    path = Path(base_dir) / ".env"
    key = str(path.resolve()) if path.exists() else str(path)
    if key in _LOADED and not override:
        return path.is_file()

    if not path.is_file():
        return False

    # Pre-scan so we can log a clear fix hint when line 1 is invalid.
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        raw = path.read_text(encoding="utf-8", errors="replace")
        logger.warning(
            "Could not decode %s as UTF-8. Re-save the file as UTF-8 (no BOM).",
            path,
        )

    first = ""
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped:
            first = stripped
            break

    if first and not first.startswith("#") and "=" not in first:
        logger.error(
            "Invalid .env line 1 (%r). Use KEY=value lines only — no 'export', "
            "no markdown, no shell commands. Example: MYSQL_USER=myuser",
            first[:80],
        )

    # Rewrite without BOM so later tools also parse cleanly.
    try:
        if path.read_bytes()[:3] == b"\xef\xbb\xbf":
            path.write_text(raw, encoding="utf-8", newline="\n")
            logger.info("Removed UTF-8 BOM from %s", path)
    except OSError:
        pass

    ok = load_dotenv(path, override=override, encoding="utf-8-sig")
    _LOADED.add(key)
    return bool(ok)
