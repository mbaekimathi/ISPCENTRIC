"""
Ensure the ISPCENTRIC MySQL database and Django tables exist.

Checks for missing tables / pending migrations and applies them automatically
on app boot (and again if a schema error is seen at runtime).
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import pymysql

from ispcentric.env_file import load_project_env
from ispcentric.envutil import env_flag, is_hosted

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
load_project_env(BASE_DIR, override=False)

_tables_ready = False
_last_check_at = 0.0
_CHECK_COOLDOWN_SEC = 30.0
_HOSTED = is_hosted(BASE_DIR)

# Minimum tables expected after a healthy migrate. If any are missing, migrate.
_REQUIRED_TABLES = (
    "django_migrations",
    "django_content_type",
    "auth_user",
    "accounts_organization",
    "billing_plan",
    "billing_customer",
    "core_mikrotik_router",
)


def _mysql_settings() -> dict:
    host_default = "localhost" if _HOSTED else "127.0.0.1"
    return {
        "host": os.getenv("MYSQL_HOST", host_default),
        "port": int(os.getenv("MYSQL_PORT", "3306")),
        "user": os.getenv("MYSQL_USER", "root"),
        "password": os.getenv("MYSQL_PASSWORD", ""),
        "database": os.getenv("MYSQL_DATABASE", "ISPCENTRIC"),
        "charset": "utf8mb4",
    }


def ensure_database() -> None:
    """Create the application database if allowed and missing."""
    default = "false" if _HOSTED else "true"
    if not env_flag("MYSQL_AUTO_CREATE_DB", default):
        return

    cfg = _mysql_settings()
    database = cfg.pop("database")

    try:
        connection = pymysql.connect(**cfg)
    except Exception:
        logger.exception("Could not connect to MySQL to ensure database exists.")
        return

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{database}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        connection.commit()
        logger.info("Database `%s` is ready.", database)
    except Exception:
        logger.exception("Could not create database `%s` (create it in cPanel).", database)
    finally:
        connection.close()


def _auto_migrate_enabled() -> bool:
    # Always on unless explicitly disabled.
    return env_flag("DJANGO_AUTO_MIGRATE", "true")


def _existing_tables() -> set[str]:
    from django.db import connection

    try:
        return {name.lower() for name in connection.introspection.table_names()}
    except Exception:
        logger.exception("Could not list database tables.")
        return set()


def _missing_required_tables() -> list[str]:
    existing = _existing_tables()
    if not existing:
        # Empty / unreachable DB — treat all required as missing.
        return list(_REQUIRED_TABLES)
    return [name for name in _REQUIRED_TABLES if name.lower() not in existing]


def _pending_migrations() -> list[tuple[str, str]]:
    """Return [(app_label, migration_name), ...] still to apply."""
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    try:
        executor = MigrationExecutor(connection)
        targets = executor.loader.graph.leaf_nodes()
        plan = executor.migration_plan(targets)
        return [(migration.app_label, migration.name) for migration, _backwards in plan]
    except Exception:
        logger.exception("Could not inspect pending migrations.")
        # Fail open: force a migrate attempt when inspection breaks (often missing tables).
        return [("__unknown__", "inspect_failed")]


def _acquire_migrate_lock() -> Path | None:
    """Simple exclusive lock so multiple Passenger workers do not migrate together."""
    lock_dir = BASE_DIR / "tmp"
    try:
        lock_dir.mkdir(exist_ok=True)
    except OSError:
        return None

    lock_path = lock_dir / "migrate.lock"
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"{os.getpid()}\n{time.time()}\n")
        return lock_path
    except FileExistsError:
        # Stale lock older than 5 minutes — take over.
        try:
            age = time.time() - lock_path.stat().st_mtime
            if age > 300:
                lock_path.unlink(missing_ok=True)
                return _acquire_migrate_lock()
        except OSError:
            pass
        return None
    except OSError:
        return None


def _release_migrate_lock(lock_path: Path | None) -> None:
    if lock_path is None:
        return
    try:
        lock_path.unlink(missing_ok=True)
    except OSError:
        pass


def _run_migrate() -> bool:
    from django.core.management import call_command

    lock = _acquire_migrate_lock()
    if lock is None and (BASE_DIR / "tmp" / "migrate.lock").exists():
        logger.info("Another worker is already migrating; waiting briefly.")
        time.sleep(2)
        # Re-check after wait — peer may have finished.
        if not _missing_required_tables() and not [
            p for p in _pending_migrations() if p[0] != "__unknown__"
        ]:
            return True
        # Try once more for the lock.
        lock = _acquire_migrate_lock()
        if lock is None:
            logger.warning("Could not acquire migrate lock; skipping this attempt.")
            return False

    try:
        logger.info("Applying database migrations…")
        call_command("migrate", interactive=False, verbosity=1, run_syncdb=True)
        logger.info("Database migrations finished.")
        return True
    except Exception:
        logger.exception("Auto-migrate failed; run: python manage.py migrate")
        return False
    finally:
        _release_migrate_lock(lock)


def ensure_tables(*, force: bool = False) -> bool:
    """
    Check DB schema and apply migrations when tables are missing or updates pending.

    Returns True when the schema looks current after this call.
    """
    global _tables_ready, _last_check_at

    if not _auto_migrate_enabled():
        logger.debug("DJANGO_AUTO_MIGRATE is disabled; skipping schema check.")
        return False

    now = time.monotonic()
    if (
        not force
        and _tables_ready
        and (now - _last_check_at) < _CHECK_COOLDOWN_SEC
    ):
        return True

    _last_check_at = now

    try:
        missing = _missing_required_tables()
        pending = _pending_migrations()
    except Exception:
        logger.exception("Schema check failed.")
        missing, pending = list(_REQUIRED_TABLES), [("__unknown__", "check_failed")]

    needs_migrate = bool(missing) or bool(pending)

    if not needs_migrate:
        _tables_ready = True
        return True

    if missing:
        logger.warning("Missing database tables: %s", ", ".join(missing))
    if pending and pending[0][0] != "__unknown__":
        preview = ", ".join(f"{app}.{name}" for app, name in pending[:12])
        more = f" (+{len(pending) - 12} more)" if len(pending) > 12 else ""
        logger.warning("Pending migrations: %s%s", preview, more)
    elif pending:
        logger.warning("Migration state could not be read; attempting migrate anyway.")

    ok = _run_migrate()
    if ok:
        # Verify after migrate.
        still_missing = _missing_required_tables()
        still_pending = [
            p for p in _pending_migrations() if p[0] != "__unknown__"
        ]
        _tables_ready = not still_missing and not still_pending
        if _tables_ready:
            logger.info("ISPCENTRIC database schema is up to date.")
        else:
            if still_missing:
                logger.error("Tables still missing after migrate: %s", ", ".join(still_missing))
            if still_pending:
                logger.error(
                    "Migrations still pending after migrate: %s",
                    ", ".join(f"{a}.{n}" for a, n in still_pending[:8]),
                )
    else:
        _tables_ready = False

    return _tables_ready


def repair_schema_if_needed() -> bool:
    """Force a schema check + migrate (used after a runtime schema error)."""
    global _tables_ready
    _tables_ready = False
    return ensure_tables(force=True)
