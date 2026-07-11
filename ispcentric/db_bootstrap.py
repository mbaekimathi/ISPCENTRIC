"""
Ensure the ISPCENTRIC MySQL database and Django tables exist.

On cPanel, leave MYSQL_AUTO_CREATE_DB=false and DJANGO_AUTO_MIGRATE=false —
create the database in cPanel MySQL, then run migrate after each git pull.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pymysql
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

_tables_ready = False


def _env_flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes")


def _mysql_settings() -> dict:
    return {
        "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
        "port": int(os.getenv("MYSQL_PORT", "3306")),
        "user": os.getenv("MYSQL_USER", "root"),
        "password": os.getenv("MYSQL_PASSWORD", ""),
        "database": os.getenv("MYSQL_DATABASE", "ISPCENTRIC"),
        "charset": "utf8mb4",
    }


def ensure_database() -> None:
    """Create the application database if allowed and missing."""
    if not _env_flag("MYSQL_AUTO_CREATE_DB", "true"):
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


def ensure_tables() -> None:
    """Apply Django migrations when auto-migrate is enabled."""
    global _tables_ready
    if _tables_ready:
        return
    if not _env_flag("DJANGO_AUTO_MIGRATE", "true"):
        return

    from django.core.management import call_command

    try:
        call_command("migrate", interactive=False, verbosity=0, run_syncdb=True)
        _tables_ready = True
        logger.info("ISPCENTRIC tables are up to date.")
    except Exception:
        logger.exception("Auto-migrate failed; run: python manage.py migrate")
