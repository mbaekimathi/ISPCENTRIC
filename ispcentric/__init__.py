# MySQL driver for Django.
# Prefer mysqlclient when installed (local/VPS). Fall back to PyMySQL on hosts
# such as cPanel where compiling mysqlclient is impractical. Django 5+ rejects
# PyMySQL's native version_info, so report a compatible tuple before shimming.
try:
    import MySQLdb

    if MySQLdb.version_info < (2, 2, 1):
        raise ImportError(f"mysqlclient {MySQLdb.__version__} is too old")
except ImportError:
    import pymysql

    pymysql.version_info = (2, 2, 1, "final", 0)
    pymysql.install_as_MySQLdb()


def _relax_local_mariadb_version_check() -> None:
    """
    Allow local XAMPP/WAMP MariaDB 10.4 when running Django 5+.

    Django 4.2 already accepts MariaDB 10.4, so this is a no-op for production
    (requirements pin Django<5). Only patch local dev boxes — never hosted VPS.
    """
    import os
    from functools import cached_property
    from pathlib import Path

    base_dir = Path(__file__).resolve().parent.parent
    try:
        from ispcentric.env_file import load_project_env

        load_project_env(base_dir, override=False)
    except Exception:
        pass

    if os.getenv("DJANGO_ALLOW_MARIADB_104", "true").strip().lower() in {
        "0",
        "false",
        "no",
    }:
        return

    hosted_mode = (os.getenv("DJANGO_HOSTED", "auto") or "auto").strip().lower()
    if hosted_mode in {"1", "true", "yes", "on", "hosted", "production", "prod"}:
        return
    try:
        from ispcentric.envutil import is_hosted

        if is_hosted(base_dir):
            return
    except Exception:
        pass

    try:
        import django

        if django.VERSION < (5, 0):
            return
    except Exception:
        return

    try:
        from django.db.backends.mysql import features as mysql_features

        original_descriptor = mysql_features.DatabaseFeatures.minimum_database_version
        if isinstance(original_descriptor, cached_property):
            original_minimum_version = original_descriptor.func
        elif hasattr(original_descriptor, "fget"):
            original_minimum_version = original_descriptor.fget
        else:
            original_minimum_version = original_descriptor

        @cached_property
        def minimum_database_version(self):
            if getattr(self.connection, "mysql_is_mariadb", False):
                return (10, 4)
            return original_minimum_version(self)

        mysql_features.DatabaseFeatures.minimum_database_version = (
            minimum_database_version
        )

        original_insert_descriptor = (
            mysql_features.DatabaseFeatures.can_return_columns_from_insert
        )
        if isinstance(original_insert_descriptor, cached_property):
            original_can_return = original_insert_descriptor.func
        elif hasattr(original_insert_descriptor, "fget"):
            original_can_return = original_insert_descriptor.fget
        else:
            original_can_return = original_insert_descriptor

        @property
        def can_return_columns_from_insert(self):
            if getattr(self.connection, "mysql_is_mariadb", False):
                version = getattr(self.connection, "mysql_version", None)
                if version and version < (10, 5):
                    return False
            return original_can_return(self)

        mysql_features.DatabaseFeatures.can_return_columns_from_insert = (
            can_return_columns_from_insert
        )
    except Exception:
        pass


try:
    _relax_local_mariadb_version_check()
except Exception:
    pass
