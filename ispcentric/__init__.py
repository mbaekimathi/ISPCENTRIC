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
        from functools import cached_property as functools_cached_property

        from django.db.backends.mysql import features as mysql_features
        from django.utils.functional import cached_property as django_cached_property

        def _feature_getter(descriptor):
            # Django and stdlib cached_property both need __set_name__ when
            # defined on the class. After class creation, unwrap the callable.
            if isinstance(
                descriptor, (django_cached_property, functools_cached_property)
            ):
                return getattr(descriptor, "real_func", None) or descriptor.func
            fget = getattr(descriptor, "fget", None)
            if callable(fget):
                return fget
            if callable(descriptor):
                return descriptor
            raise TypeError(
                f"Unsupported database feature descriptor: {descriptor!r}"
            )

        original_minimum_version = _feature_getter(
            mysql_features.DatabaseFeatures.minimum_database_version
        )

        # Use a normal property. Assigning functools.cached_property after
        # class creation skips __set_name__ and crashes on Python 3.12+.
        @property
        def minimum_database_version(self):
            if getattr(self.connection, "mysql_is_mariadb", False):
                return (10, 4)
            return original_minimum_version(self)

        mysql_features.DatabaseFeatures.minimum_database_version = (
            minimum_database_version
        )

        original_can_return = _feature_getter(
            mysql_features.DatabaseFeatures.can_return_columns_from_insert
        )

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
