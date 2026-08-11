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
    """Allow local XAMPP/WAMP MariaDB 10.4 — Django 5+ defaults to requiring 10.11+."""
    import os
    from pathlib import Path

    if os.getenv("DJANGO_ALLOW_MARIADB_104", "true").strip().lower() in {
        "0",
        "false",
        "no",
    }:
        return
    try:
        from ispcentric.envutil import is_hosted

        if is_hosted(Path(__file__).resolve().parent.parent):
            return
    except Exception:
        return

    try:
        from django.db.backends.mysql import features as mysql_features

        _original = mysql_features.DatabaseFeatures.minimum_database_version

        @property
        def _minimum_database_version(self):
            if getattr(self.connection, "mysql_is_mariadb", False):
                return (10, 4)
            return _original.fget(self)

        mysql_features.DatabaseFeatures.minimum_database_version = (
            _minimum_database_version
        )

        @property
        def _can_return_columns_from_insert(self):
            if getattr(self.connection, "mysql_is_mariadb", False):
                version = getattr(self.connection, "mysql_version", None)
                if version and version < (10, 5):
                    return False
            return self.connection.mysql_is_mariadb

        mysql_features.DatabaseFeatures.can_return_columns_from_insert = (
            _can_return_columns_from_insert
        )
    except Exception:
        pass


try:
    _relax_local_mariadb_version_check()
except Exception:
    pass
