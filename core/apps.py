from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"
    verbose_name = "Core"

    def ready(self):
        # Skip during migrate/makemigrations to avoid recursion
        import sys

        if any(cmd in sys.argv for cmd in ("migrate", "makemigrations", "check")):
            return

        from ispcentric.db_bootstrap import ensure_tables

        try:
            ensure_tables()
        except Exception:
            # Connection may not be ready yet during early boot; WSGI/ASGI will retry
            pass
