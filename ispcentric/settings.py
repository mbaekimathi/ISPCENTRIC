"""Django settings for ISPCENTRIC."""

from pathlib import Path
import os

from dotenv import load_dotenv

from ispcentric.db_bootstrap import ensure_database
from ispcentric.envutil import env_flag, is_hosted

BASE_DIR = Path(__file__).resolve().parent.parent
# Do not override real process env (cPanel Python App env vars win)
load_dotenv(BASE_DIR / ".env", override=False)

HOSTED = is_hosted(BASE_DIR)

# Local/XAMPP only unless MYSQL_AUTO_CREATE_DB is forced on
ensure_database()


def _secret_key() -> str:
    raw = (os.getenv("DJANGO_SECRET_KEY") or "").strip()
    if raw and raw not in {
        "change-me-in-production",
        "generate-a-long-random-string",
        "django-insecure-ispcentric-dev-only-change-me",
    }:
        return raw

    secret_file = BASE_DIR / ".secret_key"
    if secret_file.exists():
        stored = secret_file.read_text(encoding="utf-8").strip()
        if stored:
            return stored

    try:
        from django.core.management.utils import get_random_secret_key

        key = get_random_secret_key()
    except Exception:
        key = "django-insecure-ispcentric-fallback-change-me"

    try:
        secret_file.write_text(key, encoding="utf-8")
    except OSError:
        pass
    return key


SECRET_KEY = _secret_key()

# Hosted defaults to production; local defaults to debug
if os.getenv("DJANGO_DEBUG") is not None:
    DEBUG = env_flag("DJANGO_DEBUG", "False")
else:
    DEBUG = not HOSTED

_hosts_raw = (os.getenv("DJANGO_ALLOWED_HOSTS") or "").strip()
if HOSTED:
    # Always accept the cPanel domain/subdomain (ignore leftover localhost .env values)
    ALLOWED_HOSTS = ["*"]
elif _hosts_raw and _hosts_raw.lower() not in ("auto", "*"):
    ALLOWED_HOSTS = [h.strip() for h in _hosts_raw.split(",") if h.strip()]
else:
    ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

CSRF_TRUSTED_ORIGINS = [
    o.strip()
    for o in (os.getenv("DJANGO_CSRF_TRUSTED_ORIGINS") or "").split(",")
    if o.strip()
]
# On hosted, middleware adds https://<current-host> per request
AUTO_CSRF_ORIGINS = HOSTED or env_flag("DJANGO_AUTO_CSRF_ORIGINS", "false")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core.apps.CoreConfig",
    "accounts.apps.AccountsConfig",
    "billing.apps.BillingConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "ispcentric.middleware.AutoCsrfOriginMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "ispcentric.middleware.PrefetchEmployeeMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "ispcentric.middleware.SchemaErrorMiddleware",
]

ROOT_URLCONF = "ispcentric.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "accounts.context_processors.staff_workspace",
            ],
        },
    },
]

WSGI_APPLICATION = "ispcentric.wsgi.application"

# Hosted MySQL defaults to localhost; only user/password/database need .env
_mysql_host_default = "localhost" if HOSTED else "127.0.0.1"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.getenv("MYSQL_DATABASE", "ISPCENTRIC"),
        "USER": os.getenv("MYSQL_USER", "root"),
        "PASSWORD": os.getenv("MYSQL_PASSWORD", ""),
        "HOST": os.getenv("MYSQL_HOST", _mysql_host_default),
        "PORT": os.getenv("MYSQL_PORT", "3306"),
        # Reuse connections across requests (avoids TCP/auth handshake each time).
        "CONN_MAX_AGE": int(os.getenv("MYSQL_CONN_MAX_AGE", "60")),
        "OPTIONS": {
            "charset": "utf8mb4",
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    }
}

# Local-memory cache is enough for single-worker / low-traffic; swap for Redis when scaled.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "ispcentric-default",
        "TIMEOUT": 60,
        "OPTIONS": {"MAX_ENTRIES": 1000},
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Africa/Nairobi"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
    },
}
WHITENOISE_USE_FINDERS = DEBUG

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
# Hosted: serve uploads through Django/Passenger by default
if os.getenv("DJANGO_SERVE_MEDIA") is not None:
    SERVE_MEDIA = env_flag("DJANGO_SERVE_MEDIA", "false")
else:
    SERVE_MEDIA = True if HOSTED else DEBUG

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

GOOGLE_MAPS_API_KEY = (os.getenv("GOOGLE_MAPS_API_KEY") or "").strip()

LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "core:workspace"
LOGOUT_REDIRECT_URL = "core:landing"

if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SESSION_COOKIE_SECURE = env_flag("DJANGO_SESSION_COOKIE_SECURE", "true")
    CSRF_COOKIE_SECURE = env_flag("DJANGO_CSRF_COOKIE_SECURE", "true")
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"

# Hosted / production: write errors to logs/django.log (check this on 500s).
_LOG_DIR = BASE_DIR / "logs"
try:
    _LOG_DIR.mkdir(exist_ok=True)
except OSError:
    _LOG_DIR = BASE_DIR

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": str(_LOG_DIR / "django.log"),
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console", "file"] if (HOSTED or not DEBUG) else ["console"],
        "level": "INFO",
    },
    "loggers": {
        "django.request": {
            "handlers": ["console", "file"] if (HOSTED or not DEBUG) else ["console"],
            "level": "ERROR",
            "propagate": False,
        },
        "django.db.backends": {
            "handlers": ["file"] if (HOSTED or not DEBUG) else ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}
