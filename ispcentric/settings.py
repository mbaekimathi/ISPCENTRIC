"""Django settings for ISPCENTRIC."""

from pathlib import Path
import os

from ispcentric.db_bootstrap import ensure_database
from ispcentric.env_file import load_project_env
from ispcentric.envutil import env_flag, is_hosted

BASE_DIR = Path(__file__).resolve().parent.parent
# Do not override real process env (cPanel Python App env vars win)
load_project_env(BASE_DIR, override=False)

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

from urllib.parse import urlparse

_hosts_raw = (os.getenv("DJANGO_ALLOWED_HOSTS") or "").strip()


def _hosts_from_public_base() -> list[str]:
    url = (os.getenv("PUBLIC_BASE_URL") or "").strip()
    if not url or url.lower() in {"auto", "detect", "lan", "local"}:
        return []
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
    except Exception:
        return []
    host = (parsed.hostname or "").strip().lower()
    return [host] if host else []


# Track whether the operator opted into a wildcard host list (risky with
# AUTO_CSRF_ORIGINS). Captive probe hosts are appended below and are not "*".
_ALLOWED_HOSTS_WILDCARD = False

if HOSTED:
    if _hosts_raw and _hosts_raw.lower() not in ("auto",):
        if _hosts_raw.strip() == "*":
            # Explicit opt-in only — prefer a comma-separated host list.
            ALLOWED_HOSTS = ["*"]
            _ALLOWED_HOSTS_WILDCARD = True
        else:
            ALLOWED_HOSTS = [h.strip() for h in _hosts_raw.split(",") if h.strip()]
    else:
        ALLOWED_HOSTS = _hosts_from_public_base()
        if not ALLOWED_HOSTS:
            # Legacy hosted installs without DJANGO_ALLOWED_HOSTS.
            # Require DJANGO_ALLOW_WILDCARD_HOSTS=true to keep "*" — otherwise
            # fall back to PUBLIC_BASE_URL host only when set, else "*" with a
            # loud warning so existing VPS boxes keep booting.
            if env_flag("DJANGO_ALLOW_WILDCARD_HOSTS", "false"):
                ALLOWED_HOSTS = ["*"]
                _ALLOWED_HOSTS_WILDCARD = True
            else:
                import logging as _logging

                _logging.getLogger(__name__).warning(
                    "Hosted install has no DJANGO_ALLOWED_HOSTS / PUBLIC_BASE_URL "
                    "host. Using ALLOWED_HOSTS=['*'] temporarily — set "
                    "DJANGO_ALLOWED_HOSTS to your domain (see .env.production.example). "
                    "AUTO_CSRF_ORIGINS is disabled while '*' is active unless "
                    "DJANGO_AUTO_CSRF_ORIGINS=true."
                )
                ALLOWED_HOSTS = ["*"]
                _ALLOWED_HOSTS_WILDCARD = True
elif _hosts_raw and _hosts_raw.lower() not in ("auto", "*"):
    ALLOWED_HOSTS = [h.strip() for h in _hosts_raw.split(",") if h.strip()]
else:
    ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

# Windows/Android/iOS/OEM captive-portal probes are DNS-hijacked to the MikroTik
# gateway, then dst-nat'd to this app. Accept those Host headers (keep in sync
# with ispcentric.middleware.CAPTIVE_PROBE_HOSTS).
ALLOWED_HOSTS += [
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "www.msftncsi.com",
    "dns.msftncsi.com",
    "ipv6.msftconnecttest.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "captive.apple.com",
    "www.apple.com",
    "www.appleiphonecell.com",
    "www.itools.info",
    "www.ibook.info",
    "www.airport.us",
    "www.thinkdifferent.us",
    "detectportal.firefox.com",
    "network-test.debian.org",
    "neverssl.com",
    "example.com",
    "connectivitycheck.platform.hicloud.com",
    "connectivitycheck.platform.hihonorcloud.com",
    "10.10.0.1",
]

CSRF_TRUSTED_ORIGINS = [
    o.strip()
    for o in (os.getenv("DJANGO_CSRF_TRUSTED_ORIGINS") or "").split(",")
    if o.strip()
]
# On hosted with pinned hosts, middleware adds https://<current-host> per request.
# With ALLOWED_HOSTS='*', auto-trusting the request Host enables CSRF origin
# injection — require an explicit DJANGO_AUTO_CSRF_ORIGINS=true in that case.
if _ALLOWED_HOSTS_WILDCARD:
    AUTO_CSRF_ORIGINS = env_flag("DJANGO_AUTO_CSRF_ORIGINS", "false")
else:
    AUTO_CSRF_ORIGINS = HOSTED or env_flag("DJANGO_AUTO_CSRF_ORIGINS", "false")

# STK callback: confirm ResultCode=0 with Daraja STK Query before fulfillment.
# Set false only for offline tests that mock fulfillment without Daraja.
STK_CALLBACK_REQUIRE_DARAJA_QUERY = env_flag(
    "STK_CALLBACK_REQUIRE_DARAJA_QUERY", "true"
)
# Optional comma-separated allowlist for /api/mpesa/stk-callback/ (empty = any IP).
MPESA_CALLBACK_ALLOWED_IPS = (os.getenv("MPESA_CALLBACK_ALLOWED_IPS") or "").strip()
if HOSTED and not DEBUG and not MPESA_CALLBACK_ALLOWED_IPS:
    import logging as _logging

    _logging.getLogger(__name__).warning(
        "MPESA_CALLBACK_ALLOWED_IPS is empty on a hosted install. "
        "Set it to Safaricom callback source IPs (see .env.production.example) "
        "so forged STK callbacks are rejected at the edge. "
        "Daraja STK Query confirmation remains enabled by default."
    )

# Fernet key or passphrase for EncryptedCharField (router/payment/CPE secrets).
# If unset, a key is derived from DJANGO_SECRET_KEY — set this explicitly in
# production so SECRET_KEY rotation does not brick ciphertext.
FIELD_ENCRYPTION_KEY = (os.getenv("FIELD_ENCRYPTION_KEY") or "").strip()

# Public WireGuard .rsc download limits (MikroTik retries a few times on paste).
WIREGUARD_RSC_DOWNLOAD_LIMIT = int(os.getenv("WIREGUARD_RSC_DOWNLOAD_LIMIT") or "20")
WIREGUARD_RSC_DOWNLOAD_WINDOW = int(os.getenv("WIREGUARD_RSC_DOWNLOAD_WINDOW") or "3600")
WIREGUARD_RSC_TOKEN_MAX_AGE = int(os.getenv("WIREGUARD_RSC_TOKEN_MAX_AGE") or "7200")

# Public base URL for captive Hotspot / renew pages pushed to MikroTik.
# Use a concrete URL on hosted (e.g. http://isp.richcom.co.ke), or "auto"/empty
# locally so the LAN IPv4 is picked at runtime (see core.hotspot_portal).
PUBLIC_BASE_URL = (os.getenv("PUBLIC_BASE_URL") or "").strip().rstrip("/")
if PUBLIC_BASE_URL.lower() in {"auto", "detect", "lan", "local"}:
    PUBLIC_BASE_URL = ""

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

# WireGuard tunnel the routers dial so a hosted server can reach their API.
WIREGUARD_ENDPOINT = (os.getenv("WIREGUARD_ENDPOINT") or "").strip()
WIREGUARD_SERVER_PUBLIC_KEY = (os.getenv("WIREGUARD_SERVER_PUBLIC_KEY") or "").strip()
WIREGUARD_SUBNET = (os.getenv("WIREGUARD_SUBNET") or "10.9.0.0/24").strip()
WIREGUARD_INTERFACE = (os.getenv("WIREGUARD_INTERFACE") or "wg0").strip()
WIREGUARD_CONF_PATH = (os.getenv("WIREGUARD_CONF_PATH") or "/etc/wireguard/wg0.conf").strip()
# Optional helper on the VPS, e.g. /opt/ispcentric/scripts/wireguard_apply_peer.sh
WIREGUARD_SYNC_COMMAND = (os.getenv("WIREGUARD_SYNC_COMMAND") or "").strip()

# Background MikroTik watchdog (sample_mikrotik_status): repair management + WAN.
MIKROTIK_AUTO_RESTORE = env_flag("MIKROTIK_AUTO_RESTORE", "true" if HOSTED else "false")
MIKROTIK_AUTO_RESTORE_COOLDOWN_SEC = int(os.getenv("MIKROTIK_AUTO_RESTORE_COOLDOWN_SEC") or "300")
MIKROTIK_INTERNET_PROBE_COOLDOWN_SEC = int(os.getenv("MIKROTIK_INTERNET_PROBE_COOLDOWN_SEC") or "300")
MIKROTIK_AUTO_RESTORE_ALERTS = env_flag(
    "MIKROTIK_AUTO_RESTORE_ALERTS", "true" if HOSTED else "false"
)
MIKROTIK_AUTO_RESTORE_ALERT_COOLDOWN_SEC = int(
    os.getenv("MIKROTIK_AUTO_RESTORE_ALERT_COOLDOWN_SEC") or "3600"
)

# Local auto portal URLs use this machine's current LAN IPs — accept them as Hosts
# so DisallowedHost does not block Hotspot clients after the IP changes.
# Runs after WIREGUARD_SUBNET so preferred_lan_ipv4 can exclude the tunnel net.
if not HOSTED:
    try:
        from core.hotspot_portal import local_ipv4_addresses, preferred_lan_ipv4

        for _ip in sorted(local_ipv4_addresses()):
            if _ip and _ip not in ALLOWED_HOSTS:
                ALLOWED_HOSTS.append(_ip)
        _lan = preferred_lan_ipv4()
        if _lan and _lan not in ALLOWED_HOSTS:
            ALLOWED_HOSTS.append(_lan)
    except Exception:
        pass

# Reverse proxies whose X-Forwarded-For may be trusted (nginx on the same box).
TRUSTED_PROXY_IPS = [
    p.strip()
    for p in (os.getenv("DJANGO_TRUSTED_PROXY_IPS") or "127.0.0.1,::1").split(",")
    if p.strip()
]

MIDDLEWARE = [
    "ispcentric.middleware.RealClientIpMiddleware",
    "ispcentric.middleware.CaptiveHostRewriteMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "ispcentric.security_headers.SecurityHeadersMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "ispcentric.middleware.HotspotCaptiveProbeMiddleware",
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
            "connect_timeout": 5,
            "read_timeout": 5,
            "write_timeout": 5,
        },
    }
}

# Shared file cache so TTL keys (status/surfing/live) work across Passenger workers.
# Override with DJANGO_CACHE_BACKEND=locmem for single-process local if needed.
# In DEBUG, default to in-memory cache (faster, no disk writes under .cache/).
_cache_backend = (os.getenv("DJANGO_CACHE_BACKEND") or "").strip().lower()
if not _cache_backend and DEBUG:
    _cache_backend = "locmem"
elif not _cache_backend:
    _cache_backend = "file"
if _cache_backend in {"locmem", "locmemcache", "local"}:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "ispcentric-default",
            "TIMEOUT": 60,
            "OPTIONS": {"MAX_ENTRIES": 1000},
        }
    }
else:
    _cache_dir = BASE_DIR / ".cache"
    try:
        _cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
            "LOCATION": str(_cache_dir),
            "TIMEOUT": 60,
            "OPTIONS": {"MAX_ENTRIES": 2000},
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Owner self-signup: open in DEBUG by default; closed when hosted unless invite key set.
OWNER_REGISTER_INVITE_KEY = (os.getenv("DJANGO_OWNER_REGISTER_INVITE_KEY") or "").strip()
ALLOW_PUBLIC_OWNER_REGISTRATION = env_flag(
    "DJANGO_ALLOW_PUBLIC_OWNER_REGISTRATION",
    "true" if DEBUG else "false",
)

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

# Session / cookie defaults (explicit hardening)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = int(os.getenv("DJANGO_SESSION_COOKIE_AGE") or str(60 * 60 * 12))
SESSION_SAVE_EVERY_REQUEST = env_flag(
    "DJANGO_SESSION_SAVE_EVERY_REQUEST",
    "false" if DEBUG else "true",
)

# Email (password reset). Console backend in DEBUG when unset.
EMAIL_BACKEND = (
    os.getenv("DJANGO_EMAIL_BACKEND")
    or (
        "django.core.mail.backends.console.EmailBackend"
        if DEBUG
        else "django.core.mail.backends.smtp.EmailBackend"
    )
)
EMAIL_HOST = (os.getenv("DJANGO_EMAIL_HOST") or "").strip()
EMAIL_PORT = int(os.getenv("DJANGO_EMAIL_PORT") or "587")
EMAIL_HOST_USER = (os.getenv("DJANGO_EMAIL_HOST_USER") or "").strip()
EMAIL_HOST_PASSWORD = (os.getenv("DJANGO_EMAIL_HOST_PASSWORD") or "").strip()
EMAIL_USE_TLS = env_flag("DJANGO_EMAIL_USE_TLS", "true")
DEFAULT_FROM_EMAIL = (
    os.getenv("DJANGO_DEFAULT_FROM_EMAIL") or "noreply@ispcentric.local"
).strip()

if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SESSION_COOKIE_SECURE = env_flag("DJANGO_SESSION_COOKIE_SECURE", "true")
    CSRF_COOKIE_SECURE = env_flag("DJANGO_CSRF_COOKIE_SECURE", "true")
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"
    SECURE_SSL_REDIRECT = env_flag("DJANGO_SECURE_SSL_REDIRECT", "false")
    SECURE_HSTS_SECONDS = int(os.getenv("DJANGO_SECURE_HSTS_SECONDS") or ("31536000" if HOSTED else "0"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = env_flag(
        "DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS",
        "true" if SECURE_HSTS_SECONDS else "false",
    )
    SECURE_HSTS_PRELOAD = env_flag(
        "DJANGO_SECURE_HSTS_PRELOAD",
        "true" if SECURE_HSTS_SECONDS else "false",
    )

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
