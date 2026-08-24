"""Django settings for Kai."""

import os
from pathlib import Path
from urllib.parse import unquote, urlparse

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name, default=False):
    value = os.environ.get(name)
    return default if value is None else value.lower() in ("1", "true", "yes", "on")


DEV_SECRET_KEY = "dev-only-secret-key-base-change-in-production"  # nosec B105
SECRET_KEY = os.environ.get("SECRET_KEY_BASE", DEV_SECRET_KEY)

DEBUG = os.environ.get("DJANGO_DEBUG", "") == "1"
PRODUCTION = env_bool("DJANGO_PRODUCTION")

ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")
SOURCE_CODE_URL = os.environ.get("SOURCE_CODE_URL", "")

if PRODUCTION:
    if DEBUG:
        raise ImproperlyConfigured("DJANGO_DEBUG must be disabled in production")
    if SECRET_KEY == DEV_SECRET_KEY:
        raise ImproperlyConfigured("SECRET_KEY_BASE is required in production")
    if not os.environ.get("DJANGO_ALLOWED_HOSTS") or "*" in ALLOWED_HOSTS:
        raise ImproperlyConfigured("explicit DJANGO_ALLOWED_HOSTS are required in production")
    if urlparse(SOURCE_CODE_URL).scheme not in {"http", "https"}:
        raise ImproperlyConfigured("SOURCE_CODE_URL is required in production")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    "kai",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "kai.security_middleware.SecurityHeadersMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "kai.security_middleware.csp_nonce",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


def _database_from_url(url):
    parsed = urlparse(url)
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": parsed.path.lstrip("/"),
        "USER": unquote(parsed.username or ""),
        "PASSWORD": unquote(parsed.password or ""),
        "HOST": parsed.hostname or "",
        "PORT": str(parsed.port) if parsed.port else "",
    }


DATABASES = {
    "default": _database_from_url(
        os.environ.get("DATABASE_URL", "postgres://kai:kai@localhost:5433/kai_django_dev")
    )
}

AUTH_USER_MODEL = "kai.User"

AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]

LDAP_SERVER_URI = os.environ.get("LDAP_SERVER_URI", "")
if LDAP_SERVER_URI:
    import ldap
    from django_auth_ldap.config import GroupOfNamesType, LDAPSearch

    LDAP_START_TLS = env_bool("LDAP_START_TLS")
    if not LDAP_SERVER_URI.startswith("ldaps://") and not LDAP_START_TLS:
        raise ImproperlyConfigured("LDAP requires an ldaps:// URI or LDAP_START_TLS=1")
    LDAP_USER_SEARCH_BASE = os.environ.get("LDAP_USER_SEARCH_BASE")
    if not LDAP_USER_SEARCH_BASE:
        raise ImproperlyConfigured("LDAP_USER_SEARCH_BASE is required when LDAP is enabled")

    AUTHENTICATION_BACKENDS.insert(0, "kai.auth_backends.SecureLDAPBackend")
    AUTH_LDAP_SERVER_URI = LDAP_SERVER_URI
    AUTH_LDAP_START_TLS = LDAP_START_TLS
    AUTH_LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "")
    AUTH_LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "")
    AUTH_LDAP_USER_SEARCH = LDAPSearch(
        LDAP_USER_SEARCH_BASE,
        ldap.SCOPE_SUBTREE,
        os.environ.get("LDAP_USER_FILTER", "(mail=%(user)s)"),
    )
    AUTH_LDAP_USER_ATTR_MAP = {"email": os.environ.get("LDAP_EMAIL_ATTRIBUTE", "mail")}
    AUTH_LDAP_ALWAYS_UPDATE_USER = True
    AUTH_LDAP_CACHE_TIMEOUT = 300
    AUTH_LDAP_CONNECTION_OPTIONS = {
        ldap.OPT_NETWORK_TIMEOUT: 10,
        ldap.OPT_TIMEOUT: 15,
    }
    AUTH_LDAP_GLOBAL_OPTIONS = {ldap.OPT_X_TLS_REQUIRE_CERT: ldap.OPT_X_TLS_DEMAND}
    if os.environ.get("LDAP_CA_CERT_FILE"):
        AUTH_LDAP_GLOBAL_OPTIONS[ldap.OPT_X_TLS_CACERTFILE] = os.environ["LDAP_CA_CERT_FILE"]

    LDAP_GROUP_SEARCH_BASE = os.environ.get("LDAP_GROUP_SEARCH_BASE")
    if LDAP_GROUP_SEARCH_BASE:
        AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
            LDAP_GROUP_SEARCH_BASE,
            ldap.SCOPE_SUBTREE,
            "(objectClass=groupOfNames)",
        )
        AUTH_LDAP_GROUP_TYPE = GroupOfNamesType()
        if os.environ.get("LDAP_REQUIRED_GROUP"):
            AUTH_LDAP_REQUIRE_GROUP = os.environ["LDAP_REQUIRED_GROUP"]
        if os.environ.get("LDAP_ADMIN_GROUP"):
            AUTH_LDAP_USER_FLAGS_BY_GROUP = {"is_staff": os.environ["LDAP_ADMIN_GROUP"]}

# Raw bcrypt (no SHA-256 pre-hash) so password digests stay compatible with the
# has_secure_password data inherited from the Rails deployment.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.BCryptPasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

# Parity with Rails has_secure_password: no complexity rules, only bcrypt's
# 72-byte input cap (enforced by the hasher).
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

ALLOW_PUBLIC_SIGNUP = env_bool("ALLOW_PUBLIC_SIGNUP", DEBUG)
AUTH_RATE_LIMIT_ATTEMPTS = int(os.environ.get("AUTH_RATE_LIMIT_ATTEMPTS", "5"))
AUTH_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("AUTH_RATE_LIMIT_WINDOW_SECONDS", "900"))
API_TOKEN_TTL_DAYS = int(os.environ.get("API_TOKEN_TTL_DAYS", "90"))

LOGIN_URL = "/login"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# Files served at the URL root (favicons, fonts, robots.txt), same URLs as the
# Rails public/ directory.
WHITENOISE_ROOT = BASE_DIR / "public"

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    # No manifest hashing: JS modules are loaded via an importmap and relative
    # imports, which hashed filenames would break.
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}

MEDIA_ROOT = Path(os.environ.get("KAI_STORAGE_PATH", BASE_DIR / "storage"))
DATA_UPLOAD_MAX_MEMORY_SIZE = int(os.environ.get("MAX_REQUEST_BYTES", str(2 * 1024**3)))
FILE_UPLOAD_MAX_MEMORY_SIZE = 0
MAX_PCAP_UPLOAD_BYTES = int(os.environ.get("MAX_PCAP_UPLOAD_BYTES", str(1024**3)))

# Spool every upload to a real temp file so metadata extraction (capinfos and
# the binary header parser) can always work from a filesystem path.
FILE_UPLOAD_HANDLERS = ["django.core.files.uploadhandler.TemporaryFileUploadHandler"]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"

SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT")
SESSION_COOKIE_SECURE = env_bool("DJANGO_SECURE_COOKIES", not DEBUG)
CSRF_COOKIE_SECURE = env_bool("DJANGO_SECURE_COOKIES", not DEBUG)
SECURE_HSTS_SECONDS = int(os.environ.get("DJANGO_HSTS_SECONDS", "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("DJANGO_HSTS_INCLUDE_SUBDOMAINS")
SECURE_HSTS_PRELOAD = env_bool("DJANGO_HSTS_PRELOAD")
if env_bool("DJANGO_BEHIND_HTTPS_PROXY"):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# The frontend JS sends the Rails-style X-CSRF-Token header (read from the
# csrf-token meta tag), so accept that header name.
CSRF_HEADER_NAME = "HTTP_X_CSRF_TOKEN"

_csrf_origins = os.environ.get("DJANGO_CSRF_TRUSTED_ORIGINS", "")
if _csrf_origins:
    CSRF_TRUSTED_ORIGINS = _csrf_origins.split(",")

EMAIL_BACKEND = os.environ.get(
    "EMAIL_BACKEND",
    "django.core.mail.backends.console.EmailBackend"
    if DEBUG
    else "django.core.mail.backends.smtp.EmailBackend",
)
EMAIL_HOST = os.environ.get("EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = env_bool("EMAIL_USE_TLS", True)
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "kai@localhost")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}
