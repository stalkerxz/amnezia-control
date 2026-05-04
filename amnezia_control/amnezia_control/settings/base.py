from pathlib import Path
import os
from celery.schedules import crontab

BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "unsafe-dev-secret")
DEBUG = os.getenv("DJANGO_DEBUG", "0") == "1"
ALLOWED_HOSTS = [h.strip() for h in os.getenv("DJANGO_ALLOWED_HOSTS", "*").split(",") if h.strip()]


def _csv_env(name, default=""):
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


def _bool_env(name, default="1"):
    return os.getenv(name, default).lower() in {"1", "true", "yes", "on"}

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    "core",
    "accounts",
    "servers",
    "vpn",
    "audit",
    "jobs",
    "portal",
    "notifications",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "amnezia_control.urls"

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
            ],
        },
    }
]

WSGI_APPLICATION = "amnezia_control.wsgi.application"
ASGI_APPLICATION = "amnezia_control.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "amnezia"),
        "USER": os.getenv("POSTGRES_USER", "amnezia"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", "amnezia"),
        "HOST": os.getenv("POSTGRES_HOST", "db"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "ru"
LANGUAGES = (("ru", "Russian"), ("en", "English"))
TIME_ZONE = os.getenv("TIME_ZONE", "UTC")
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

MEDIA_URL = "/media/"
MEDIA_ROOT = Path(os.getenv("MEDIA_ROOT", str(BASE_DIR / "media")))

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.User"

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login/"

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
    }
}

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)
CELERY_TASK_TIME_LIMIT = 120
CELERY_TASK_SOFT_TIME_LIMIT = 90
LIMITS_ENFORCE_EVERY_MINUTES = int(os.getenv("LIMITS_ENFORCE_EVERY_MINUTES", "5"))
CELERY_BEAT_SCHEDULE = {
    "vpn-client-limits-enforce": {
        "task": "vpn.tasks.enforce_client_limits_task",
        "schedule": crontab(minute=f"*/{max(1, LIMITS_ENFORCE_EVERY_MINUTES)}"),
    },
    "notifications-client-access-limits": {
        "task": "notifications.tasks.notify_client_access_limits_task",
        "schedule": crontab(minute="15", hour="8"),
    },
    "client-expiration-reminders": {
        "task": "vpn.tasks.send_expiration_reminders_task",
        "schedule": crontab(minute="30", hour="8"),
    },
}

CONFIG_ENCRYPTION_KEY = os.getenv("CONFIG_ENCRYPTION_KEY", "")


EMAIL_BACKEND = os.getenv("EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend")
EMAIL_HOST = os.getenv("EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "25"))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = _bool_env("EMAIL_USE_TLS", "0")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "no-reply@amnezia-control.local")
ADMINS = [(email, email) for email in _csv_env("DJANGO_ADMINS", "")]
SITE_URL = os.getenv("SITE_URL", "").rstrip("/")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
EXPIRATION_REMINDER_ENABLED = _bool_env("EXPIRATION_REMINDER_ENABLED", "1")
EXPIRATION_REMINDER_DAYS = _csv_env("EXPIRATION_REMINDER_DAYS", "7,3,1")
EXPIRATION_REMINDER_CHANNELS = _csv_env("EXPIRATION_REMINDER_CHANNELS", "email")
ADMIN_EXPIRATION_REMINDER_EMAILS = _csv_env("ADMIN_EXPIRATION_REMINDER_EMAILS", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_ADMIN_CHAT_IDS = _csv_env("TELEGRAM_ADMIN_CHAT_IDS", "")
NOTIFICATIONS_ENABLED = os.getenv("NOTIFICATIONS_ENABLED", "1") == "1"
NOTIFICATIONS_CHANNELS = [channel.strip() for channel in os.getenv("NOTIFICATIONS_CHANNELS", "email").split(",") if channel.strip()]
NOTIFICATIONS_EMAIL_FROM = os.getenv("NOTIFICATIONS_EMAIL_FROM", DEFAULT_FROM_EMAIL)
NOTIFICATIONS_BASE_URL = os.getenv("NOTIFICATIONS_BASE_URL", "")
NOTIFICATIONS_EXPIRING_DAYS = int(os.getenv("NOTIFICATIONS_EXPIRING_DAYS", "3"))
NOTIFICATIONS_TELEGRAM_BOT_TOKEN = os.getenv("NOTIFICATIONS_TELEGRAM_BOT_TOKEN", "").strip()
NOTIFICATIONS_TELEGRAM_ADMIN_CHAT_IDS = [
    chat_id.strip()
    for chat_id in os.getenv("NOTIFICATIONS_TELEGRAM_ADMIN_CHAT_IDS", "").split(",")
    if chat_id.strip()
]

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
X_FRAME_OPTIONS = "DENY"


STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
