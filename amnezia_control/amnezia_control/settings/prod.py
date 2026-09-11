from .base import *
from .base import _bool_env
import os

DEBUG = False

DJANGO_FORCE_SSL = _bool_env("DJANGO_FORCE_SSL", "0")

# Granular HTTPS controls allow production to use secure cookies and
# application-level redirects without forcing long-lived HSTS/preload.
# DJANGO_FORCE_SSL keeps backward-compatible all-on behavior.
SESSION_COOKIE_SECURE = _bool_env(
    "DJANGO_SESSION_COOKIE_SECURE",
    "1" if DJANGO_FORCE_SSL else "0",
)
CSRF_COOKIE_SECURE = _bool_env(
    "DJANGO_CSRF_COOKIE_SECURE",
    "1" if DJANGO_FORCE_SSL else "0",
)
SECURE_SSL_REDIRECT = _bool_env(
    "DJANGO_SECURE_SSL_REDIRECT",
    "1" if DJANGO_FORCE_SSL else "0",
)
SECURE_HSTS_SECONDS = int(
    os.getenv(
        "DJANGO_SECURE_HSTS_SECONDS",
        "31536000" if DJANGO_FORCE_SSL else "0",
    )
)
SECURE_HSTS_INCLUDE_SUBDOMAINS = _bool_env(
    "DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS",
    "1" if DJANGO_FORCE_SSL else "0",
)
SECURE_HSTS_PRELOAD = _bool_env(
    "DJANGO_SECURE_HSTS_PRELOAD",
    "1" if DJANGO_FORCE_SSL else "0",
)
