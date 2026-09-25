"""server-kit 管理网站的安全默认设置。"""

from __future__ import annotations

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured


WEB_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = WEB_DIR.parent
STATE_DIR = Path(os.environ.get("SERVER_KIT_WEB_STATE", "/var/lib/server-kit-web"))
TESTING = os.environ.get("SERVER_KIT_TESTING") == "1"


def read_secret_key() -> str:
    path = Path(os.environ.get("SERVER_KIT_SECRET_KEY_FILE", "/etc/server-kit/web-secret-key"))
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        if TESTING:
            return "test-only-secret-key-not-for-production-000000000000000"
        raise ImproperlyConfigured(f"缺少管理网站密钥文件：{path}")
    if len(value) < 50:
        raise ImproperlyConfigured("管理网站密钥长度不足")
    return value


SECRET_KEY = read_secret_key()
DEBUG = False
ALLOWED_HOSTS = [
    item.strip()
    for item in os.environ.get("SERVER_KIT_ALLOWED_HOSTS", "10.20.0.1").split(",")
    if item.strip()
]
# SSH local forwarding preserves the browser's loopback Host header. Allow the
# documented first-login path without changing the AWG-only listening address.
ALLOWED_HOSTS = list(dict.fromkeys([*ALLOWED_HOSTS, "127.0.0.1", "localhost"]))
if TESTING:
    ALLOWED_HOSTS.append("testserver")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "dashboard",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "dashboard.middleware.SafeExpiredPostMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
if not TESTING:
    MIDDLEWARE.insert(1, "whitenoise.middleware.WhiteNoiseMiddleware")

ROOT_URLCONF = "server_kit_web.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [WEB_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]
ASGI_APPLICATION = "server_kit_web.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": STATE_DIR / "db.sqlite3",
        "OPTIONS": {"timeout": 10},
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 14}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# 新密码优先使用内存困难的 Argon2id；保留旧算法以便登录时无感升级。
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]

LANGUAGE_CODE = "zh-hans"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = STATE_DIR / "static"
STATICFILES_DIRS = [WEB_DIR / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}
if TESTING:
    STORAGES["staticfiles"] = {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"
    }
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"
SESSION_COOKIE_NAME = "server_kit_session"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SECURE = False  # 默认仅在 AWG 加密隧道内使用 HTTP。
# 活跃使用时滚动续期 8 小时；关闭浏览器后仍立即失效。
SESSION_COOKIE_AGE = 8 * 60 * 60
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SECURE = False
CSRF_FAILURE_VIEW = "dashboard.auth.csrf_failure"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

SERVER_KIT_AGENT_SOCKET = os.environ.get(
    "SERVER_KIT_AGENT_SOCKET", "/run/server-kit/manager.sock"
)
SERVER_KIT_BACKUP_DIR = Path(
    os.environ.get("SERVER_KIT_BACKUP_DIR", "/var/lib/server-kit-backups")
)
SERVER_KIT_UPLOAD_DIR = STATE_DIR / "uploads"
SERVER_KIT_MAX_UPLOAD_BYTES = int(os.environ.get("SERVER_KIT_MAX_UPLOAD_BYTES", str(2 * 1024 * 1024 * 1024)))
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024
DATA_UPLOAD_MAX_MEMORY_SIZE = SERVER_KIT_MAX_UPLOAD_BYTES + 1024 * 1024
