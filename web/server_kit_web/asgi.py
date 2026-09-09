"""ASGI 入口。"""

import os

from django.core.asgi import get_asgi_application


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "server_kit_web.settings")
application = get_asgi_application()
