import os
import django
import logging

logger = logging.getLogger("django")

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fanaSystem.settings")
logger.info("Setting DJANGO_SETTINGS_MODULE...")

django.setup()
logger.info("Django setup complete.")

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from fanaDashboard.routing import websocket_urlpatterns
from fanaDashboard.middleware import WebSocketJWTAuthenticationMiddleware

logger.info("Importing application components...")

django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": WebSocketJWTAuthenticationMiddleware(
        URLRouter(websocket_urlpatterns)
    ),
})

logger.info("ASGI application setup complete.")

