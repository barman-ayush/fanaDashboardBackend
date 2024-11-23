import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from fanaDashboard.routing import websocket_urlpatterns
from fanaDashboard.middleware import WebSocketJWTAuthenticationMiddleware

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fanaSystem.settings")

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": WebSocketJWTAuthenticationMiddleware(
        URLRouter(websocket_urlpatterns)
    ),
})
