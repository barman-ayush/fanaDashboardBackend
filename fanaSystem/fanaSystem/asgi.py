import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from fanaDashboard import routing
from fanaDashboard.middleware import JWTAuthenticationMiddleware  # Your custom JWT middleware

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fanaSystem.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": JWTAuthenticationMiddleware(  # Replace AuthMiddlewareStack with custom middleware
        URLRouter(
            routing.websocket_urlpatterns
        )
    ),
})
