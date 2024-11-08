# fanaDashboard/routing.py
from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path("ws/fanaDashboard/", consumers.DashboardConsumer.as_asgi()),
]
