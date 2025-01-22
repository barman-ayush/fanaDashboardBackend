"""
URL configuration for fanaSystem project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# fanaDashboard/urls.py

from django.urls import path
from . import views

urlpatterns = [
    
    path('test/', views.test_view, name='test_view'),
    path('sendOtp/', views.send_otp, name='send_view'),
    path('verifyOtp/', views.verify_otp, name='verify_view'),
    path('login/', views.login_view, name='login_view'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('handleFanaCall/', views.handle_fana_call, name='handleFanaCall'),
    path('setSession/', views.set_session, name='set_session'),
    path('receiveOrder/', views.receive_order, name='receive_order')
]

