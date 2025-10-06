"""example URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
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
from django.contrib import admin
from django.urls import path, re_path, include
from . import views, auth
from mfa import TrustedDevice

urlpatterns = [
    path("admin/", admin.site.urls),
    path("mfa/", include("mfa.urls")),
    path("auth/login", auth.loginView, name="login"),
    path("auth/logout", auth.logoutView, name="logout"),
    path("devices/add/", TrustedDevice.add, name="add_trusted_device"),
    re_path("^$", views.home, name="home"),
    path("registered/", views.registered, name="registered"),
]
