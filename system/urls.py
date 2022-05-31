# -*- coding: utf-8 -*-
from django.urls import path

from system.views import auth_views


app_name = 'system'
urlpatterns = [
    # 认证授权
    path('login', auth_views.login, name='login'),
    path('register', auth_views.register, name='register'),
]
