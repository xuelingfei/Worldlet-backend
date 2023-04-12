# -*- coding: utf-8 -*-
from django.urls import path

from system.views import auth_views, user_views

app_name = 'system'
urlpatterns = [
    # 认证授权
    path('login', auth_views.login, name='login'),
    path('register', auth_views.register, name='register'),
    path('', auth_views.layout, name='layout'),
    path('home', auth_views.home, name='home'),

    # 用户管理
    path('user/index', user_views.index, name='user_index'),
]
