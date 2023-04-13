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
    path('403', auth_views.page_permission_denied, name='page_permission_denied'),
    path('404', auth_views.page_not_found, name='page_not_found'),
    path('500', auth_views.page_error, name='page_error'),

    # 用户管理
    path('user/index', user_views.index, name='user_index'),
]
