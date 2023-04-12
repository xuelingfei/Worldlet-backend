# -*- coding: utf-8 -*-
from json import dumps

from django.core.exceptions import PermissionDenied
from django.shortcuts import render
from django_middleware_global_request import get_request

from system.models.auth import User


def login(request):
    ctx = {
        'title': '登录',
    }
    user = User.objects.filter(pk=1)
    setattr(request, 'user', {id: 1})
    r = get_request()
    print(r)
    return render(request, 'base.html', ctx)


def register(request):
    raise PermissionDenied


def layout(request):
    ctx = {
        'username': '登录',
    }
    user = User.objects.filter(pk=1)
    setattr(request, 'user', {id: 1})
    r = get_request()
    menu_tree = [
        {'id': 1, 'icon': 'layui-icon-home', 'path': 'home', 'label': '首页', 'hasChildren': False,
         'data': dumps({'id': 1, 'path': 'home', 'label': '首页', 'hasChildren': False})},
        {'id': 1, 'path': 'user/index', 'label': '用户管理', 'hasChildren': True,
         'data': dumps({'id': 1, 'path': 'user/index', 'label': '用户管理', 'hasChildren': True}),
         'children': [
             {'id': 1, 'path': 'user/index', 'label': '用户管理', 'hasChildren': False,
              'data': dumps({'id': 1, 'path': 'user/index', 'label': '用户管理', 'hasChildren': False})},
             {'id': 1, 'path': 'user/index', 'label': '用户管理', 'hasChildren': False,
              'data': dumps({'id': 1, 'path': 'user/index', 'label': '用户管理', 'hasChildren': False})},
             {'id': 1, 'path': 'user/index', 'label': '用户管理', 'hasChildren': False,
              'data': dumps({'id': 1, 'path': 'user/index', 'label': '用户管理', 'hasChildren': False})},
         ]},
        {}
    ]
    ctx['menuTree'] = menu_tree
    return render(request, 'layout.html', ctx)


def home(request):
    ctx = {}
    user = User.objects.filter(pk=1)
    setattr(request, 'user', {id: 1})
    r = get_request()
    print(r)
    return render(request, 'index.html', ctx)
