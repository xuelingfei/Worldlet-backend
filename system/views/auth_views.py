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
    ctx = {}
    user = User.objects.filter(pk=1)
    ctx['username'] = '管理员'
    menu_tree = [
        {'id': 1, 'icon': 'layui-icon-home', 'path': 'home', 'label': '首页', 'hasChildren': False,
         'data': dumps({'id': 1, 'path': 'home', 'label': '首页', 'hasChildren': False})},
        {'id': 2, 'label': '系统管理', 'hasChildren': True,
         'data': dumps({'id': 2, 'label': '系统管理', 'hasChildren': True}),
         'children': [
             {'id': 21, 'path': 'user/index', 'label': '用户管理', 'hasChildren': False,
              'data': dumps({'id': 21, 'path': 'user/index', 'label': '用户管理', 'hasChildren': False})},
             {'id': 22, 'path': 'user/add', 'label': '用户', 'hasChildren': False,
              'data': dumps({'id': 22, 'path': 'user/add', 'label': '用户', 'hasChildren': False})},
         ]},
        {'id': 3, 'label': '特殊页面', 'hasChildren': True,
         'data': dumps({'id': 3, 'label': '特殊页面', 'hasChildren': True}),
         'children': [
             {'id': 403, 'path': '403', 'label': '403', 'hasChildren': False,
              'data': dumps({'id': 403, 'path': '403', 'label': '403', 'hasChildren': False})},
             {'id': 404, 'path': '404', 'label': '404', 'hasChildren': False,
              'data': dumps({'id': 404, 'path': '404', 'label': '404', 'hasChildren': False})},
             {'id': 500, 'path': '500', 'label': '500', 'hasChildren': False,
              'data': dumps({'id': 500, 'path': '500', 'label': '500', 'hasChildren': False})},
             {'id': 502, 'path': '502', 'label': '502', 'hasChildren': False,
              'data': dumps({'id': 500, 'path': '502', 'label': '502', 'hasChildren': False})},
         ]},
        {},
    ]
    ctx['menuTree'] = menu_tree
    return render(request, 'layout.html', ctx)


def home(request):
    ctx = {'title': 'home'}
    return render(request, 'home.html', ctx)


def page_permission_denied(request):
    return render(request, '403.html', {})


def page_not_found(request):
    return render(request, '404.html', {})


def page_error(request):
    return render(request, '500.html', {})
