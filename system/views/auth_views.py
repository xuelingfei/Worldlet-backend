# -*- coding: utf-8 -*-
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
    print(r)
    return render(request, 'layout.html', ctx)


def home(request):
    ctx = {}
    user = User.objects.filter(pk=1)
    setattr(request, 'user', {id: 1})
    r = get_request()
    print(r)
    return render(request, 'default.html', ctx)
