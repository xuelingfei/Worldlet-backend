# -*- coding: utf-8 -*-
from django.core.exceptions import PermissionDenied
from django.shortcuts import render


def login(request):
    ctx = {
        'title': '登录',
    }
    return render(request, 'default.html', ctx)


def register(request):
    raise PermissionDenied
