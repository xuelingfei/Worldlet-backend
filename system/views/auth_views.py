# -*- coding: utf-8 -*-
from django.core.exceptions import PermissionDenied
from django.shortcuts import render

from system.models.auth import User


def login(request):
    ctx = {
        'title': '登录',
    }
    user = User.objects.filter(pk=1)
    return render(request, 'default.html', ctx)


def register(request):
    raise PermissionDenied
