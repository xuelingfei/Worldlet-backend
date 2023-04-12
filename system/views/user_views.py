# -*- coding: utf-8 -*-
from django.contrib.auth.models import User
from django.shortcuts import render
from django_middleware_global_request import get_request


def index(request):
    ctx = {}
    user = User.objects.filter(pk=1)
    setattr(request, 'user', {id: 1})
    r = get_request()
    print(r)
    return render(request, 'index.html', ctx)
