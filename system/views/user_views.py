# -*- coding: utf-8 -*-
from django.contrib.auth.models import User
from django.shortcuts import render
from django_middleware_global_request import get_request


def index(request):
    ctx = {'title': 'user_index'}
    return render(request, 'index.html', ctx)
