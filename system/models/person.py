# -*- coding: utf-8 -*-
from django.db import models

from system.models.base import BaseModel


class Person(BaseModel):
    FEMALE = 0
    MALE = 1
    GENDER_CHOICE = [
        (FEMALE, '女'),
        (MALE, '男'),
    ]

    name = models.CharField(verbose_name='姓名', null=True, max_length=50)
    gender = models.IntegerField(verbose_name='性别', null=True, choices=GENDER_CHOICE)
    birthday = models.DateField(verbose_name='生日', null=True)
    lunar_birthday = models.CharField(verbose_name='农历生日', null=True, max_length=10)  # YYYY-RMM-DD 格式，R: 0 非闰月，1 闰月
    description = models.TextField(verbose_name='描述', null=True)
    signature = models.TextField(verbose_name='个性签名', null=True)

    real = models.IntegerField(verbose_name='是否已实名', null=True, choices=BaseModel.IS_OR_NOT, default=BaseModel.NOT)
    id_number = models.CharField(verbose_name='身份证号', null=True, max_length=255)

    create_user = models.IntegerField(null=True)
    update_user = models.IntegerField(null=True)

    class Meta:
        verbose_name = '个人信息表'
