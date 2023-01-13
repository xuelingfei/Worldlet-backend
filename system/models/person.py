# -*- coding: utf-8 -*-
from django.db import models

from system.models.base import BaseModel


class Person(BaseModel):
    WOMAN = 0
    MAN = 1
    GENDER_CHOICE = [
        (WOMAN, '女'),
        (MAN, '男'),
    ]

    nickname = models.CharField(verbose_name='昵称', null=True, max_length=50)
    gender = models.CharField(verbose_name='性别', null=True, choices=GENDER_CHOICE)
    birthday = models.DateField(verbose_name='生日', null=True)
    lunar_birthday = models.CharField(verbose_name='农历生日', null=True, max_length=10,
                                      db_column='lunar_birthday')  # YYYY-RMM-DD 格式，R: 0 非闰月，1 闰月
    description = models.TextField(verbose_name='描述', null=True)
    signature = models.TextField(verbose_name='个性签名', null=True)

    is_real = models.IntegerField(verbose_name='是否已实名', null=True, choices=BaseModel.IS_OR_NOT, default=0,
                                  db_column='is_real')
    real_name = models.CharField(verbose_name='真实姓名', null=True, max_length=50, db_column='real_name')
    id_number = models.CharField(verbose_name='身份证号', null=True, max_length=50, db_column='id_number')

    create_user = models.CharField(null=True, max_length=50)
    update_user = models.CharField(null=True, max_length=50)

    class Meta:
        verbose_name = '个人信息表'
        db_table = 'system_person'

    def __str__(self):
        if self.state == BaseModel.STATE_NORMAL:
            if hasattr(self, 'real_name'):
                return self.real_name
            elif hasattr(self, 'nickname'):
                return self.nickname
            else:
                return '%s object (%s)' % (self.__class__.__name__, self.pk)
        else:
            return None
