# -*- coding: utf-8 -*-
from django.db import models


class BaseModel(models.Model):
    FALSE = 0
    TRUE = 1
    IS_OR_NOT = (
        (FALSE, '否'),
        (TRUE, '是'),
    )

    STATE_DELETE = -1  # 已删除
    STATE_HIDDEN = 0  # 已隐藏
    STATE_NORMAL = 1  # 正常
    STATE_CHOICE = [
        (STATE_DELETE, '已删除'),
        (STATE_HIDDEN, '已隐藏'),
        (STATE_NORMAL, '正常'),
    ]

    state = models.IntegerField(verbose_name='状态', null=True, choices=STATE_CHOICE)
    create_time = models.DateTimeField(verbose_name='创建时间', null=True, auto_now_add=True)
    update_time = models.DateTimeField(verbose_name='更新时间', null=True, auto_now=True)

    class Meta:
        abstract = True
        verbose_name = '基础对象'

    def __str__(self):
        if self.state == BaseModel.STATE_NORMAL:
            if hasattr(self, 'name'):
                return self.name
            else:
                return '%s object (%s)' % (self.__class__.__name__, self.pk)
        else:
            return None
