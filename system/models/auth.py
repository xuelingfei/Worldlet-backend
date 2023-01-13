# -*- coding: utf-8 -*-
import hashlib

from django.db import models

from system.models.base import BaseModel
from system.models.person import Person


class User(BaseModel):
    avatar = models.ImageField(verbose_name='头像', null=True, upload_to='avatar/')
    name = models.CharField(verbose_name='用户名', null=True, max_length=50)
    mobile = models.CharField(verbose_name='手机号', null=True, max_length=50)
    mail = models.EmailField(verbose_name='邮箱', null=True)
    password = models.CharField(verbose_name='密码', null=True, max_length=50)
    is_admin = models.IntegerField(verbose_name='是否是管理员', null=True, choices=BaseModel.IS_OR_NOT, default=0)
    last_login = models.DateTimeField(verbose_name='上次登录时间', null=True)

    person = models.ForeignKey(Person, null=True, on_delete=models.DO_NOTHING)

    create_user = models.ForeignKey('self', null=True, on_delete=models.DO_NOTHING)#related_name="%(app_label)s_%(class)s_related", related_query_name="%(app_label)s_%(class)ss",
    update_user = models.ForeignKey('self', null=True, on_delete=models.DO_NOTHING)#如果你未指定抽象基类中的 related_name 属性，默认的反转名会是子类名，后接 '_set' 。

    class Meta:
        verbose_name = '用户表'
        db_table = 'system_user'

    # password 字段需加密
    def save(self, *args, **kwargs):
        if self.id and not self.password:
            user = User.objects.get(pk=self.id)
            self.password = user.password
        elif self.password:
            self.password = hashlib.md5(self.password.encode(encoding='utf-8')).hexdigest()
        super(User, self).save(*args, **kwargs)


class Role(BaseModel):
    name = models.CharField(verbose_name='角色名', null=True, max_length=50)
    description = models.TextField(verbose_name='描述', null=True)

    create_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING)
    update_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING)

    class Meta:
        verbose_name = '角色表'
        db_table = 'system_role'


class Menu(BaseModel):
    MENU = 0
    OPERATION = 1
    TYPE_CHOICE = (
        (MENU, '菜单'),
        (OPERATION, '操作'),
    )
    name = models.CharField(verbose_name='名称', null=True, max_length=50)
    type_ = models.IntegerField(verbose_name='类型', null=True, choices=TYPE_CHOICE)
    url = models.CharField(verbose_name='映射地址', null=True, max_length=50)
    icon = models.CharField(verbose_name='图标', null=True, max_length=254)
    index = models.IntegerField(verbose_name='排序', default=0)
    parent = models.ForeignKey('self', verbose_name='父菜单', null=True, on_delete=models.SET_NULL)
    description = models.TextField(verbose_name='描述', null=True)

    create_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING)
    update_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING)

    class Meta:
        verbose_name = '菜单表'
        db_table = 'system_menu'

    def __str__(self):
        return self.name if self.state == BaseModel.STATE_NORMAL and self.type_ == Menu.TYPE_CHOICE[0][0] else None


class UserRole(BaseModel):
    related_roles = models.TextField(verbose_name='关联角色', null=True)
    user = models.ForeignKey(User, verbose_name='用户', null=True, on_delete=models.SET_NULL)

    create_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING)
    update_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING)

    class Meta:
        verbose_name = '用户角色表'
        db_table = 'system_user_role'


class RoleMenu(BaseModel):
    related_menus = models.TextField(verbose_name='关联菜单', null=True)
    role = models.ForeignKey(Role, verbose_name="角色", null=True, on_delete=models.SET_NULL)

    create_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING)
    update_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING)

    class Meta:
        verbose_name = '角色菜单表'
        db_table = 'system_role_menu'
