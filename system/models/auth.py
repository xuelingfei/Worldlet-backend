# -*- coding: utf-8 -*-
from django.db import models

from system.models.base import BaseModel
from system.models.person import Person
from system.utils.cryption import CryptHash


class User(BaseModel):
    avatar = models.ImageField(verbose_name='头像', null=True, upload_to='avatar/')
    name = models.CharField(verbose_name='用户名', null=True, max_length=50)
    mobile = models.CharField(verbose_name='手机号', null=True, max_length=50)
    mail = models.EmailField(verbose_name='邮箱', null=True)
    password = models.CharField(verbose_name='密码', null=True, max_length=255)
    admin = models.IntegerField(verbose_name='是否是管理员', null=True, choices=BaseModel.IS_OR_NOT, default=BaseModel.NOT)
    last_login = models.DateTimeField(verbose_name='上次登录时间', null=True)

    person = models.ForeignKey(Person, verbose_name='实名信息', null=True, on_delete=models.DO_NOTHING,
                               related_name='system_Users_related')

    create_user = models.ForeignKey('self', null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_UsersCreated_related')
    update_user = models.ForeignKey('self', null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_UsersUpdated_related')

    class Meta:
        verbose_name = '用户表'

    # password 字段需加密
    def save(self, *args, **kwargs):
        if self.id and not self.password:
            user = User.objects.get(pk=self.id)
            self.password = user.password
        elif self.password:
            self.password = CryptHash.hmac_sha(self.password)
        super(User, self).save(*args, **kwargs)


class Menu(BaseModel):
    name = models.CharField(verbose_name='名称', null=True, max_length=50)
    map = models.CharField(verbose_name='映射', null=True, max_length=50)
    icon = models.CharField(verbose_name='图标', null=True, max_length=50)
    index = models.IntegerField(verbose_name='排序', default=0)
    parent = models.ForeignKey('self', verbose_name='父菜单', null=True, on_delete=models.SET_NULL,
                               related_name='system_Menus_related')
    description = models.TextField(verbose_name='描述', null=True)

    create_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_MenusCreated_related')
    update_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_MenusUpdated_related')

    class Meta:
        verbose_name = '菜单表'


class Access(BaseModel):
    BACKEND, FRONTEND = ['0', '1']
    POSITION_CHOICE = [
        (FRONTEND, '前台'),
        (BACKEND, '后台'),
    ]
    MENU, FUNC = ['0', '1']
    KIND_CHOICE = [
        (MENU, '菜单'),
        (FUNC, '功能'),
    ]
    name = models.CharField(verbose_name='名称', null=True, max_length=50)
    map = models.CharField(verbose_name='映射', null=True, max_length=50)
    description = models.TextField(verbose_name='描述', null=True)

    menu = models.ForeignKey(Menu, verbose_name='关联菜单', null=True, on_delete=models.SET_NULL,
                             related_name='system_Accesses_related')

    position = models.CharField(verbose_name='位置', null=True, max_length=50, choices=POSITION_CHOICE)
    kind = models.CharField(verbose_name='类型', null=True, max_length=50, choices=KIND_CHOICE)

    create_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_AccessesCreated_related')
    update_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_AccessesUpdated_related')

    class Meta:
        verbose_name = '权限表'


class Role(BaseModel):
    name = models.CharField(verbose_name='角色名', null=True, max_length=50)
    description = models.TextField(verbose_name='描述', null=True)

    create_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_RolesCreated_related')
    update_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_RolesUpdated_related')

    class Meta:
        verbose_name = '角色表'


class RoleAccess(BaseModel):
    related_accesses = models.TextField(verbose_name='关联权限', null=True)
    role = models.ForeignKey(Role, verbose_name="角色", null=True, on_delete=models.SET_NULL,
                             related_name='system_RoleMenus_related')

    create_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_RoleMenusCreated_related')
    update_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_RoleMenusUpdated_related')

    class Meta:
        verbose_name = '角色权限表'
        db_table = 'system_role_access'


class UserRole(BaseModel):
    related_roles = models.TextField(verbose_name='关联角色', null=True)
    user = models.ForeignKey(User, verbose_name='用户', null=True, on_delete=models.SET_NULL,
                             related_name='system_UserRoles_related')

    create_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_UserRolesCreated_related')
    update_user = models.ForeignKey(User, null=True, on_delete=models.DO_NOTHING,
                                    related_name='system_UserRolesUpdated_related')

    class Meta:
        verbose_name = '用户角色表'
        db_table = 'system_user_role'
