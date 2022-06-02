# -*- coding: utf-8 -*-
import json


class JsonRespWrapper:
    """
    code
    1 成功
    0 未登录
    -1 失败
    """
    @staticmethod
    def success(message, data=None):
        resp = {"success": True, "code": "1", "message": message, "data": data}
        return json.dumps(resp)
        # return json.dumps(resp, ensure_ascii=False)

    @staticmethod
    def error(message, code='-1'):
        resp = {"success": False, "code": code, "message": message}
        return json.dumps(resp)

    @staticmethod
    def not_login():
        resp = {"success": False, "code": "0", "message": "未登录"}
        return json.dumps(resp)
