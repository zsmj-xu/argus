"""认证/鉴权辅助。

token_required 校验登录态(authentication);current_user 取当前用户。
角色校验(role)与所有权校验(ownership)由各 handler 自行负责——本靶场的
漏洞正在于:某些 handler 忘了做本应做的 ownership/role 校验。
"""
from __future__ import annotations

import os

from flask import request

from models import User, db

VULN = int(os.getenv("VULN", "1"))


def _decode_token(token: str) -> int | None:
    """演示用极简 token:格式 'token-<user_id>'。真实场景是 JWT。"""
    if token and token.startswith("token-"):
        try:
            return int(token.split("-", 1)[1])
        except ValueError:
            return None
    return None


def current_user() -> User | None:
    """从 Authorization 头解析当前用户。返回 None 表示未认证。"""
    auth = request.headers.get("Authorization", "")
    parts = auth.split(" ")
    token = parts[1] if len(parts) == 2 else ""
    uid = _decode_token(token)
    if uid is None:
        return None
    return db.users.get(uid)


def error(msg: str, code: int):
    from flask import jsonify

    resp = jsonify({"status": "fail", "message": msg})
    resp.status_code = code
    return resp
