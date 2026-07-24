"""用户 / 钱包相关 handler —— 单 handler 漏洞(对照基线)。

这些漏洞在单个 handler 内即可判定,无图组直读源码应当也能发现,用作基线,
以便和跨 handler 漏洞的两组表现做对比。
"""
from __future__ import annotations

from flask import request

from auth import VULN, current_user, error
from models import User, Wallet, db


def register():
    """注册新用户。

    ★单 handler 漏洞(trust_boundary / mass assignment):vuln 版直接采信请求体里
    的 role 字段,允许自注册为 admin。服务端不得信任客户端传入的权限字段。
    """
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    if db.user_by_name(username):
        return error("User already exists.", 400)
    uid = db.next_id(db.users)

    if VULN:
        # 采信客户端 role 字段 —— 提权
        user = User(uid, username, body.get("password", ""), role=body.get("role", "user"))
    else:
        user = User(uid, username, body.get("password", ""), role="user")
    db.users[uid] = user
    db.wallets[uid] = Wallet(uid, balance=0)
    return {"id": uid, "message": "Registered."}, 200


def login():
    """登录,签发演示 token。"""
    body = request.get_json(silent=True) or {}
    user = db.user_by_name(body.get("username", ""))
    if not user or user.password != body.get("password", ""):
        return error("Invalid credentials.", 401)
    return {"token": f"token-{user.id}"}, 200


def get_me():
    """查看自己的资料。★正确的兄弟 handler:只返回当前用户自己。★"""
    user = current_user()
    if not user:
        return error("Authentication required.", 401)
    return {"id": user.id, "username": user.username, "role": user.role}, 200


def list_users():
    """列出所有用户(含 role)——管理功能。

    ★单 handler 漏洞(role / BFLA):vuln 版只校验登录、不校验 admin,
    任何登录用户都能拉取全部用户列表。对比 issue_coupon 里写对了的 admin 校验。
    """
    user = current_user()
    if not user:
        return error("Authentication required.", 401)
    if not VULN:
        if user.role != "admin":
            return error("Admin only.", 403)
    # vuln 版:漏了 admin 校验
    users = [{"id": u.id, "username": u.username, "role": u.role} for u in db.users.values()]
    return {"users": users}, 200


def get_wallet(user_id):
    """查看某钱包余额。

    ★单 handler 漏洞(authentication + ownership):vuln 版既不要求登录、也不校验
    钱包归属,任何人可用 user_id 枚举查看他人余额。对比 get_me 只暴露自己。
    """
    if VULN:
        wallet = db.wallets.get(user_id)
        if not wallet:
            return error("Wallet not found.", 404)
        return {"user_id": wallet.user_id, "balance": wallet.balance}, 200
    else:
        user = current_user()
        if not user:
            return error("Authentication required.", 401)
        if user.id != user_id:
            return error("Not your wallet.", 403)
        wallet = db.wallets.get(user_id)
        return {"user_id": wallet.user_id, "balance": wallet.balance}, 200
