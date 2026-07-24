"""优惠券(Coupon)相关 handler。

★漏洞③(跨 handler ownership + replay):优惠券在**签发时**绑定给特定用户
(Coupon.issued_to,在 issue_coupon 里确定),兑换时本应校验"兑换者 == 被签发者"。
vuln 版的 redeem 只按 code 查券、不校验归属,导致任何知道 code 的用户都能兑换
本不属于自己的券把钱加到自己钱包(跨用户越权 + 侵占额度)。

判定这个漏洞必须跨 handler:redeem 函数体里只有一个 code 字符串,"这张券属于谁"
的信息在另一个 handler(issue_coupon)写入的 issued_to 字段里。
"""
from __future__ import annotations

from flask import request

from auth import VULN, current_user, error
from models import Coupon, db


def issue_coupon():
    """管理员给某用户签发一张优惠券,绑定 issued_to。

    这里确立了"券归属"这一业务事实,供 redeem 侧校验。
    """
    user = current_user()
    if not user:
        return error("Authentication required.", 401)
    # role:仅管理员可签发优惠券
    if user.role != "admin":
        return error("Admin only.", 403)
    body = request.get_json(silent=True) or {}
    code = body.get("code", "")
    coupon = Coupon(
        code=code,
        issued_to=int(body.get("issued_to", 0)),
        amount=int(body.get("amount", 0)),
    )
    db.coupons[code] = coupon
    return {"code": code, "message": "Coupon issued."}, 200


def redeem_coupon():
    """兑换优惠券,把面额加到当前用户钱包。

    ★漏洞③:vuln 版不校验 coupon.issued_to == 当前用户(跨 handler ownership),
    任何持 code 者都能兑换他人的券。(replay 侧则由 redeemed 标志控制。)
    """
    user = current_user()
    if not user:
        return error("Authentication required.", 401)
    body = request.get_json(silent=True) or {}
    code = body.get("code", "")
    coupon = db.coupons.get(code)
    if not coupon:
        return error("Coupon not found.", 404)
    if coupon.redeemed:
        return error("Coupon already redeemed.", 400)

    if VULN:
        # 缺少归属校验:没有比对 coupon.issued_to == user.id
        coupon.redeemed = True
        db.wallets[user.id].balance += coupon.amount
        return {"balance": db.wallets[user.id].balance, "message": "Redeemed."}, 200
    else:
        if coupon.issued_to != user.id:
            return error("This coupon was not issued to you.", 403)
        coupon.redeemed = True
        db.wallets[user.id].balance += coupon.amount
        return {"balance": db.wallets[user.id].balance, "message": "Redeemed."}, 200
