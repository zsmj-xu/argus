"""订单(Order)相关 handler —— 跨 handler 逻辑漏洞的主战场。

订单状态机在多个 handler 间流转:
    create_order  : (none)   -> created
    pay_order     : created  -> paid       (从钱包扣款)
    ship_order    : paid     -> shipped    (只有卖家能发货)  ← 漏洞①
    return_order  : shipped  -> return_requested (只有买家能申请)  ← 兄弟(写对了)
    refund_order  : return_requested -> refunded (退款到买家钱包)  ← 漏洞②

要判定 ship_order / refund_order 是否安全,**必须跨 handler**理解:
- ship 的"谁有权"来自 Listing.seller_id(在 create_listing 时确定,不在 order 里);
- refund 的"能否退"来自订单状态机(在 create/pay/return 里一步步建立),
  以及退款只能发生一次(replay)。
只读 ship_order / refund_order 单个函数体,看不出这些约束。
"""
from __future__ import annotations

from flask import request

from auth import VULN, current_user, error
from models import Order, db


def create_order():
    """买家对某 listing 下单。状态 -> created。"""
    user = current_user()
    if not user:
        return error("Authentication required.", 401)
    body = request.get_json(silent=True) or {}
    listing = db.listings.get(int(body.get("listing_id", 0)))
    if not listing or listing.status != "active":
        return error("Listing not available.", 400)
    oid = db.next_id(db.orders)
    order = Order(id=oid, listing_id=listing.id, buyer_id=user.id, amount=listing.price)
    db.orders[oid] = order
    return {"id": oid, "status": order.status}, 200


def pay_order(order_id):
    """买家付款:created -> paid,从买家钱包扣款。"""
    user = current_user()
    if not user:
        return error("Authentication required.", 401)
    order = db.orders.get(order_id)
    if not order:
        return error("Order not found.", 404)
    if order.buyer_id != user.id:
        return error("Not your order.", 403)
    if order.status != "created":
        return error("Order not payable.", 400)
    wallet = db.wallets[user.id]
    if wallet.balance < order.amount:
        return error("Insufficient balance.", 400)
    wallet.balance -= order.amount
    order.status = "paid"
    return {"status": order.status, "balance": wallet.balance}, 200


def ship_order(order_id):
    """发货:paid -> shipped。

    ★漏洞①(跨 handler ownership / BOLA):发货本应只有该订单对应 listing 的
    **卖家**能操作。卖家身份不在 order 上,要顺着 order.listing_id -> Listing.seller_id
    才能拿到。vuln 版跳过了这层校验,任何登录用户都能把别人的订单标记为已发货
    (可用于诈骗:标记发货却从不真正发货,或抢先发货扰乱交易)。

    对比 update_listing 里写对了的 owner 校验——这里是"漏写"。
    """
    user = current_user()
    if not user:
        return error("Authentication required.", 401)
    order = db.orders.get(order_id)
    if not order:
        return error("Order not found.", 404)
    if order.status != "paid":
        return error("Order not in a shippable state.", 400)

    if VULN:
        # 缺少 seller 所有权校验:没有把 order 接回 listing 的卖家
        order.status = "shipped"
        return {"status": order.status}, 200
    else:
        listing = db.listings.get(order.listing_id)
        if not listing or listing.seller_id != user.id:
            return error("Only the seller can ship this order.", 403)
        order.status = "shipped"
        return {"status": order.status}, 200


def return_order(order_id):
    """申请退货:shipped -> return_requested。★正确的兄弟 handler:校验了 buyer。★

    与 ship_order 对照:这里 *有* 归属校验(只有买家能申请退货),
    证明 ship_order 缺 seller 校验是漏写。
    """
    user = current_user()
    if not user:
        return error("Authentication required.", 401)
    order = db.orders.get(order_id)
    if not order:
        return error("Order not found.", 404)
    # ownership:只有买家本人能对自己的订单申请退货
    if order.buyer_id != user.id:
        return error("Not your order.", 403)
    if order.status != "shipped":
        return error("Order not returnable.", 400)
    order.status = "return_requested"
    return {"status": order.status}, 200


def refund_order(order_id):
    """退款:return_requested -> refunded,把款退回买家钱包。

    ★漏洞②(跨 handler replay / 幂等):退款必须满足两个跨 handler 约束——
    (a) 订单状态确实处于 return_requested(由 create->pay->return 一路流转建立);
    (b) 退款只能发生一次(否则重复退款,凭空生成余额)。
    vuln 版既不校验状态机、也不设置终态,导致同一订单可被反复退款,每次都给
    买家钱包加钱。单看本函数体只看到"给钱包加钱",看不出它破坏了状态机不变量。

    对比 pay_order 里 `order.status != 'created'` 的状态校验——这里是漏写。
    """
    user = current_user()
    if not user:
        return error("Authentication required.", 401)
    order = db.orders.get(order_id)
    if not order:
        return error("Order not found.", 404)
    if order.buyer_id != user.id:
        return error("Not your order.", 403)

    if VULN:
        # 既不校验 status == return_requested,也不置为终态 refunded:可重放
        db.wallets[order.buyer_id].balance += order.amount
        return {"status": "refunded", "balance": db.wallets[order.buyer_id].balance}, 200
    else:
        if order.status != "return_requested":
            return error("Order not in refundable state.", 400)
        db.wallets[order.buyer_id].balance += order.amount
        order.status = "refunded"  # 终态,防重放
        return {"status": order.status, "balance": db.wallets[order.buyer_id].balance}, 200
