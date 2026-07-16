"""商品(Listing)相关 handler。

对照点:update_listing 正确地校验了 owner(seller),create/get 无需归属。
这为下游 orders.ship_order「缺少 seller 校验」提供了非对称对照证据。
"""
from __future__ import annotations

from flask import request

from auth import VULN, current_user, error
from models import Listing, db


def list_listings():
    """公开:任何人可浏览在售商品。无需鉴权、无归属概念。"""
    items = [
        {"id": l.id, "seller_id": l.seller_id, "title": l.title,
         "price": l.price, "status": l.status}
        for l in db.listings.values()
    ]
    return {"listings": items}, 200


def create_listing():
    """已登录用户挂出商品。卖家即当前用户(服务端决定,不采信请求体)。"""
    user = current_user()
    if not user:
        return error("Authentication required.", 401)
    body = request.get_json(silent=True) or {}
    lid = db.next_id(db.listings)
    listing = Listing(
        id=lid,
        seller_id=user.id,          # 归属由服务端设定
        title=body.get("title", ""),
        price=int(body.get("price", 0)),
    )
    db.listings[lid] = listing
    return {"id": lid, "message": "Listing created."}, 200


def update_listing(listing_id):
    """更新商品。★正确实现的兄弟 handler:校验了 owner。★

    这是对照组:同一套代码里 owner 校验 *是* 会写的,说明 ship_order 缺失
    seller 校验是"漏写",而非框架不支持。
    """
    user = current_user()
    if not user:
        return error("Authentication required.", 401)
    listing = db.listings.get(listing_id)
    if not listing:
        return error("Listing not found.", 404)
    # ownership:只有卖家本人能改自己的商品
    if listing.seller_id != user.id:
        return error("You do not own this listing.", 403)
    body = request.get_json(silent=True) or {}
    if "title" in body:
        listing.title = body["title"]
    if "price" in body:
        listing.price = int(body["price"])
    return {"message": "Listing updated."}, 200
