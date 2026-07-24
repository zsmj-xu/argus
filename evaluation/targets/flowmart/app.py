"""Runnable Flask wrapper for the flowmart static-analysis benchmark."""

from __future__ import annotations

from pathlib import Path

import yaml
from flask import Flask, jsonify

from auth import VULN
from api.coupons import issue_coupon, redeem_coupon
from api.listings import create_listing, list_listings, update_listing
from api.orders import create_order, pay_order, refund_order, return_order, ship_order
from api.support import preview_message
from api.users import get_me, get_wallet, list_users, login, register


def create_app() -> Flask:
    app = Flask(__name__)

    app.add_url_rule("/users/register", view_func=register, methods=["POST"])
    app.add_url_rule("/users/login", view_func=login, methods=["POST"])
    app.add_url_rule("/users/me", view_func=get_me, methods=["GET"])
    app.add_url_rule("/users", view_func=list_users, methods=["GET"])
    app.add_url_rule("/wallets/<int:user_id>", view_func=get_wallet, methods=["GET"])
    app.add_url_rule("/listings", view_func=list_listings, methods=["GET"])
    app.add_url_rule("/listings", view_func=create_listing, methods=["POST"])
    app.add_url_rule("/listings/<int:listing_id>", view_func=update_listing, methods=["PUT"])
    app.add_url_rule("/orders", view_func=create_order, methods=["POST"])
    app.add_url_rule("/orders/<int:order_id>/pay", view_func=pay_order, methods=["POST"])
    app.add_url_rule("/orders/<int:order_id>/ship", view_func=ship_order, methods=["POST"])
    app.add_url_rule("/orders/<int:order_id>/return", view_func=return_order, methods=["POST"])
    app.add_url_rule("/orders/<int:order_id>/refund", view_func=refund_order, methods=["POST"])
    app.add_url_rule("/coupons/issue", view_func=issue_coupon, methods=["POST"])
    app.add_url_rule("/coupons/redeem", view_func=redeem_coupon, methods=["POST"])
    app.add_url_rule("/support/preview", view_func=preview_message, methods=["GET"])

    @app.get("/openapi.json")
    def openapi():
        spec_path = Path(__file__).parent / "openapi_specs" / "openapi3.yml"
        return jsonify(yaml.safe_load(spec_path.read_text(encoding="utf-8")))

    @app.get("/health")
    def health():
        return {"status": "ok", "vulnerable": bool(VULN)}

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5000)
