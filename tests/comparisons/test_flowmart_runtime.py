"""Runtime smoke tests for the Shannon-compatible flowmart wrapper."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any

import pytest

flask = pytest.importorskip("flask")
Flask = flask.Flask

ROOT = Path(__file__).resolve().parents[2]
FLOWMART = ROOT / "evaluation" / "targets" / "flowmart"


@pytest.fixture
def flowmart_app(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(FLOWMART))
    monkeypatch.setenv("VULN", "1")
    for name in (
        "app",
        "auth",
        "models",
        "api",
        "api.users",
        "api.orders",
        "api.coupons",
        "api.listings",
        "api.support",
    ):
        sys.modules.pop(name, None)
    module = importlib.import_module("app")
    app = module.create_app()
    app.config["TESTING"] = True
    return app


def _login(client: Any, username: str, password: str) -> dict[str, str]:
    response = client.post("/users/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


def test_health_openapi_and_seeded_login(flowmart_app: Any) -> None:
    client = flowmart_app.test_client()

    assert client.get("/health").get_json() == {"status": "ok", "vulnerable": True}
    spec = client.get("/openapi.json").get_json()
    assert spec["openapi"] == "3.0.0"
    assert "/orders/{order_id}/refund" in spec["paths"]
    assert _login(client, "alice", "alice-pw")["Authorization"] == "Bearer token-1"
    xss = client.get("/support/preview", query_string={"message": "<script>alert(1)</script>"})
    assert b"<script>alert(1)</script>" in xss.data


def test_vulnerable_business_flows_are_reachable_over_http(flowmart_app: Any) -> None:
    client = flowmart_app.test_client()
    alice = _login(client, "alice", "alice-pw")
    bob = _login(client, "bob", "bob-pw")

    # Missing authentication + ownership on wallet lookup.
    assert client.get("/wallets/1").status_code == 200

    # Client-controlled role during registration.
    registered = client.post(
        "/users/register",
        json={"username": "mallory", "password": "pw", "role": "admin"},
    )
    assert registered.status_code == 200
    mallory = _login(client, "mallory", "pw")
    me = client.get("/users/me", headers=mallory).get_json()
    assert me["role"] == "admin"

    # Coupon issued to alice can be redeemed by bob.
    redeemed = client.post("/coupons/redeem", headers=bob, json={"code": "WELCOME50"})
    assert redeemed.status_code == 200

    # Bob buys alice's listing and can ship it despite not being the seller.
    created = client.post("/orders", headers=bob, json={"listing_id": 1}).get_json()
    order_id = created["id"]
    assert client.post(f"/orders/{order_id}/pay", headers=bob).status_code == 200
    assert client.post(f"/orders/{order_id}/ship", headers=bob).status_code == 200
    assert client.post(f"/orders/{order_id}/return", headers=bob).status_code == 200

    # Refund does not transition to a terminal state and can be replayed.
    first = client.post(f"/orders/{order_id}/refund", headers=bob).get_json()
    second = client.post(f"/orders/{order_id}/refund", headers=bob).get_json()
    assert second["balance"] - first["balance"] == 5000

    # Keep alice exercised as an authenticated non-admin control identity.
    assert client.get("/users", headers=alice).status_code == 200
