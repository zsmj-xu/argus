"""flowmart 数据模型(纯内存,静态分析靶场无需真起 DB)。

业务实体之间的所有权链是跨 handler 漏洞的基础:
    User --owns--> Wallet
    User(seller) --owns--> Listing
    Order --refers--> Listing(卖家) + buyer(User)
    Coupon --issued_to--> User(签发时绑定)
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class User:
    id: int
    username: str
    password: str
    # 权限字段:服务端应自行决定,不得由注册请求体设置(trust_boundary)
    role: str = "user"  # "user" | "admin"


@dataclass
class Wallet:
    user_id: int
    balance: int = 0  # 以分为单位


@dataclass
class Listing:
    id: int
    seller_id: int          # 该商品归属的卖家(所有权链的根)
    title: str
    price: int
    status: str = "active"  # "active" | "sold"


@dataclass
class Order:
    id: int
    listing_id: int
    buyer_id: int
    amount: int
    # 订单状态机:created -> paid -> shipped -> (return_requested -> refunded)
    # 这个状态机跨多个 handler 流转,是"重放/幂等"类漏洞的判定依据。
    status: str = "created"


@dataclass
class Coupon:
    code: str
    issued_to: int          # 签发时绑定的用户 id(归属)——跨 handler 判定的关键
    amount: int
    redeemed: bool = False   # 是否已被兑换(replay 判定)


class DB:
    """极简内存存储。种子数据里 alice/bob 是普通用户,carol 是 admin。"""

    def __init__(self):
        self.users: dict[int, User] = {}
        self.wallets: dict[int, Wallet] = {}
        self.listings: dict[int, Listing] = {}
        self.orders: dict[int, Order] = {}
        self.coupons: dict[str, Coupon] = {}
        self._seed()

    def _seed(self):
        self.users[1] = User(1, "alice", "alice-pw", role="user")
        self.users[2] = User(2, "bob", "bob-pw", role="user")
        self.users[3] = User(3, "carol", "carol-pw", role="admin")
        for uid in (1, 2, 3):
            self.wallets[uid] = Wallet(uid, balance=10_000)
        # alice 挂了一个商品
        self.listings[1] = Listing(1, seller_id=1, title="二手相机", price=5_000)
        # 签发给 alice 的优惠券
        self.coupons["WELCOME50"] = Coupon("WELCOME50", issued_to=1, amount=5_000)

    def user_by_name(self, username: str) -> User | None:
        for u in self.users.values():
            if u.username == username:
                return u
        return None

    def next_id(self, table: dict) -> int:
        return (max(table.keys()) + 1) if table else 1


db = DB()
