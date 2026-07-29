from __future__ import annotations

from dataclasses import dataclass
import pytest

from argus.verification.http_policy import (
    HttpPolicyDenied,
    HttpRequestPolicy,
    render_resource_path,
)
from argus.verification.executors.http_readonly import ReadonlyHttpExecutor
from argus.verification.models import (
    EnvironmentKind,
    EnvironmentProfile,
    ScopeRule,
)


@dataclass
class FakeResolver:
    addresses: list[str]
    calls: int = 0

    def resolve(self, host: str, port: int) -> list[str]:
        self.calls += 1
        return self.addresses


def _environment(*, private: bool = False) -> EnvironmentProfile:
    from uuid import uuid4

    return EnvironmentProfile(
        project_id=uuid4(),
        kind=EnvironmentKind.EXISTING_URL,
        target_base_url="https://test.example.invalid",
        scope_allowlist=[
            ScopeRule(
                scheme="https",
                host="test.example.invalid",
                port=443,
                path_prefix="/api/",
            )
        ],
        test_only=True,
        allow_private_addresses=private,
    )


@pytest.mark.parametrize(
    "path",
    [
        "//evil.example/api/orders/1",
        "https://evil.example/api/orders/1",
        "/api/../admin",
        "/api/%2e%2e/admin",
        "/api/%252e%252e/admin",
        "/api/%5c%5cevil.example/x",
        "/apix/orders/1",
    ],
)
def test_url_bypass_inputs_are_denied_before_dns(path: str) -> None:
    resolver = FakeResolver(["203.0.113.10"])
    with pytest.raises(HttpPolicyDenied):
        HttpRequestPolicy(resolver).approve(_environment(), path)
    assert resolver.calls == 0


def test_dns_private_address_requires_explicit_test_only_opt_in() -> None:
    resolver = FakeResolver(["127.0.0.1"])
    with pytest.raises(HttpPolicyDenied, match="private or loopback"):
        HttpRequestPolicy(resolver).approve(_environment(), "/api/orders/1")

    target = HttpRequestPolicy(resolver).approve(
        _environment(private=True),
        "/api/orders/1",
    )
    assert target.pinned_ip == "127.0.0.1"


def test_dns_link_local_is_always_denied() -> None:
    with pytest.raises(HttpPolicyDenied, match="forbidden"):
        HttpRequestPolicy(FakeResolver(["169.254.169.254"])).approve(
            _environment(private=True),
            "/api/orders/1",
        )


def test_test_data_is_encoded_as_one_path_segment() -> None:
    assert (
        render_resource_path("/api/orders/{resource_id}", {"resource_id": "../admin?token=x"})
        == "/api/orders/..%2Fadmin%3Ftoken%3Dx"
    )


def test_redirect_is_revalidated_and_must_keep_the_approved_origin() -> None:
    resolver = FakeResolver(["8.8.8.8"])
    policy = HttpRequestPolicy(resolver)
    target = policy.approve(
        _environment(),
        "https://test.example.invalid/api/orders/2",
        previous_url="https://test.example.invalid/api/orders/1",
    )
    assert target.pinned_ip == "8.8.8.8"

    with pytest.raises(HttpPolicyDenied):
        policy.approve(
            _environment(),
            "https://evil.example/api/orders/2",
            previous_url="https://test.example.invalid/api/orders/1",
        )


def test_transport_rejects_write_method_before_opening_a_connection() -> None:
    with pytest.raises(PermissionError, match="non-safe method"):
        ReadonlyHttpExecutor().request(
            method="POST",
            url="https://test.example.invalid/api/orders/1",
            host="test.example.invalid",
            pinned_ip="127.0.0.1",
            headers=(),
            timeout_seconds=1,
            max_bytes=10,
        )
