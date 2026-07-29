"""Canonical URL and DNS policy for the M9 read-only HTTP broker."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import posixpath
import socket
from typing import Protocol
from urllib.parse import quote, unquote, urljoin, urlsplit

from argus.verification.models import EnvironmentProfile, ScopeRule


class HttpPolicyDenied(PermissionError):
    pass


class Resolver(Protocol):
    def resolve(self, host: str, port: int) -> list[str]: ...


class SystemResolver:
    def resolve(self, host: str, port: int) -> list[str]:
        return sorted(
            {
                address
                for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                if isinstance((address := item[4][0]), str)
            }
        )


@dataclass(frozen=True)
class ApprovedTarget:
    url: str
    host: str
    port: int
    pinned_ip: str


def render_resource_path(template: str, values: dict[str, str]) -> str:
    result = template
    for key, value in values.items():
        if not value or any(character in value for character in "\r\n\x00"):
            raise HttpPolicyDenied(f"invalid test data value: {key}")
        result = result.replace("{" + key + "}", quote(value, safe=""))
    if "{" in result or "}" in result:
        raise HttpPolicyDenied("resource path contains unresolved test-data placeholders")
    return result


class HttpRequestPolicy:
    def __init__(self, resolver: Resolver | None = None) -> None:
        self.resolver = resolver or SystemResolver()

    def approve(
        self,
        environment: EnvironmentProfile,
        resource_path: str,
        *,
        previous_url: str | None = None,
    ) -> ApprovedTarget:
        if not environment.test_only or not environment.enabled:
            raise HttpPolicyDenied("M9 requires an enabled test-only environment")
        if environment.target_base_url is None:
            raise HttpPolicyDenied("environment has no HTTP base URL")
        if any(character in resource_path for character in "\\\r\n\x00"):
            raise HttpPolicyDenied("resource path contains a forbidden character")
        is_absolute_redirect = previous_url is not None and resource_path.startswith(("http://", "https://"))
        if resource_path.startswith("//") or ("://" in resource_path and not is_absolute_redirect):
            raise HttpPolicyDenied("absolute and scheme-relative targets are forbidden")
        decoded = resource_path
        for _ in range(3):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        if "\\" in decoded or decoded.startswith("//"):
            raise HttpPolicyDenied("encoded URL delimiters are forbidden")
        decoded_path = urlsplit(decoded).path
        if any(part in {".", ".."} for part in decoded_path.split("/")):
            raise HttpPolicyDenied("dot path segments are forbidden")

        url = (
            resource_path
            if is_absolute_redirect
            else urljoin(environment.target_base_url.rstrip("/") + "/", resource_path.lstrip("/"))
        )
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise HttpPolicyDenied("target URL is not a canonical HTTP(S) URL")
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        normalized_path = posixpath.normpath(unquote(parsed.path))
        if parsed.path.endswith("/") and not normalized_path.endswith("/"):
            normalized_path += "/"
        rule = next(
            (
                item
                for item in environment.scope_allowlist
                if self._matches(item, parsed.scheme, host, port, normalized_path)
            ),
            None,
        )
        if rule is None:
            raise HttpPolicyDenied("target URL is outside the explicit scope allowlist")
        if previous_url is not None and self._origin(previous_url) != self._origin(url):
            raise HttpPolicyDenied("cross-origin redirects are forbidden")

        addresses = self.resolver.resolve(host, port)
        if not addresses:
            raise HttpPolicyDenied("target hostname did not resolve")
        approved: list[str] = []
        for raw_address in addresses:
            address = ipaddress.ip_address(raw_address)
            if address.is_unspecified or address.is_multicast or address.is_link_local or address.is_reserved:
                raise HttpPolicyDenied(f"resolved address is forbidden: {address}")
            if (address.is_private or address.is_loopback) and not environment.allow_private_addresses:
                raise HttpPolicyDenied("private or loopback address requires explicit test-only opt-in")
            approved.append(address.compressed)
        return ApprovedTarget(url=url, host=host, port=port, pinned_ip=sorted(approved)[0])

    @staticmethod
    def _matches(rule: ScopeRule, scheme: str, host: str, port: int, path: str) -> bool:
        rule_port = rule.port or (443 if rule.scheme == "https" else 80)
        prefix = rule.path_prefix
        boundary = prefix.endswith("/") or path == prefix or path.startswith(prefix + "/")
        return (
            rule.scheme == scheme
            and rule.host.encode("idna").decode("ascii") == host
            and rule_port == port
            and path.startswith(prefix)
            and boundary
        )

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        parsed = urlsplit(url)
        assert parsed.hostname is not None
        return (
            parsed.scheme,
            parsed.hostname.lower().rstrip("."),
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
