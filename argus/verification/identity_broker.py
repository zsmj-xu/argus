"""Resolve opaque identity handles into request material inside the broker boundary."""

from __future__ import annotations

from dataclasses import dataclass
import re

from argus.verification.models import IdentityProfile
from argus.verification.secrets import SecretProvider

_HEADER = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class IdentityBrokerError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class BoundIdentity:
    headers: tuple[tuple[str, str], ...]

    def __repr__(self) -> str:
        return "BoundIdentity(headers=<redacted>)"


class IdentityBroker:
    def __init__(self, secret_provider: SecretProvider) -> None:
        self.secret_provider = secret_provider

    def bind(self, identity: IdentityProfile) -> BoundIdentity:
        if not identity.enabled:
            raise IdentityBrokerError("identity is disabled")
        try:
            secret = self.secret_provider.resolve(identity.credential_ref).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IdentityBrokerError("identity secret must be UTF-8") from exc
        if not secret or any(character in secret for character in "\r\n"):
            raise IdentityBrokerError("identity secret is invalid")
        kind = identity.attributes.get("auth_scheme", "bearer")
        if kind == "bearer":
            return BoundIdentity((("Authorization", f"Bearer {secret}"),))
        if kind == "header":
            name = identity.attributes.get("header_name")
            if not isinstance(name, str) or _HEADER.fullmatch(name) is None:
                raise IdentityBrokerError("header identity requires a safe header_name")
            return BoundIdentity(((name, secret),))
        if kind == "cookie":
            name = identity.attributes.get("cookie_name")
            if not isinstance(name, str) or _HEADER.fullmatch(name) is None:
                raise IdentityBrokerError("cookie identity requires a safe cookie_name")
            return BoundIdentity((("Cookie", f"{name}={secret}"),))
        raise IdentityBrokerError("unsupported identity auth_scheme")
