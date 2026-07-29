"""Opaque secret-provider interfaces.

Only the provider sees resolved bytes. Domain models, persistence, plans,
artifacts, prompts, and audit events store the credential reference alone.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol


class SecretNotAvailable(LookupError):
    pass


class SecretProvider(Protocol):
    def resolve(self, credential_ref: str) -> bytes: ...


class EnvironmentSecretProvider:
    def __init__(self, environ: Mapping[str, str]) -> None:
        self._environ = environ

    def resolve(self, credential_ref: str) -> bytes:
        prefix, separator, name = credential_ref.partition(":")
        if separator != ":" or prefix != "env" or not name:
            raise SecretNotAvailable("environment provider only accepts env: references")
        value = self._environ.get(name)
        if value is None:
            raise SecretNotAvailable(f"environment secret is unavailable: {name}")
        return value.encode("utf-8")


class KeychainSecretProvider(Protocol):
    """Reserved port for a future OS Keychain adapter."""

    def resolve(self, credential_ref: str) -> bytes: ...
