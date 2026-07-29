"""Deterministic hashing helpers for V2 domain objects."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import TypeAlias
from uuid import UUID

from pydantic import BaseModel, JsonValue

CanonicalValue: TypeAlias = JsonValue | UUID | Enum | BaseModel


def _canonicalize(value: CanonicalValue) -> JsonValue:
    if isinstance(value, BaseModel):
        return _canonicalize(value.model_dump(mode="json", exclude_none=False))
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return _canonicalize(value.value)
    if isinstance(value, Mapping):
        return {str(key): _canonicalize(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_canonicalize(item) for item in value]
    return value


def canonical_json_bytes(value: CanonicalValue) -> bytes:
    """Serialize a JSON-compatible value with stable keys and separators."""
    return json.dumps(
        _canonicalize(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_digest(value: CanonicalValue) -> str:
    """Return a lowercase SHA-256 digest for the canonical representation."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
