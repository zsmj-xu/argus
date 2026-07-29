"""Canonical codecs supported by the Artifact Store."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, JsonValue

from argus.domain.hashing import canonical_json_bytes


def encode_json(value: JsonValue | BaseModel) -> bytes:
    return canonical_json_bytes(value)


def encode_jsonl(records: Iterable[JsonValue | BaseModel]) -> bytes:
    lines = [canonical_json_bytes(record) for record in records]
    return b"".join(line + b"\n" for line in lines)


def encode_text(value: str) -> bytes:
    return value.encode("utf-8")
