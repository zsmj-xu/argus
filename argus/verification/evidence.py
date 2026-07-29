"""Redaction and immutable evidence artifact helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Iterable

from pydantic import JsonValue

_SENSITIVE = ("authorization", "cookie", "csrf", "token", "api-key", "apikey")


def redact_headers(headers: Iterable[tuple[str, str]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for name, value in headers:
        if any(term in name.lower() for term in _SENSITIVE):
            digest = hashlib.sha256(value.encode()).hexdigest()[:16]
            result[name.lower()] = f"[REDACTED:sha256:{digest}]"
        else:
            result[name.lower()] = value[:1024]
    return result


def bounded_excerpt(body: bytes, *, limit: int = 2048) -> str:
    text = body[:limit].decode("utf-8", errors="replace")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return text

    def redact(item: object) -> object:
        if isinstance(item, dict):
            return {
                str(key): ("[REDACTED]" if any(term in str(key).lower() for term in _SENSITIVE) else redact(child))
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [redact(child) for child in item[:50]]
        return item

    return json.dumps(redact(value), sort_keys=True, ensure_ascii=False)
