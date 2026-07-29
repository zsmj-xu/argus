"""Fail-safe redaction for persisted events and error summaries."""

from __future__ import annotations

import hashlib
import re
from typing import cast

from pydantic import JsonValue

_SENSITIVE_KEY = re.compile(
    r"(api.?key|authorization|cookie|credential|csrf|password|private.?key|prompt|secret|token)",
    re.IGNORECASE,
)


def _marker(value: object) -> str:
    digest = hashlib.sha256(str(value).encode()).hexdigest()[:16]
    return f"[REDACTED:sha256:{digest}]"


def redact_json(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return {
            str(key): (_marker(child) if _SENSITIVE_KEY.search(str(key)) else redact_json(child))
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [redact_json(child) for child in value]
    return value


def redact_payload(payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], redact_json(payload))


def safe_error_summary(exc: BaseException) -> str:
    return f"{type(exc).__name__}: operation failed; inspect redacted audit metadata"
