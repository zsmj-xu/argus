from __future__ import annotations

import ast
from pathlib import Path

import pytest

from argus.control.db import control_db_path
from argus.verification.secrets import EnvironmentSecretProvider, SecretNotAvailable

from .helpers import seed_verification


def test_environment_secret_provider_resolves_only_env_references() -> None:
    provider = EnvironmentSecretProvider({"OWNER_TOKEN": "secret-value"})

    assert provider.resolve("env:OWNER_TOKEN") == b"secret-value"
    with pytest.raises(SecretNotAvailable):
        provider.resolve("keychain:owner")
    with pytest.raises(SecretNotAvailable):
        provider.resolve("env:MISSING")


def test_plaintext_secret_is_not_persisted(tmp_path: Path) -> None:
    plaintext = "actual-owner-secret"
    provider = EnvironmentSecretProvider({"ARGUS_TEST_OWNER_TOKEN": plaintext})
    assert provider.resolve("env:ARGUS_TEST_OWNER_TOKEN") == plaintext.encode()
    database, _repositories, *_rest = seed_verification(tmp_path)
    database.close()

    raw_database = control_db_path(tmp_path / "runs").read_bytes()
    assert plaintext.encode() not in raw_database
    assert b"ARGUS_TEST_OWNER_TOKEN" in raw_database


def test_m8_planning_modules_remain_offline_after_m9() -> None:
    root = Path(__file__).parents[2] / "argus" / "verification"
    forbidden_roots = {
        "http.client",
        "httpx",
        "playwright",
        "requests",
        "socket",
        "subprocess",
        "urllib.request",
    }
    imported: set[str] = set()
    for name in (
        "approvals.py",
        "models.py",
        "persistence.py",
        "planning.py",
        "policy.py",
        "requirements.py",
        "secrets.py",
    ):
        path = root / name
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)

    assert imported.isdisjoint(forbidden_roots)
    assert (root / "broker.py").exists()
    assert (root / "executors" / "http_readonly.py").exists()
