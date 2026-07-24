"""Comparison configurations stay aligned across runnable targets."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from argus.config import load_config

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = ROOT / "docs" / "comparisons" / "configs"
FIVE_CLASSES = ["injection", "xss", "auth", "authz", "ssrf"]


@pytest.mark.parametrize(
    "filename",
    [
        "argus-vampi-5class.yaml",
        "argus-flowmart-5class.yaml",
        "argus-crapi-workshop-5class.yaml",
        "argus-crapi-community-5class.yaml",
    ],
)
def test_argus_configs_use_the_fair_five_class_arm(filename: str) -> None:
    config = load_config(str(CONFIGS / filename), [])

    assert config["analyzers"] == {"enrichment": [], "vuln": FIVE_CLASSES}
    assert config["source_mode"] == "stripped"
    assert config["checkpoints"] is False
    assert config["strict_outputs"] is True


def test_flowmart_shannon_config_is_discovery_only_and_serial() -> None:
    with (CONFIGS / "shannon-flowmart.yaml").open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    assert config["vuln_classes"] == FIVE_CLASSES
    assert config["exploit"] == "false"
    assert config["authentication"]["login_url"].endswith(":5012/users/login")
    assert config["pipeline"]["max_concurrent_pipelines"] == 1


def test_crapi_shannon_config_is_discovery_only_and_serial() -> None:
    with (CONFIGS / "shannon-crapi.yaml").open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    assert config["vuln_classes"] == FIVE_CLASSES
    assert config["exploit"] == "false"
    assert config["authentication"]["login_url"].endswith(":8888/identity/api/auth/login")
    assert config["pipeline"]["max_concurrent_pipelines"] == 1
