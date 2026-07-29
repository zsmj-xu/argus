import pytest

from argus.config import apply_overrides, load_config, validate_config


def test_apply_dotted_override():
    cfg = {"auth": {"roles": "x"}}
    apply_overrides(cfg, ["auth.roles=./roles.yaml", "focus=src/orders/"])
    assert cfg["auth"]["roles"] == "./roles.yaml"
    assert cfg["focus"] == "src/orders/"


def test_load_config_missing_file_returns_defaults(tmp_path):
    cfg = load_config(None, [])
    assert cfg["analyzers"]["vuln"]  # 有默认启用的分析器
    assert cfg["llm"]["auditLevel"] == "redacted"


@pytest.mark.parametrize(
    "config",
    [
        {"source_mode": "typo"},
        {"source": {"mode": "typo"}},
        {"analysisMode": "best-effort"},
        {"llm": {"auditLevel": "everything"}},
        {"verification": {"enabled": "yes"}},
        {"plugins": {"allowExternal": "yes"}},
        {"analysMode": "v2"},
        {"llm": {"auditLevl": "redacted"}},
        {"analyzers": {"vuln": ["authz"], "typo": True}},
    ],
)
def test_core_config_fails_closed(config):
    with pytest.raises(ValueError, match="invalid Argus config"):
        validate_config(config)


def test_v2_source_mode_is_normalized_to_legacy_projection():
    config = validate_config(
        {
            "schemaVersion": "2",
            "source": {"mode": "stripped", "ignore": ["dist/"]},
            "engine": {"type": "local"},
        }
    )

    assert config["source_mode"] == "stripped"
    assert config["source"]["mode"] == "stripped"


def test_known_legacy_extensions_remain_typed_and_custom_values_are_explicit():
    config = validate_config(
        {
            "strict_outputs": True,
            "avoid": "generated/",
            "business-flow": {"batch_size": 8},
            "extensions": {"vendor.option": {"enabled": True}},
        }
    )

    assert config["strict_outputs"] is True
    assert config["avoid"] == "generated/"
    assert config["business-flow"]["batch_size"] == 8
    assert config["extensions"]["vendor.option"] == {"enabled": True}
