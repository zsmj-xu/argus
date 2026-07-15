from argus.config import apply_overrides, load_config


def test_apply_dotted_override():
    cfg = {"auth": {"roles": "x"}}
    apply_overrides(cfg, ["auth.roles=./roles.yaml", "focus=src/orders/"])
    assert cfg["auth"]["roles"] == "./roles.yaml"
    assert cfg["focus"] == "src/orders/"


def test_load_config_missing_file_returns_defaults(tmp_path):
    cfg = load_config(None, [])
    assert cfg["analyzers"]["vuln"]  # 有默认启用的分析器
