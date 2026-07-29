"""配置解析 —— 默认配置 + YAML 深合并 + 命令行 `--set` 点路径覆盖。

编排层据此决定跑哪些分析器、开哪些 checkpoint、以什么 source_mode 喂源码。
配置最终会进入 AnalysisContext.config,分析器只读消费。
"""

from __future__ import annotations

import copy
from typing import Literal
from typing import Any

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    ValidationError,
    model_validator,
)

from argus.contracts import SourceMode
from argus.llm.audit import AuditLevel

# 默认配置。人可用 YAML 覆盖任意子树,或用命令行 `--set a.b=c` 打点覆盖。
# - analyzers.enrichment:富化器 name 列表(产语义,喂给下游漏洞分析器)。
# - analyzers.vuln:漏洞分析器 name 列表(产 Finding),默认启用 authz。
# - checkpoints:默认全开(True 表示每个阶段都停下等人确认)。
# - source_mode:喂给 LLM 的源码模式,默认 "raw"(不 strip 注释)。
DEFAULT_CONFIG: dict[str, Any] = {
    "analyzers": {
        "enrichment": [],
        "vuln": ["authz"],
    },
    "checkpoints": True,
    "source_mode": SourceMode.RAW.value,
    "llm": {
        "auditLevel": AuditLevel.REDACTED.value,
    },
    "verification": {
        "enabled": False,
        "allow_safe_read": False,
        "allow_reversible_write": False,
    },
}


class _ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class AnalyzerConfig(_ConfigModel):
    enrichment: list[str] = Field(default_factory=list)
    vuln: list[str] = Field(default_factory=lambda: ["authz"])


class VerificationConfig(_ConfigModel):
    enabled: StrictBool = False
    allow_safe_read: StrictBool = False
    allow_reversible_write: StrictBool = False


class SourceConfig(_ConfigModel):
    mode: SourceMode | None = None
    ignore: list[str] = Field(default_factory=list)


class LlmConfig(_ConfigModel):
    audit_level: AuditLevel = Field(
        default=AuditLevel.REDACTED,
        alias="auditLevel",
    )


class EngineConfig(_ConfigModel):
    type: Literal["local"] = "local"


class PluginConfig(_ConfigModel):
    enabled: list[str] = Field(default_factory=list)
    providers: dict[str, str] = Field(default_factory=dict)
    allow_external: StrictBool = Field(default=False, alias="allowExternal")
    external_roots: list[str] = Field(default_factory=list, alias="externalRoots")
    config: dict[str, dict[str, JsonValue]] = Field(default_factory=dict)


class CoreConfig(_ConfigModel):
    schema_version: Literal["2"] | None = Field(default=None, alias="schemaVersion")
    analyzers: AnalyzerConfig = Field(default_factory=AnalyzerConfig)
    checkpoints: StrictBool | list[str] = True
    source_mode: SourceMode | None = None
    source: SourceConfig | None = None
    analysis_mode: Literal["legacy", "v2", "compare"] = Field(
        default="v2",
        alias="analysisMode",
    )
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    llm: LlmConfig = Field(default_factory=LlmConfig)
    engine: EngineConfig | None = None
    plugins: PluginConfig | None = None
    strict_outputs: StrictBool | None = None
    focus: str | list[str] | None = None
    avoid: str | list[str] | None = None
    auth: dict[str, JsonValue] | None = None
    authz: dict[str, JsonValue] | None = None
    injection: dict[str, JsonValue] | None = None
    xss: dict[str, JsonValue] | None = None
    ssrf: dict[str, JsonValue] | None = None
    invariant: dict[str, JsonValue] | None = None
    baseline: dict[str, JsonValue] | None = None
    business_flow: dict[str, JsonValue] | None = Field(
        default=None,
        alias="business-flow",
    )
    business_logic: dict[str, JsonValue] | None = Field(
        default=None,
        alias="business-logic",
    )
    shannon: dict[str, JsonValue] | None = None
    codegraph: dict[str, JsonValue] | None = None
    detection: dict[str, JsonValue] | None = None
    execution: dict[str, JsonValue] | None = None
    extensions: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reconcile_source_mode(self) -> CoreConfig:
        if (
            self.source is not None
            and self.source.mode is not None
            and self.source_mode is not None
            and self.source.mode is not self.source_mode
        ):
            raise ValueError("source.mode and source_mode must match when both are set")
        return self


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    try:
        validated = CoreConfig.model_validate(config)
    except ValidationError as exc:
        raise ValueError(f"invalid Argus config: {exc}") from exc
    result = validated.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    result["source_mode"] = (
        validated.source.mode.value
        if validated.source is not None and validated.source.mode is not None
        else (validated.source_mode.value if validated.source_mode is not None else SourceMode.RAW.value)
    )
    return result


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """把 overlay 深合并进 base(就地修改 base 并返回)。

    两边同 key 且都是 dict 时递归合并;否则 overlay 的值直接覆盖 base。
    """
    for key, overlay_value in overlay.items():
        base_value = base.get(key)
        if isinstance(base_value, dict) and isinstance(overlay_value, dict):
            _deep_merge(base_value, overlay_value)
        else:
            base[key] = overlay_value
    return base


def _coerce_scalar(raw: str) -> Any:
    """把 `--set` 右值字符串转成合适的标量类型。

    走 YAML 标量解析,让 `true`/`42`/`3.14` 得到 bool/int/float,其余保持字符串。
    """
    return yaml.safe_load(raw)


def apply_overrides(cfg: dict[str, Any], overrides: list[str]) -> None:
    """就地把形如 `a.b=c` 的点路径键值对写入 cfg。

    中间层级不存在时自动建 dict。右值走 YAML 标量解析(如 `true` → bool)。
    每个 override 必须含一个 `=`,否则抛 ValueError。
    """
    for override in overrides:
        if "=" not in override:
            raise ValueError(f"invalid override (expected 'a.b=c'): {override!r}")

        dotted_key, _, raw_value = override.partition("=")
        path = dotted_key.split(".")

        cursor = cfg
        for segment in path[:-1]:
            existing = cursor.get(segment)
            if not isinstance(existing, dict):
                existing = {}
                cursor[segment] = existing
            cursor = existing

        cursor[path[-1]] = _coerce_scalar(raw_value)


def load_config(yaml_path: str | None, overrides: list[str]) -> dict[str, Any]:
    """加载合并后的配置:默认配置 → YAML 深合并 → 命令行覆盖。

    yaml_path 为 None 时跳过 YAML(仅默认 + overrides)。YAML 顶层必须是映射,
    否则抛 ValueError。返回的是全新副本,不改动 DEFAULT_CONFIG。
    """
    cfg = copy.deepcopy(DEFAULT_CONFIG)

    if yaml_path is not None:
        with open(yaml_path, encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)
        if loaded is not None:
            if not isinstance(loaded, dict):
                raise ValueError(f"config YAML must be a mapping at top level: {yaml_path}")
            _deep_merge(cfg, loaded)

    apply_overrides(cfg, overrides)
    return validate_config(cfg)
