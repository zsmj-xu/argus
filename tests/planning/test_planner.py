from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from argus.domain.enums import PluginKind
from argus.planning.planner import PlanningRequest, TaskOrdering, TaskPlanner
from argus.planning.validation import (
    AmbiguousCapabilityError,
    CircularDependencyError,
    InvalidProviderError,
    MissingCapabilityError,
    UnknownPluginError,
)
from argus.plugins.contracts import (
    CapabilityDeclaration,
    CapabilityRequirement,
    PluginSpec,
)
from argus.plugins.registry import PluginOrigin, PluginRegistry


def _plugin(
    plugin_id: str,
    *,
    consumes: tuple[str, ...] = (),
    produces: tuple[str, ...] = (),
) -> PluginSpec:
    return PluginSpec(
        id=plugin_id,
        version="1.0.0",
        kind=PluginKind.DETECTOR,
        entrypoint="tests.planning.test_planner:noop",
        consumes=[CapabilityRequirement(capability=item) for item in consumes],
        produces=[
            CapabilityDeclaration(
                capability=item,
                artifact_type=item.removesuffix(".v1"),
                schema_version="1.0",
            )
            for item in produces
        ],
    )


def _registry(*plugins: PluginSpec) -> PluginRegistry:
    registry = PluginRegistry()
    for plugin in plugins:
        registry.register(plugin, origin=PluginOrigin.BUILTIN)
    return registry


def noop() -> None:
    pass


def test_dependency_closure_and_topological_order_are_deterministic() -> None:
    registry = _registry(
        _plugin("provider.graph", consumes=("source.snapshot.v1",), produces=("code.graph.v1",)),
        _plugin("detector.beta", consumes=("code.graph.v1",), produces=("candidate.beta.v1",)),
        _plugin("detector.alpha", consumes=("code.graph.v1",), produces=("candidate.alpha.v1",)),
        _plugin(
            "aggregate.results",
            consumes=("candidate.alpha.v1", "candidate.beta.v1"),
            produces=("finding.aggregate.v1",),
        ),
    )
    scan_id = uuid4()
    request = PlanningRequest(
        scan_id=scan_id,
        selected_plugin_ids=["aggregate.results"],
        initial_capabilities={"source.snapshot.v1"},
    )

    first = TaskPlanner(registry).compile(request)
    second = TaskPlanner(registry).compile(request)

    assert [task.plugin_id for task in first.tasks] == [
        "provider.graph",
        "detector.alpha",
        "detector.beta",
        "aggregate.results",
    ]
    assert first.id == second.id
    assert first.plan_hash == second.plan_hash
    assert [task.model_dump(exclude={"id"}) for task in first.tasks] == [
        task.model_dump(exclude={"id"}) for task in second.tasks
    ]


def test_unknown_plugin_and_missing_capability_are_actionable() -> None:
    scan_id = uuid4()
    with pytest.raises(UnknownPluginError, match="missing"):
        TaskPlanner(_registry()).compile(PlanningRequest(scan_id=scan_id, selected_plugin_ids=["missing"]))
    with pytest.raises(MissingCapabilityError, match="code.graph.v1"):
        TaskPlanner(_registry(_plugin("detector.one", consumes=("code.graph.v1",)))).compile(
            PlanningRequest(scan_id=scan_id, selected_plugin_ids=["detector.one"])
        )


def test_ambiguous_producer_requires_explicit_valid_choice() -> None:
    registry = _registry(
        _plugin("provider.one", produces=("code.graph.v1",)),
        _plugin("provider.two", produces=("code.graph.v1",)),
        _plugin("detector.one", consumes=("code.graph.v1",)),
    )
    request = PlanningRequest(
        scan_id=uuid4(),
        selected_plugin_ids=["detector.one"],
    )
    with pytest.raises(AmbiguousCapabilityError, match="explicit provider"):
        TaskPlanner(registry).compile(request)
    with pytest.raises(InvalidProviderError, match="does not produce"):
        TaskPlanner(registry).compile(
            request.model_copy(update={"provider_choices": {"code.graph.v1": "detector.one"}})
        )

    plan = TaskPlanner(registry).compile(
        request.model_copy(update={"provider_choices": {"code.graph.v1": "provider.two"}})
    )
    assert [task.plugin_id for task in plan.tasks] == [
        "provider.two",
        "detector.one",
    ]


def test_cycle_reports_readable_plugin_path() -> None:
    registry = _registry(
        _plugin("plugin.one", consumes=("cap.two.v1",), produces=("cap.one.v1",)),
        _plugin("plugin.two", consumes=("cap.one.v1",), produces=("cap.two.v1",)),
    )

    with pytest.raises(CircularDependencyError, match=r"plugin\.one -> plugin\.two -> plugin\.one"):
        TaskPlanner(registry).compile(PlanningRequest(scan_id=uuid4(), selected_plugin_ids=["plugin.one"]))


def test_explicit_ordering_constraint_preserves_adapter_semantics() -> None:
    registry = _registry(
        _plugin("plugin.alpha"),
        _plugin("plugin.zeta"),
    )

    plan = TaskPlanner(registry).compile(
        PlanningRequest(
            scan_id=uuid4(),
            selected_plugin_ids=["plugin.alpha", "plugin.zeta"],
            ordering_constraints=[
                TaskOrdering(
                    before_plugin_id="plugin.zeta",
                    after_plugin_id="plugin.alpha",
                )
            ],
        )
    )

    assert [task.plugin_id for task in plan.tasks] == [
        "plugin.zeta",
        "plugin.alpha",
    ]


def test_generic_planner_contains_no_builtin_vulnerability_names() -> None:
    source = (Path(__file__).parents[2] / "argus" / "planning" / "planner.py").read_text(encoding="utf-8")

    assert all(name not in source.lower() for name in ("injection", "authz", "business-flow"))
