from __future__ import annotations

from uuid import uuid4

from argus.domain.enums import FindingStatus, Severity, StaticConfidence
from argus.domain.models import Artifact, CodeLocation, Project, Scan, StaticFindingV2, Task

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def make_project(name: str = "demo") -> Project:
    return Project(name=name, repository_path=f"/tmp/{name}", default_config={"checkpoints": True})


def make_scan(project: Project) -> Scan:
    return Scan(
        project_id=project.id,
        snapshot_id=uuid4(),
        config={"source_mode": "raw"},
        config_hash=SHA_A,
    )


def make_task(scan: Scan, plugin_id: str = "legacy.authz") -> Task:
    return Task(
        scan_id=scan.id,
        plugin_id=plugin_id,
        plugin_version="1.0.0",
        kind="legacy_analyzer",
        required_capabilities=["code.graph.codegraph.v1"],
        expected_capabilities=["legacy.findings.authz.v1"],
        config_hash=SHA_A,
        cache_key=SHA_B,
    )


def make_artifact(scan: Scan, task: Task) -> Artifact:
    return Artifact(
        scan_id=scan.id,
        snapshot_id=scan.snapshot_id,
        task_id=task.id,
        artifact_type="legacy.findings.authz.v1",
        schema_version="1.0",
        capabilities=["legacy.findings.authz.v1"],
        producer_plugin_id=task.plugin_id,
        producer_plugin_version=task.plugin_version,
        media_type="application/json",
        content_hash=SHA_C,
        size_bytes=42,
        storage_uri="runs/_data/artifacts/sha256/cc/payload",
        metadata={"fixture": True},
    )


def make_finding(scan: Scan, *, title: str = "IDOR") -> StaticFindingV2:
    return StaticFindingV2(
        fingerprint=SHA_B,
        scan_id=scan.id,
        snapshot_id=scan.snapshot_id,
        rule_id="authorization.idor",
        rule_version="1.0.0",
        title=title,
        weakness_id="CWE-639",
        vuln_class="authorization",
        severity=Severity.HIGH,
        static_confidence=StaticConfidence.HIGH,
        status=FindingStatus.UNVERIFIED,
        locations=[CodeLocation(file="src/orders.py", line=10, node_id="function:get_order")],
        source_node_ids=["route:get-order"],
        sink_node_ids=["function:get_order"],
        rationale="Ownership is not checked.",
        remediation="Check resource ownership.",
    )
