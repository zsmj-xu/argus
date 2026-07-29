"""Persistent, safely serialized application service for the M7 console."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import re
from typing import Any, TypeVar, cast
from urllib.parse import urlencode
from uuid import UUID

from pydantic import JsonValue, TypeAdapter, ValidationError

from argus.artifacts.store import ArtifactStore
from argus.control.db import Database, control_db_path, upgrade_database
from argus.control.events import EventService
from argus.control.repositories import Repositories
from argus.control.services import ControlServices
from argus.domain.enums import (
    FindingStatus,
    ReviewStatus,
    ReviewSubjectType,
    ScanStatus,
    Severity,
    StaticConfidence,
    TaskStatus,
)
from argus.domain.errors import NotFoundError
from argus.domain.hashing import sha256_digest
from argus.domain.models import (
    Artifact,
    Event,
    Project,
    ReviewRequest,
    Scan,
    StaticFindingV2,
    TaskAttempt,
    utc_now,
)
from argus.execution.local import LocalPlanExecutor
from argus.security_ir.models import GraphSlice
from argus.verification.approvals import ApprovalService
from argus.verification.broker import VerificationBroker, VerificationExecutionDenied
from argus.verification.models import (
    AbortCondition,
    ApprovalDecision,
    EnvironmentProfile,
    ExpectedObservation,
    ExpectedSideEffect,
    IdentityProfile,
    RequestBudget,
    RiskClass,
    RollbackStrategy,
    VerificationAction,
)
from argus.verification.planning import PlanDraft, VerificationPlanCompiler
from argus.verification.policy import VerificationPolicyConfig
from argus.verification.requirements import RequirementResolver, VerifierDeclaration
from argus.verification.secrets import EnvironmentSecretProvider

_JSON_OBJECT = TypeAdapter(dict[str, JsonValue])
_PROJECT_NAME = re.compile(r"^[^\x00-\x1f/\\]{1,255}$")
_SENSITIVE_KEYS = {
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "password",
    "privatekey",
    "refreshtoken",
    "secret",
    "secrets",
    "token",
    "accesstoken",
}
_SENSITIVE_OUTPUT_KEYS = _SENSITIVE_KEYS | {
    "messages",
    "prompt",
    "systemprompt",
    "userprompt",
}
_PREVIEW_BYTES = 64 * 1024
_GRAPH_SLICE_MAX_BYTES = 5 * 1024 * 1024
_GRAPH_SLICE_MAX_NODES = 500
_DENIED_PREVIEW_TERMS = (
    "audit",
    "credential",
    "prompt",
    "secret",
)
_TEXT_MEDIA_TYPES = {
    "application/json",
    "application/yaml",
    "text/markdown",
    "text/plain",
}
_MUTABLE_FINDING_FIELDS = {
    "preconditions",
    "rationale",
    "remediation",
    "severity",
    "static_confidence",
    "status",
    "title",
}
T = TypeVar("T")


class ControlPlaneInputError(ValueError):
    """A caller supplied an unsafe or invalid control-plane value."""


class ArtifactAccessDenied(PermissionError):
    """A sensitive audit/prompt Artifact is not exposed through the API."""


@dataclass(frozen=True)
class ArtifactContent:
    artifact: Artifact
    path: Path


def _normalized_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def safe_json(value: object) -> JsonValue:
    """Return JSON data with credential-shaped keys recursively redacted."""
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            name = str(key)
            result[name] = "[REDACTED]" if _normalized_key(name) in _SENSITIVE_OUTPUT_KEYS else safe_json(item)
        return result
    if isinstance(value, (list, tuple)):
        return [safe_json(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "value"):
        return safe_json(getattr(value, "value"))
    return str(value)


def _model(value: Any) -> dict[str, JsonValue]:
    return cast(
        dict[str, JsonValue],
        safe_json(value.model_dump(mode="json")),
    )


def _uuid(value: object, field: str) -> UUID:
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str):
        raise ControlPlaneInputError(f"{field} must be a UUID")
    try:
        return UUID(value)
    except ValueError as exc:
        raise ControlPlaneInputError(f"{field} must be a UUID") from exc


def _non_empty(value: object, field: str, *, maximum: int = 10_000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ControlPlaneInputError(f"{field} must be a non-empty string of at most {maximum} characters")
    return value.strip()


def _repository_path(value: object) -> str:
    raw = _non_empty(value, "repository_path", maximum=4096)
    if not os.path.isabs(raw):
        raise ControlPlaneInputError("repository_path must be absolute")
    resolved = os.path.realpath(raw)
    if not os.path.isdir(resolved):
        raise ControlPlaneInputError("repository_path must be an existing directory")
    return resolved


def _config(value: object) -> dict[str, JsonValue]:
    if value is None:
        return {}
    try:
        config = _JSON_OBJECT.validate_python(value)
    except ValidationError as exc:
        raise ControlPlaneInputError("config must be a JSON object") from exc
    sensitive = _sensitive_paths(config)
    if sensitive:
        raise ControlPlaneInputError(f"config must not contain credentials: {sorted(sensitive)}")
    return config


def _uuid_list(value: object, field: str) -> list[UUID]:
    if not isinstance(value, list) or not value or len(value) > 100:
        raise ControlPlaneInputError(f"{field} must contain between 1 and 100 UUIDs")
    parsed = [_uuid(item, field) for item in value]
    if len(parsed) != len(set(parsed)):
        raise ControlPlaneInputError(f"{field} must not contain duplicates")
    return parsed


def _object_list(
    value: object,
    field: str,
    *,
    allow_empty: bool = False,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or (not value and not allow_empty) or len(value) > 100:
        qualifier = "up to 100" if allow_empty else "between 1 and 100"
        raise ControlPlaneInputError(f"{field} must contain {qualifier} objects")
    if any(not isinstance(item, dict) for item in value):
        raise ControlPlaneInputError(f"{field} must contain objects")
    return cast(list[dict[str, Any]], value)


def _string_list(value: object, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 100
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ControlPlaneInputError(f"{field} must be a unique list of at most 100 non-empty strings")
    return cast(list[str], value)


def _verification_policy_config(
    scan_config: dict[str, JsonValue],
    project_config: dict[str, JsonValue],
) -> VerificationPolicyConfig:
    merged: dict[str, JsonValue] = {
        "enabled": False,
        "allow_safe_read": False,
        "allow_reversible_write": False,
    }
    for source in (project_config, scan_config):
        raw = source.get("verification")
        if isinstance(raw, dict):
            for key in merged:
                if key in raw:
                    merged[key] = raw[key]
    try:
        return VerificationPolicyConfig.model_validate(merged)
    except ValidationError as exc:
        raise ControlPlaneInputError(f"invalid verification policy config: {exc}") from exc


def _sensitive_paths(
    value: JsonValue,
    *,
    prefix: str = "",
) -> list[str]:
    if isinstance(value, dict):
        paths: list[str] = []
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else key
            if _normalized_key(key) in _SENSITIVE_KEYS:
                paths.append(path)
            else:
                paths.extend(_sensitive_paths(item, prefix=path))
        return paths
    if isinstance(value, list):
        return [
            path for index, item in enumerate(value) for path in _sensitive_paths(item, prefix=f"{prefix}[{index}]")
        ]
    return []


def _duration_seconds(
    started: datetime | None,
    finished: datetime | None,
) -> float | None:
    if started is None:
        return None
    end = finished or utc_now()
    try:
        return max(0.0, (end - started).total_seconds())
    except TypeError:
        return None


class ControlPlaneService:
    """Open the Control Store per operation so Web restarts lose no state."""

    def __init__(self, runs_root: str | Path) -> None:
        self.runs_root = Path(runs_root).resolve()
        self.database_path = control_db_path(self.runs_root)
        self.artifacts = ArtifactStore(self.runs_root)

    @contextmanager
    def _repositories(
        self,
        *,
        create: bool = False,
    ) -> Iterator[Repositories]:
        if create:
            upgrade_database(self.database_path)
        elif not self.database_path.is_file():
            raise NotFoundError("Control Store does not exist")
        database = Database(self.database_path)
        try:
            yield Repositories(database)
        finally:
            database.close()

    def _read(self, operation: Callable[[Repositories], T]) -> T:
        with self._repositories() as repositories:
            return operation(repositories)

    def list_projects(self) -> list[dict[str, JsonValue]]:
        def operation(repositories: Repositories) -> list[dict[str, JsonValue]]:
            scans = repositories.scans.list()
            scan_counts = Counter(scan.project_id for scan in scans)
            return [
                {
                    **_model(project),
                    "scan_count": scan_counts[project.id],
                    "scans": [_scan_projection(repositories, scan) for scan in scans if scan.project_id == project.id],
                    "latest_scan": next(
                        (_model(scan) for scan in reversed(scans) if scan.project_id == project.id),
                        None,
                    ),
                }
                for project in repositories.projects.list()
            ]

        return self._read(operation)

    def create_project(self, payload: dict[str, Any]) -> dict[str, JsonValue]:
        name = _non_empty(payload.get("name"), "name", maximum=255)
        if _PROJECT_NAME.fullmatch(name) is None:
            raise ControlPlaneInputError("name contains path or control characters")
        project = Project(
            name=name,
            repository_path=_repository_path(payload.get("repository_path")),
            default_config=_config(payload.get("default_config")),
        )
        with self._repositories(create=True) as repositories:
            created = repositories.projects.create(project)
            EventService(repositories.events).append(
                "project.created",
                project_id=created.id,
                payload={"name": created.name},
            )
            return self._project_detail(repositories, created)

    def get_project(self, project_id: UUID) -> dict[str, JsonValue]:
        return self._read(
            lambda repositories: self._project_detail(
                repositories,
                repositories.projects.get(project_id),
            )
        )

    def update_project(
        self,
        project_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, JsonValue]:
        allowed = {
            "archived",
            "default_config",
            "name",
            "repository_path",
        }
        unknown = set(payload) - allowed
        if unknown or not payload:
            raise ControlPlaneInputError(f"project patch contains unsupported fields: {sorted(unknown)}")
        with self._repositories() as repositories:
            current = repositories.projects.get(project_id)
            changes: dict[str, object] = {"updated_at": utc_now()}
            if "name" in payload:
                name = _non_empty(payload["name"], "name", maximum=255)
                if _PROJECT_NAME.fullmatch(name) is None:
                    raise ControlPlaneInputError("name contains path or control characters")
                changes["name"] = name
            if "repository_path" in payload:
                changes["repository_path"] = _repository_path(payload["repository_path"])
            if "default_config" in payload:
                changes["default_config"] = _config(payload["default_config"])
            if "archived" in payload:
                if not isinstance(payload["archived"], bool):
                    raise ControlPlaneInputError("archived must be boolean")
                changes["archived_at"] = utc_now() if payload["archived"] else None
            updated = repositories.projects.update(current.model_copy(update=changes))
            EventService(repositories.events).append(
                "project.updated",
                project_id=updated.id,
                payload={"fields": cast(JsonValue, sorted(payload))},
            )
            return self._project_detail(repositories, updated)

    def list_verification_environments(self, project_id: UUID) -> list[dict[str, JsonValue]]:
        return self._read(
            lambda repositories: [
                _model(item) for item in repositories.verification.environments.list(project_id=project_id)
            ]
        )

    def create_verification_environment(
        self,
        project_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, JsonValue]:
        allowed = {
            "capabilities",
            "enabled",
            "health_checks",
            "kind",
            "reset_capability",
            "scope_allowlist",
            "source_snapshot_binding",
            "target_base_url",
            "test_only",
            "allow_private_addresses",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise ControlPlaneInputError(f"verification environment contains unsupported fields: {sorted(unknown)}")
        with self._repositories() as repositories:
            repositories.projects.get(project_id)
            try:
                environment = EnvironmentProfile.model_validate(
                    {
                        **payload,
                        "project_id": project_id,
                    }
                )
            except ValidationError as exc:
                raise ControlPlaneInputError(f"invalid verification environment: {exc}") from exc
            created = repositories.verification.environments.create(environment)
            EventService(repositories.events).append(
                "verification.environment.created",
                project_id=project_id,
                payload={
                    "environment_id": str(created.id),
                    "kind": created.kind.value,
                    "enabled": created.enabled,
                },
            )
            return _model(created)

    def list_verification_identities(self, project_id: UUID) -> list[dict[str, JsonValue]]:
        return self._read(
            lambda repositories: [
                _model(item) for item in repositories.verification.identities.list(project_id=project_id)
            ]
        )

    def create_verification_identity(
        self,
        project_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, JsonValue]:
        allowed = {
            "attributes",
            "credential_ref",
            "enabled",
            "handle",
            "role",
            "tenant",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise ControlPlaneInputError(f"verification identity contains unsupported fields: {sorted(unknown)}")
        attributes = payload.get("attributes", {})
        if not isinstance(attributes, dict):
            raise ControlPlaneInputError("identity attributes must be an object")
        sensitive = _sensitive_paths(cast(dict[str, Any], attributes))
        if sensitive:
            raise ControlPlaneInputError(f"identity attributes cannot contain credentials: {sensitive}")
        with self._repositories() as repositories:
            repositories.projects.get(project_id)
            try:
                identity = IdentityProfile.model_validate(
                    {
                        **payload,
                        "project_id": project_id,
                    }
                )
            except ValidationError as exc:
                raise ControlPlaneInputError(f"invalid verification identity: {exc}") from exc
            created = repositories.verification.identities.create(identity)
            EventService(repositories.events).append(
                "verification.identity.created",
                project_id=project_id,
                payload={
                    "identity_id": str(created.id),
                    "handle": created.handle,
                    "role": created.role,
                    "credential_ref": created.credential_ref,
                },
            )
            return _model(created)

    @staticmethod
    def _project_detail(
        repositories: Repositories,
        project: Project,
    ) -> dict[str, JsonValue]:
        scans = repositories.scans.list(project_id=project.id)
        return {
            **_model(project),
            "scans": [_scan_projection(repositories, scan) for scan in scans],
        }

    def list_scans(self, project_id: UUID) -> list[dict[str, JsonValue]]:
        return self._read(
            lambda repositories: [
                _scan_projection(repositories, scan) for scan in repositories.scans.list(project_id=project_id)
            ]
        )

    def get_scan(self, scan_id: UUID) -> dict[str, JsonValue]:
        return self._read(
            lambda repositories: _scan_detail(
                repositories,
                repositories.scans.get(scan_id),
            )
        )

    def tasks(self, scan_id: UUID) -> list[dict[str, JsonValue]]:
        def operation(repositories: Repositories) -> list[dict[str, JsonValue]]:
            repositories.scans.get(scan_id)
            artifacts = repositories.artifacts.list(scan_id=scan_id)
            outputs: dict[UUID, list[Artifact]] = {}
            for artifact in artifacts:
                outputs.setdefault(artifact.task_id, []).append(artifact)
            attempts = repositories.attempts.list(scan_id=scan_id)
            by_task: dict[UUID, list[TaskAttempt]] = {}
            for attempt in attempts:
                by_task.setdefault(attempt.task_id, []).append(attempt)
            result: list[dict[str, JsonValue]] = []
            for task in repositories.tasks.list(scan_id=scan_id):
                task_attempts = by_task.get(task.id, [])
                latest = task_attempts[-1] if task_attempts else None
                result.append(
                    {
                        **_model(task),
                        "duration_seconds": _duration_seconds(
                            task.started_at,
                            task.finished_at,
                        ),
                        "attempts": [_safe_attempt(item) for item in task_attempts],
                        "input_artifact_ids": (
                            [str(item) for item in latest.input_artifact_ids] if latest is not None else []
                        ),
                        "output_artifacts": [_artifact_projection(item) for item in outputs.get(task.id, [])],
                    }
                )
            return result

        return self._read(operation)

    def plan(self, scan_id: UUID) -> dict[str, JsonValue]:
        def operation(repositories: Repositories) -> dict[str, JsonValue]:
            scan = repositories.scans.get(scan_id)
            if scan.plan_id is None:
                raise NotFoundError(f"scan {scan_id} has no TaskPlan")
            plan = repositories.plans.get(scan.plan_id)
            return {
                **_model(plan),
                "artifact_id": str(repositories.plans.artifact_id(plan.id)),
            }

        return self._read(operation)

    def events(self, scan_id: UUID) -> list[dict[str, JsonValue]]:
        return self._read(
            lambda repositories: [_safe_event(item) for item in repositories.events.list(scan_id=scan_id)]
        )

    def list_artifacts(self, scan_id: UUID) -> list[dict[str, JsonValue]]:
        return self._read(
            lambda repositories: [_artifact_projection(item) for item in repositories.artifacts.list(scan_id=scan_id)]
        )

    def artifact(self, artifact_id: UUID) -> dict[str, JsonValue]:
        def operation(repositories: Repositories) -> dict[str, JsonValue]:
            artifact = repositories.artifacts.get(artifact_id)
            detail = _artifact_projection(artifact)
            preview = self._preview(artifact)
            return {
                **detail,
                "preview": preview,
                "download_url": f"/api/artifacts/{artifact.id}?download=1",
            }

        return self._read(operation)

    def artifact_content(self, artifact_id: UUID) -> ArtifactContent:
        def operation(repositories: Repositories) -> ArtifactContent:
            artifact = repositories.artifacts.get(artifact_id)
            if _sensitive_artifact(artifact):
                raise ArtifactAccessDenied("sensitive audit or prompt Artifact download is disabled")
            path = self.artifacts.verified_path(
                artifact.content_hash,
                expected_size=artifact.size_bytes,
            )
            return ArtifactContent(artifact=artifact, path=path)

        return self._read(operation)

    def graph_slice_artifact(self, artifact_id: UUID) -> dict[str, JsonValue]:
        """Return one Finding-bound, already bounded Graph Slice Artifact."""

        def operation(repositories: Repositories) -> dict[str, JsonValue]:
            artifact = repositories.artifacts.get(artifact_id)
            if artifact.artifact_type != "graph.slice.v1":
                raise ControlPlaneInputError("Artifact is not a graph.slice.v1")
            if artifact.size_bytes > _GRAPH_SLICE_MAX_BYTES:
                raise ControlPlaneInputError("Graph Slice Artifact exceeds the Web size limit")
            path = self.artifacts.verified_path(
                artifact.content_hash,
                expected_size=artifact.size_bytes,
            )
            try:
                graph_slice = GraphSlice.model_validate_json(path.read_bytes())
            except ValidationError as exc:
                raise ControlPlaneInputError("Graph Slice Artifact is invalid") from exc
            if graph_slice.max_nodes > _GRAPH_SLICE_MAX_NODES or len(graph_slice.nodes) > graph_slice.max_nodes:
                raise ControlPlaneInputError("Graph Slice Artifact is not bounded")
            return {
                "artifact_id": str(artifact.id),
                "artifact_type": artifact.artifact_type,
                "graph_slice": safe_json(graph_slice.model_dump(mode="json")),
            }

        return self._read(operation)

    def _preview(self, artifact: Artifact) -> JsonValue:
        if _sensitive_artifact(artifact):
            return {
                "available": False,
                "reason": "sensitive artifact preview is disabled",
            }
        media_type = artifact.media_type.split(";", 1)[0]
        if media_type not in _TEXT_MEDIA_TYPES:
            return {
                "available": False,
                "reason": "binary artifact; use verified download",
            }
        path = self.artifacts.verified_path(
            artifact.content_hash,
            expected_size=artifact.size_bytes,
        )
        payload = path.read_bytes()[: _PREVIEW_BYTES + 1]
        truncated = len(payload) > _PREVIEW_BYTES
        text = payload[:_PREVIEW_BYTES].decode("utf-8", errors="replace")
        if media_type == "application/json":
            try:
                value = safe_json(json.loads(text))
            except json.JSONDecodeError:
                value = text
        else:
            value = text
        return {
            "available": True,
            "truncated": truncated,
            "value": value,
        }

    def list_findings(self, scan_id: UUID) -> list[dict[str, JsonValue]]:
        return self._read(
            lambda repositories: [
                self._finding_projection(repositories, finding)
                for finding in repositories.findings.list(scan_id=scan_id)
            ]
        )

    def finding(self, finding_id: UUID) -> dict[str, JsonValue]:
        return self._read(
            lambda repositories: self._finding_projection(
                repositories,
                repositories.findings.get(finding_id),
            )
        )

    def update_finding(
        self,
        finding_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, JsonValue]:
        unknown = set(payload) - _MUTABLE_FINDING_FIELDS
        if unknown or not payload:
            raise ControlPlaneInputError(f"finding patch contains unsupported fields: {sorted(unknown)}")
        changes: dict[str, object] = {"updated_at": utc_now()}
        if "title" in payload:
            changes["title"] = _non_empty(payload["title"], "title")
        if "rationale" in payload:
            changes["rationale"] = _non_empty(
                payload["rationale"],
                "rationale",
                maximum=100_000,
            )
        if "remediation" in payload:
            changes["remediation"] = _non_empty(
                payload["remediation"],
                "remediation",
                maximum=100_000,
            )
        if "preconditions" in payload:
            value = payload["preconditions"]
            if (
                not isinstance(value, list)
                or len(value) > 100
                or any(not isinstance(item, str) or not item.strip() or len(item) > 10_000 for item in value)
            ):
                raise ControlPlaneInputError("preconditions must be at most 100 non-empty strings")
            changes["preconditions"] = list(dict.fromkeys(value))
        for field, enum_type in (
            ("severity", Severity),
            ("static_confidence", StaticConfidence),
            ("status", FindingStatus),
        ):
            if field not in payload:
                continue
            try:
                changes[field] = enum_type(str(payload[field]))
            except ValueError as exc:
                raise ControlPlaneInputError(f"invalid {field}") from exc
        with self._repositories() as repositories:
            current = repositories.findings.get(finding_id)
            updated = repositories.findings.upsert(current.model_copy(update=changes))
            EventService(repositories.events).append(
                "finding.updated",
                project_id=repositories.scans.get(updated.scan_id).project_id,
                scan_id=updated.scan_id,
                finding_id=updated.id,
                payload={
                    "fields": cast(JsonValue, sorted(payload)),
                    "static_only": True,
                    "dynamic_verification_changed": False,
                },
            )
            return self._finding_projection(repositories, updated)

    def verification_summary(self, finding_id: UUID) -> dict[str, JsonValue]:
        def operation(repositories: Repositories) -> dict[str, JsonValue]:
            finding = repositories.findings.get(finding_id)
            scan = repositories.scans.get(finding.scan_id)
            project = repositories.projects.get(scan.project_id)
            try:
                requirement = repositories.verification.requirements.get(finding.id)
            except NotFoundError:
                requirement = None
            plans = repositories.verification.plans.list(finding_id=finding.id)
            current_plan = next(
                (plan for plan in reversed(plans) if plan.status.value != "superseded"),
                None,
            )
            approvals = (
                repositories.verification.approvals.list(plan_id=current_plan.id) if current_plan is not None else []
            )
            attempts = (
                repositories.verification.attempts.list(plan_id=current_plan.id) if current_plan is not None else []
            )
            policy = _verification_policy_config(scan.config, project.default_config)
            if not policy.enabled:
                status = "disabled"
            elif requirement is None:
                status = "not_requested"
            elif requirement.missing_fields:
                status = "missing_inputs"
            elif current_plan is None:
                status = "requirements_ready"
            else:
                status = current_plan.status.value
            return {
                "finding_id": str(finding.id),
                "enabled": policy.enabled,
                "status": status,
                "network_execution_available": bool(
                    current_plan is not None
                    and current_plan.status.value == "approved"
                    and repositories.verification.environments.get(current_plan.environment_id).test_only
                ),
                "requirement": _model(requirement) if requirement is not None else None,
                "current_plan": _model(current_plan) if current_plan is not None else None,
                "plans": [_model(plan) for plan in plans],
                "approvals": [_model(approval) for approval in approvals],
                "attempts": [_model(attempt) for attempt in attempts],
                "evidence": [
                    _model(item)
                    for attempt in attempts
                    for item in repositories.verification.evidence.list(attempt_id=attempt.id)
                ],
                "missing_fields": (cast(JsonValue, requirement.missing_fields) if requirement is not None else []),
            }

        return self._read(operation)

    def execute_verification(
        self,
        plan_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, JsonValue]:
        if set(payload) != {"test_data"}:
            raise ControlPlaneInputError("verification execution requires only a test_data object")
        raw_test_data = payload.get("test_data")
        if not isinstance(raw_test_data, dict) or any(
            not isinstance(key, str) or not key or not isinstance(value, str) or not value
            for key, value in raw_test_data.items()
        ):
            raise ControlPlaneInputError("test_data must map non-empty names to non-empty strings")
        with self._repositories() as repositories:
            try:
                attempt = VerificationBroker(
                    repositories,
                    self.artifacts,
                    EnvironmentSecretProvider(os.environ),
                ).run(plan_id, test_data=cast(dict[str, str], raw_test_data))
            except VerificationExecutionDenied as exc:
                raise ControlPlaneInputError(str(exc)) from exc
            return {
                "attempt": _model(attempt),
                "evidence": [_model(item) for item in repositories.verification.evidence.list(attempt_id=attempt.id)],
            }

    def resolve_verification_requirement(
        self,
        finding_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, JsonValue]:
        allowed = {"declaration", "test_data_keys"}
        unknown = set(payload) - allowed
        if unknown:
            raise ControlPlaneInputError(f"verification requirement contains unsupported fields: {sorted(unknown)}")
        try:
            declaration = VerifierDeclaration.model_validate(payload.get("declaration"))
        except ValidationError as exc:
            raise ControlPlaneInputError(f"invalid verifier declaration: {exc}") from exc
        raw_test_data_keys = payload.get("test_data_keys", [])
        if (
            not isinstance(raw_test_data_keys, list)
            or any(not isinstance(item, str) or not item for item in raw_test_data_keys)
            or len(raw_test_data_keys) != len(set(raw_test_data_keys))
        ):
            raise ControlPlaneInputError("test_data_keys must be a unique list of non-empty names")
        with self._repositories() as repositories:
            finding = repositories.findings.get(finding_id)
            scan = repositories.scans.get(finding.scan_id)
            environments = repositories.verification.environments.list(project_id=scan.project_id)
            identities = repositories.verification.identities.list(project_id=scan.project_id)
            try:
                requirement = RequirementResolver().resolve(
                    finding,
                    declaration,
                    environments=environments,
                    identities=identities,
                    test_data_keys=set(cast(list[str], raw_test_data_keys)),
                )
            except ValueError as exc:
                raise ControlPlaneInputError(str(exc)) from exc
            persisted = repositories.verification.requirements.upsert(requirement)
            EventService(repositories.events).append(
                "verification.requirement.resolved",
                project_id=scan.project_id,
                scan_id=scan.id,
                finding_id=finding.id,
                payload={
                    "verifier_id": declaration.verifier_id,
                    "missing_fields": cast(JsonValue, persisted.missing_fields),
                    "network_permission": "none",
                },
            )
            return _model(persisted)

    def compile_verification_plan(
        self,
        finding_id: UUID,
        payload: dict[str, Any],
    ) -> dict[str, JsonValue]:
        allowed = {
            "abort_conditions",
            "actions",
            "environment_id",
            "expected_observations",
            "expected_side_effects",
            "health_checks",
            "identity_ids",
            "request_budget",
            "risk_class",
            "rollback_strategy",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise ControlPlaneInputError(f"verification plan contains unsupported fields: {sorted(unknown)}")
        environment_id = _uuid(payload.get("environment_id"), "environment_id")
        identity_ids = _uuid_list(payload.get("identity_ids"), "identity_ids")
        try:
            actions = [
                VerificationAction.model_validate(item) for item in _object_list(payload.get("actions"), "actions")
            ]
            request_budget = RequestBudget.model_validate(payload.get("request_budget"))
            expected_observations = [
                ExpectedObservation.model_validate(item)
                for item in _object_list(
                    payload.get("expected_observations"),
                    "expected_observations",
                )
            ]
            expected_side_effects = [
                ExpectedSideEffect.model_validate(item)
                for item in _object_list(
                    payload.get("expected_side_effects", []),
                    "expected_side_effects",
                    allow_empty=True,
                )
            ]
            rollback_strategy = RollbackStrategy.model_validate(payload.get("rollback_strategy"))
            abort_conditions = [
                AbortCondition.model_validate(item)
                for item in _object_list(
                    payload.get("abort_conditions"),
                    "abort_conditions",
                )
            ]
            risk_class = RiskClass(payload.get("risk_class"))
        except (ValidationError, ValueError) as exc:
            raise ControlPlaneInputError(f"invalid verification plan: {exc}") from exc
        health_checks = _string_list(payload.get("health_checks", []), "health_checks")

        with self._repositories() as repositories:
            finding = repositories.findings.get(finding_id)
            scan = repositories.scans.get(finding.scan_id)
            project = repositories.projects.get(scan.project_id)
            policy = _verification_policy_config(scan.config, project.default_config)
            if not policy.enabled:
                raise ControlPlaneInputError("verification.enabled is false for this Scan")
            requirement = repositories.verification.requirements.get(finding.id)
            environment = repositories.verification.environments.get(environment_id)
            identities = [repositories.verification.identities.get(identity_id) for identity_id in identity_ids]
            if environment.project_id != scan.project_id or any(
                identity.project_id != scan.project_id for identity in identities
            ):
                raise ControlPlaneInputError("verification inputs must belong to the Finding project")
            draft = PlanDraft(
                finding_id=finding.id,
                snapshot_id=finding.snapshot_id,
                environment=environment,
                identities=identities,
                actions=actions,
                request_budget=request_budget,
                expected_observations=expected_observations,
                expected_side_effects=expected_side_effects,
                rollback_strategy=rollback_strategy,
                health_checks=health_checks,
                abort_conditions=abort_conditions,
                risk_class=risk_class,
            )
            try:
                compiled = VerificationPlanCompiler().compile(requirement, draft)
            except ValueError as exc:
                raise ControlPlaneInputError(str(exc)) from exc
            persisted = repositories.verification.plans.create(compiled)
            if persisted.id == compiled.id:
                EventService(repositories.events).append(
                    "verification.plan.created",
                    project_id=scan.project_id,
                    scan_id=scan.id,
                    finding_id=finding.id,
                    payload={
                        "plan_id": str(persisted.id),
                        "plan_hash": persisted.plan_hash,
                        "risk_class": persisted.risk_class.value,
                        "network_execution_available": False,
                    },
                )
            return _model(persisted)

    def list_verification_approvals(
        self,
        *,
        plan_id: UUID | None = None,
    ) -> list[dict[str, JsonValue]]:
        return self._read(
            lambda repositories: [_model(item) for item in repositories.verification.approvals.list(plan_id=plan_id)]
        )

    def verification_plan(self, plan_id: UUID) -> dict[str, JsonValue]:
        def operation(repositories: Repositories) -> dict[str, JsonValue]:
            plan = repositories.verification.plans.get(plan_id)
            approvals = repositories.verification.approvals.list(plan_id=plan.id)
            return {
                **_model(plan),
                "approvals": [_model(item) for item in approvals],
                "network_execution_available": False,
            }

        return self._read(operation)

    def request_verification_approval(self, plan_id: UUID) -> dict[str, JsonValue]:
        with self._repositories() as repositories:
            plan = repositories.verification.plans.get(plan_id)
            finding = repositories.findings.get(plan.finding_id)
            scan = repositories.scans.get(finding.scan_id)
            project = repositories.projects.get(scan.project_id)
            policy = _verification_policy_config(scan.config, project.default_config)
        database = Database(self.database_path)
        try:
            approval = ApprovalService(database).request(plan_id, policy)
            return _model(approval)
        finally:
            database.close()

    def decide_verification_approval(
        self,
        approval_id: UUID,
        decision: ApprovalDecision,
        payload: dict[str, Any],
    ) -> dict[str, JsonValue]:
        reviewer = _non_empty(payload.get("reviewer"), "reviewer", maximum=255)
        reason = _non_empty(payload.get("reason"), "reason", maximum=10_000)
        unknown = set(payload) - {"reason", "reviewer"}
        if unknown:
            raise ControlPlaneInputError(
                f"verification approval decision contains unsupported fields: {sorted(unknown)}"
            )
        database = Database(self.database_path)
        try:
            approval = ApprovalService(database).decide(
                approval_id,
                decision,
                reviewer=reviewer,
                reason=reason,
            )
            return _model(approval)
        finally:
            database.close()

    @staticmethod
    def _finding_projection(
        repositories: Repositories,
        finding: StaticFindingV2,
    ) -> dict[str, JsonValue]:
        reviews = [
            review for review in repositories.reviews.list(scan_id=finding.scan_id) if finding.id in review.subject_ids
        ]
        latest = reviews[-1] if reviews else None
        verification = _finding_verification_projection(repositories, finding)
        seed_ids = list(
            dict.fromkeys(
                [
                    *finding.source_node_ids,
                    *finding.sink_node_ids,
                ]
            )
        )
        return {
            **_model(finding),
            "static_review": (_model(latest) if latest is not None else {"status": "not_requested"}),
            "dynamic_verification": verification,
            "graph_slice_url": (
                f"/api/artifacts/{finding.graph_slice_artifact_id}/graph-slice"
                if finding.graph_slice_artifact_id is not None
                else (
                    f"/api/scans/{finding.scan_id}/graph/slice?" + urlencode({"seed_id": seed_ids}, doseq=True)
                    if seed_ids
                    else None
                )
            ),
        }

    def list_reviews(
        self,
        *,
        scan_id: UUID | None = None,
        status: ReviewStatus | None = None,
    ) -> list[dict[str, JsonValue]]:
        def operation(repositories: Repositories) -> list[dict[str, JsonValue]]:
            values = repositories.reviews.list(scan_id=scan_id)
            if status is not None:
                values = [item for item in values if item.status is status]
            return [_model(item) for item in values]

        return self._read(operation)

    def create_review(self, payload: dict[str, Any]) -> dict[str, JsonValue]:
        scan_id = _uuid(payload.get("scan_id"), "scan_id")
        task_id = _uuid(payload.get("task_id"), "task_id")
        try:
            subject_type = ReviewSubjectType(str(payload.get("subject_type")))
        except ValueError as exc:
            raise ControlPlaneInputError("invalid subject_type") from exc
        raw_ids = payload.get("subject_ids")
        if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > 100:
            raise ControlPlaneInputError("subject_ids must contain between 1 and 100 UUIDs")
        subject_ids = list(dict.fromkeys(_uuid(item, "subject_id") for item in raw_ids))
        with self._repositories() as repositories:
            scan = repositories.scans.get(scan_id)
            task = repositories.tasks.get(task_id)
            if task.scan_id != scan.id:
                raise ControlPlaneInputError("task does not belong to scan")
            if subject_type is ReviewSubjectType.ARTIFACT:
                subjects = [repositories.artifacts.get(item) for item in subject_ids]
                if any(item.scan_id != scan.id for item in subjects):
                    raise ControlPlaneInputError("review artifacts must belong to scan")
                identity: JsonValue = [
                    {
                        "id": str(item.id),
                        "content_hash": item.content_hash,
                    }
                    for item in subjects
                ]
            else:
                findings = [repositories.findings.get(item) for item in subject_ids]
                if any(item.scan_id != scan.id for item in findings):
                    raise ControlPlaneInputError("review findings must belong to scan")
                identity = [
                    {
                        "id": str(item.id),
                        "fingerprint": item.fingerprint,
                    }
                    for item in findings
                ]
            review = repositories.reviews.create(
                ReviewRequest(
                    scan_id=scan.id,
                    task_id=task.id,
                    subject_type=subject_type,
                    subject_ids=subject_ids,
                    subject_hash=sha256_digest(identity),
                )
            )
            EventService(repositories.events).append(
                "review.created",
                project_id=scan.project_id,
                scan_id=scan.id,
                task_id=task.id,
                payload={
                    "review_id": str(review.id),
                    "subject_hash": review.subject_hash,
                    "subject_type": review.subject_type.value,
                },
            )
            return _model(review)

    def decide_review(
        self,
        review_id: UUID,
        target: ReviewStatus,
        payload: dict[str, Any],
    ) -> dict[str, JsonValue]:
        reviewer = _non_empty(payload.get("reviewer"), "reviewer", maximum=255)
        reason = _non_empty(payload.get("reason"), "reason", maximum=10_000)
        with self._repositories() as repositories:
            decided = ControlServices(repositories).reviews.decide(
                review_id,
                target,
                reviewer=reviewer,
                reason=reason,
            )
            return _model(decided)

    def record_action(
        self,
        event_type: str,
        *,
        project_id: UUID | None = None,
        scan_id: UUID | None = None,
        payload: dict[str, JsonValue] | None = None,
    ) -> None:
        with self._repositories() as repositories:
            EventService(repositories.events).append(
                event_type,
                project_id=project_id,
                scan_id=scan_id,
                payload=payload,
            )

    def reconcile_running_scans(self) -> list[str]:
        """Mark dead/stale workers through the existing persistent executor."""
        if not self.database_path.is_file():
            return []
        reconciled: list[str] = []
        with self._repositories() as repositories:
            executor = LocalPlanExecutor(
                repositories,
                runs_root=self.runs_root,
                stale_after=timedelta(minutes=5),
            )
            for scan in repositories.scans.list():
                if scan.status is not ScanStatus.RUNNING:
                    continue
                before = {task.id: task.status for task in repositories.tasks.list(scan_id=scan.id)}
                executor.recover_stale(scan.id)
                after = repositories.tasks.list(scan_id=scan.id)
                changed = [task for task in after if before.get(task.id) is not task.status]
                if not changed:
                    continue
                reconciled.append(str(scan.id))
                EventService(repositories.events).append(
                    "web.reconciled_lost_workers",
                    project_id=scan.project_id,
                    scan_id=scan.id,
                    payload={
                        "task_ids": [str(task.id) for task in changed],
                        "recoverable": any(
                            task.status
                            in {
                                TaskStatus.READY,
                                TaskStatus.INTERRUPTED,
                                TaskStatus.FAILED_RETRYABLE,
                            }
                            for task in changed
                        ),
                    },
                )
        return reconciled


def _scan_projection(
    repositories: Repositories,
    scan: Scan,
) -> dict[str, JsonValue]:
    tasks = repositories.tasks.list(scan_id=scan.id)
    findings = repositories.findings.list(scan_id=scan.id)
    reviews = repositories.reviews.list(scan_id=scan.id)
    return {
        **_model(scan),
        "task_counts": dict(Counter(item.status.value for item in tasks)),
        "finding_count": len(findings),
        "open_review_count": sum(item.status is ReviewStatus.OPEN for item in reviews),
    }


def _scan_detail(
    repositories: Repositories,
    scan: Scan,
) -> dict[str, JsonValue]:
    projection = _scan_projection(repositories, scan)
    tasks = repositories.tasks.list(scan_id=scan.id)
    artifacts = repositories.artifacts.list(scan_id=scan.id)
    findings = repositories.findings.list(scan_id=scan.id)
    reviews = repositories.reviews.list(scan_id=scan.id)
    try:
        snapshot: JsonValue = _model(repositories.snapshots.get(scan.snapshot_id))
        if isinstance(snapshot, dict):
            snapshot.pop("materialized_path", None)
            snapshot.pop("repository_path", None)
    except NotFoundError:
        snapshot = None
    severity_counts = Counter(item.severity.value for item in findings)
    project = repositories.projects.get(scan.project_id)
    verification_policy = _verification_policy_config(
        scan.config,
        project.default_config,
    )
    requirements = [
        requirement
        for requirement in repositories.verification.requirements.list()
        if any(finding.id == requirement.finding_id for finding in findings)
    ]
    verification_plans = [
        plan for finding in findings for plan in repositories.verification.plans.list(finding_id=finding.id)
    ]
    return {
        **projection,
        "snapshot": snapshot,
        "summary": {
            "tasks": len(tasks),
            "artifacts": len(artifacts),
            "findings": len(findings),
            "severity_counts": dict(severity_counts),
            "open_reviews": sum(item.status is ReviewStatus.OPEN for item in reviews),
        },
        "static_review": {
            "status": (
                "waiting"
                if any(item.status is ReviewStatus.OPEN for item in reviews)
                else "complete"
                if reviews
                else "not_requested"
            ),
            "label": "人工静态审核",
        },
        "dynamic_verification": {
            "available": verification_policy.enabled,
            "status": (
                "disabled"
                if not verification_policy.enabled
                else "missing_inputs"
                if any(item.missing_fields for item in requirements)
                else "planning"
                if requirements and not verification_plans
                else "planned"
                if verification_plans
                else "not_requested"
            ),
            "label": "动态验证（M9 仅人工批准的只读测试环境）",
            "requirements": len(requirements),
            "plans": len(verification_plans),
            "network_execution_available": any(
                plan.status.value == "approved"
                and repositories.verification.environments.get(plan.environment_id).test_only
                for plan in verification_plans
            ),
        },
    }


def _finding_verification_projection(
    repositories: Repositories,
    finding: StaticFindingV2,
) -> dict[str, JsonValue]:
    scan = repositories.scans.get(finding.scan_id)
    project = repositories.projects.get(scan.project_id)
    policy = _verification_policy_config(scan.config, project.default_config)
    try:
        requirement = repositories.verification.requirements.get(finding.id)
    except NotFoundError:
        requirement = None
    plans = repositories.verification.plans.list(finding_id=finding.id)
    current = next(
        (plan for plan in reversed(plans) if plan.status.value != "superseded"),
        None,
    )
    if not policy.enabled:
        status = "disabled"
    elif requirement is None:
        status = "not_requested"
    elif requirement.missing_fields:
        status = "missing_inputs"
    elif current is None:
        status = "requirements_ready"
    else:
        status = current.status.value
    return {
        "available": policy.enabled,
        "status": status,
        "label": "动态验证（M9 仅人工批准的只读测试环境）",
        "missing_fields": (cast(JsonValue, requirement.missing_fields) if requirement is not None else []),
        "plan_id": str(current.id) if current is not None else None,
        "plan_hash": current.plan_hash if current is not None else None,
        "network_execution_available": bool(
            current is not None
            and current.status.value == "approved"
            and repositories.verification.environments.get(current.environment_id).test_only
        ),
    }


def _artifact_projection(artifact: Artifact) -> dict[str, JsonValue]:
    value = _model(artifact)
    value.pop("storage_uri", None)
    value["downloadable"] = True
    return value


def _sensitive_artifact(artifact: Artifact) -> bool:
    lowered = f"{artifact.artifact_type} {' '.join(artifact.capabilities)}".lower()
    return any(term in lowered for term in _DENIED_PREVIEW_TERMS)


def _safe_attempt(attempt: TaskAttempt) -> dict[str, JsonValue]:
    value = _model(attempt)
    value.pop("input_hashes", None)
    value["duration_seconds"] = _duration_seconds(
        attempt.started_at,
        attempt.finished_at,
    )
    value["worker"] = {
        "pid": attempt.worker_pid,
        "heartbeat_at": attempt.heartbeat_at.isoformat(),
    }
    value.pop("worker_pid", None)
    return value


def _safe_event(event: Event) -> dict[str, JsonValue]:
    return _model(event)
