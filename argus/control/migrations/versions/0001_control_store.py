"""Create the initial Argus V2 control-store schema."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_control_store"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("repository_path", sa.Text(), nullable=False),
        sa.Column("default_config", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.Column("archived_at", sa.String(length=40), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("plan_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=48), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("config_hash", sa.String(length=64), nullable=False),
        sa.Column("engine", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("started_at", sa.String(length=40), nullable=True),
        sa.Column("finished_at", sa.String(length=40), nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_plan_id", "scans", ["plan_id"], unique=False)
    op.create_index("ix_scans_project_id", "scans", ["project_id"], unique=False)
    op.create_index("ix_scans_snapshot_id", "scans", ["snapshot_id"], unique=False)
    op.create_index("ix_scans_status", "scans", ["status"], unique=False)
    op.create_table(
        "tasks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("plan_id", sa.String(length=36), nullable=True),
        sa.Column("plugin_id", sa.String(length=255), nullable=False),
        sa.Column("plugin_version", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("depends_on", sa.JSON(), nullable=False),
        sa.Column("required_capabilities", sa.JSON(), nullable=False),
        sa.Column("expected_capabilities", sa.JSON(), nullable=False),
        sa.Column("config_hash", sa.String(length=64), nullable=False),
        sa.Column("cache_key", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=48), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("started_at", sa.String(length=40), nullable=True),
        sa.Column("finished_at", sa.String(length=40), nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "id", name="uq_tasks_scan_id_id"),
    )
    op.create_index("ix_tasks_cache_key", "tasks", ["cache_key"], unique=False)
    op.create_index("ix_tasks_plan_id", "tasks", ["plan_id"], unique=False)
    op.create_index("ix_tasks_scan_id", "tasks", ["scan_id"], unique=False)
    op.create_index("ix_tasks_scan_status", "tasks", ["scan_id", "status"], unique=False)
    op.create_index("ix_tasks_status", "tasks", ["status"], unique=False)
    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_type", sa.String(length=255), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("producer_plugin_id", sa.String(length=255), nullable=False),
        sa.Column("producer_plugin_version", sa.String(length=64), nullable=False),
        sa.Column("media_type", sa.String(length=255), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("storage_uri", sa.Text(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_artifacts_artifact_type", "artifacts", ["artifact_type"], unique=False)
    op.create_index("ix_artifacts_content_hash", "artifacts", ["content_hash"], unique=False)
    op.create_index("ix_artifacts_scan_id", "artifacts", ["scan_id"], unique=False)
    op.create_index("ix_artifacts_snapshot_id", "artifacts", ["snapshot_id"], unique=False)
    op.create_index("ix_artifacts_task_id", "artifacts", ["task_id"], unique=False)
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("rule_version", sa.String(length=64), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("weakness_id", sa.String(length=128), nullable=False),
        sa.Column("vuln_class", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("static_confidence", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=48), nullable=False),
        sa.Column("locations", sa.JSON(), nullable=False),
        sa.Column("source_node_ids", sa.JSON(), nullable=False),
        sa.Column("sink_node_ids", sa.JSON(), nullable=False),
        sa.Column("graph_slice_artifact_id", sa.String(length=36), nullable=True),
        sa.Column("evidence_artifact_ids", sa.JSON(), nullable=False),
        sa.Column("preconditions", sa.JSON(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"], unique=False)
    op.create_index("ix_findings_snapshot_id", "findings", ["snapshot_id"], unique=False)
    op.create_index("ix_findings_status", "findings", ["status"], unique=False)
    op.create_table(
        "events",
        sa.Column("sequence", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=True),
        sa.Column("scan_id", sa.String(length=36), nullable=True),
        sa.Column("task_id", sa.String(length=36), nullable=True),
        sa.Column("finding_id", sa.String(length=36), nullable=True),
        sa.Column("event_type", sa.String(length=255), nullable=False),
        sa.Column("level", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("sequence"),
        sa.UniqueConstraint("id"),
    )
    op.create_index("ix_events_event_type", "events", ["event_type"], unique=False)
    op.create_index("ix_events_finding_id", "events", ["finding_id"], unique=False)
    op.create_index("ix_events_project_id", "events", ["project_id"], unique=False)
    op.create_index("ix_events_scan_id", "events", ["scan_id"], unique=False)
    op.create_index("ix_events_task_id", "events", ["task_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_events_task_id", table_name="events")
    op.drop_index("ix_events_scan_id", table_name="events")
    op.drop_index("ix_events_project_id", table_name="events")
    op.drop_index("ix_events_finding_id", table_name="events")
    op.drop_index("ix_events_event_type", table_name="events")
    op.drop_table("events")
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_snapshot_id", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_artifacts_task_id", table_name="artifacts")
    op.drop_index("ix_artifacts_snapshot_id", table_name="artifacts")
    op.drop_index("ix_artifacts_scan_id", table_name="artifacts")
    op.drop_index("ix_artifacts_content_hash", table_name="artifacts")
    op.drop_index("ix_artifacts_artifact_type", table_name="artifacts")
    op.drop_table("artifacts")
    op.drop_index("ix_tasks_status", table_name="tasks")
    op.drop_index("ix_tasks_scan_status", table_name="tasks")
    op.drop_index("ix_tasks_scan_id", table_name="tasks")
    op.drop_index("ix_tasks_plan_id", table_name="tasks")
    op.drop_index("ix_tasks_cache_key", table_name="tasks")
    op.drop_table("tasks")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_snapshot_id", table_name="scans")
    op.drop_index("ix_scans_project_id", table_name="scans")
    op.drop_index("ix_scans_plan_id", table_name="scans")
    op.drop_table("scans")
    op.drop_table("projects")
