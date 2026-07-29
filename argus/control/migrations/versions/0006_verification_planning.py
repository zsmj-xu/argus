"""Add M8 offline verification requirements, plans, and approvals."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_verification_planning"
down_revision: str | None = "0005_detection_findings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "verification_environments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("target_base_url", sa.Text(), nullable=True),
        sa.Column("scope_allowlist", sa.JSON(), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("health_checks", sa.JSON(), nullable=False),
        sa.Column("reset_capability", sa.String(length=32), nullable=False),
        sa.Column("source_snapshot_binding", sa.String(length=36), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_verification_environments_project_id",
        "verification_environments",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_verification_environments_source_snapshot_binding",
        "verification_environments",
        ["source_snapshot_binding"],
        unique=False,
    )

    op.create_table(
        "verification_identities",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("handle", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=128), nullable=False),
        sa.Column("tenant", sa.String(length=255), nullable=True),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("credential_ref", sa.String(length=320), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id",
            "handle",
            name="uq_verification_identity_project_handle",
        ),
    )
    op.create_index(
        "ix_verification_identities_project_id",
        "verification_identities",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_verification_identities_role",
        "verification_identities",
        ["role"],
        unique=False,
    )

    op.create_table(
        "verification_requirements",
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("required_environment_capabilities", sa.JSON(), nullable=False),
        sa.Column("required_identity_roles", sa.JSON(), nullable=False),
        sa.Column("required_test_data", sa.JSON(), nullable=False),
        sa.Column("missing_fields", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("finding_id"),
    )

    op.create_table(
        "verification_plans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("environment_id", sa.String(length=36), nullable=False),
        sa.Column("identity_handles", sa.JSON(), nullable=False),
        sa.Column("actions", sa.JSON(), nullable=False),
        sa.Column("request_budget", sa.JSON(), nullable=False),
        sa.Column("expected_observations", sa.JSON(), nullable=False),
        sa.Column("expected_side_effects", sa.JSON(), nullable=False),
        sa.Column("rollback_strategy", sa.JSON(), nullable=False),
        sa.Column("health_checks", sa.JSON(), nullable=False),
        sa.Column("abort_conditions", sa.JSON(), nullable=False),
        sa.Column("risk_class", sa.String(length=32), nullable=False),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["environment_id"], ["verification_environments.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "environment_id",
        "finding_id",
        "plan_hash",
        "risk_class",
        "snapshot_id",
        "status",
    ):
        op.create_index(
            f"ix_verification_plans_{column}",
            "verification_plans",
            [column],
            unique=False,
        )

    op.create_table(
        "verification_approvals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("plan_id", sa.String(length=36), nullable=False),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reviewer", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("decided_at", sa.String(length=40), nullable=True),
        sa.Column("expires_at", sa.String(length=40), nullable=True),
        sa.ForeignKeyConstraint(["plan_id"], ["verification_plans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("decision", "expires_at", "plan_hash", "plan_id"):
        op.create_index(
            f"ix_verification_approvals_{column}",
            "verification_approvals",
            [column],
            unique=False,
        )


def downgrade() -> None:
    op.drop_table("verification_approvals")
    op.drop_table("verification_plans")
    op.drop_table("verification_requirements")
    op.drop_table("verification_identities")
    op.drop_table("verification_environments")
