"""Add M9 read-only HTTP verification attempts and evidence."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_http_verification"
down_revision: str | None = "0006_verification_planning"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "verification_environments",
        sa.Column("test_only", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "verification_environments",
        sa.Column("allow_private_addresses", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "verification_attempts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("plan_id", sa.String(length=36), nullable=False),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("environment_id", sa.String(length=36), nullable=False),
        sa.Column("conclusion", sa.String(length=32), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("response_bytes", sa.Integer(), nullable=False),
        sa.Column("health_before", sa.JSON(), nullable=True),
        sa.Column("health_after", sa.JSON(), nullable=True),
        sa.Column("abort_reason", sa.Text(), nullable=True),
        sa.Column("started_at", sa.String(length=40), nullable=False),
        sa.Column("finished_at", sa.String(length=40), nullable=True),
        sa.ForeignKeyConstraint(["environment_id"], ["verification_environments.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["plan_id"], ["verification_plans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("plan_id", "finding_id", "conclusion"):
        op.create_index(f"ix_verification_attempts_{column}", "verification_attempts", [column])
    op.create_table(
        "verification_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("attempt_id", sa.String(length=36), nullable=False),
        sa.Column("plan_id", sa.String(length=36), nullable=False),
        sa.Column("action_id", sa.String(length=128), nullable=False),
        sa.Column("identity_handle", sa.String(length=128), nullable=False),
        sa.Column("request_summary", sa.JSON(), nullable=False),
        sa.Column("response_status", sa.Integer(), nullable=False),
        sa.Column("response_headers", sa.JSON(), nullable=False),
        sa.Column("body_hash", sa.String(length=64), nullable=False),
        sa.Column("body_excerpt", sa.Text(), nullable=False),
        sa.Column("observation", sa.JSON(), nullable=False),
        sa.Column("predicate_result", sa.String(length=32), nullable=False),
        sa.Column("conclusion", sa.String(length=32), nullable=False),
        sa.Column("artifact_hash", sa.String(length=64), nullable=False),
        sa.Column("artifact_size_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["attempt_id"], ["verification_attempts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["plan_id"], ["verification_plans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("attempt_id", "plan_id", "conclusion"):
        op.create_index(f"ix_verification_evidence_{column}", "verification_evidence", [column])


def downgrade() -> None:
    op.drop_table("verification_evidence")
    op.drop_table("verification_attempts")
    op.drop_column("verification_environments", "allow_private_addresses")
    op.drop_column("verification_environments", "test_only")
