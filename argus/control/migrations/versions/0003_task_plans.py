"""Persist compiled TaskPlan metadata."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_task_plans"
down_revision: str | None = "0002_source_snapshots"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "task_plans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_index("ix_task_plans_plan_hash", "task_plans", ["plan_hash"], unique=False)
    op.create_index("ix_task_plans_scan_id", "task_plans", ["scan_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_task_plans_scan_id", table_name="task_plans")
    op.drop_index("ix_task_plans_plan_hash", table_name="task_plans")
    op.drop_table("task_plans")
