"""Add local execution attempts, review requests, and task policies."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_local_executor"
down_revision: str | None = "0003_task_plans"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("tasks") as batch:
        batch.add_column(
            sa.Column(
                "optional_capabilities",
                sa.JSON(),
                nullable=False,
                server_default="[]",
            )
        )
        batch.add_column(
            sa.Column(
                "continue_on_failure",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch.add_column(
            sa.Column(
                "max_attempts",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )

    op.create_table(
        "task_attempts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=48), nullable=False),
        sa.Column("plugin_id", sa.String(length=255), nullable=False),
        sa.Column("plugin_version", sa.String(length=64), nullable=False),
        sa.Column("input_artifact_ids", sa.JSON(), nullable=False),
        sa.Column("input_hashes", sa.JSON(), nullable=False),
        sa.Column("config_hash", sa.String(length=64), nullable=False),
        sa.Column("worker_pid", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.String(length=40), nullable=False),
        sa.Column("heartbeat_at", sa.String(length=40), nullable=False),
        sa.Column("finished_at", sa.String(length=40), nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id", "attempt_number", name="uq_task_attempt_number"),
    )
    op.create_index(
        "ix_task_attempts_heartbeat_at",
        "task_attempts",
        ["heartbeat_at"],
        unique=False,
    )
    op.create_index(
        "ix_task_attempts_scan_id",
        "task_attempts",
        ["scan_id"],
        unique=False,
    )
    op.create_index(
        "ix_task_attempts_status",
        "task_attempts",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_task_attempts_task_id",
        "task_attempts",
        ["task_id"],
        unique=False,
    )

    op.create_table(
        "review_requests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("subject_type", sa.String(length=32), nullable=False),
        sa.Column("subject_ids", sa.JSON(), nullable=False),
        sa.Column("subject_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reviewer", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("decided_at", sa.String(length=40), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_review_requests_scan_id",
        "review_requests",
        ["scan_id"],
        unique=False,
    )
    op.create_index(
        "ix_review_requests_status",
        "review_requests",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_review_requests_task_id",
        "review_requests",
        ["task_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_review_requests_task_id", table_name="review_requests")
    op.drop_index("ix_review_requests_status", table_name="review_requests")
    op.drop_index("ix_review_requests_scan_id", table_name="review_requests")
    op.drop_table("review_requests")
    op.drop_index("ix_task_attempts_task_id", table_name="task_attempts")
    op.drop_index("ix_task_attempts_status", table_name="task_attempts")
    op.drop_index("ix_task_attempts_scan_id", table_name="task_attempts")
    op.drop_index("ix_task_attempts_heartbeat_at", table_name="task_attempts")
    op.drop_table("task_attempts")
    with op.batch_alter_table("tasks") as batch:
        batch.drop_column("max_attempts")
        batch.drop_column("continue_on_failure")
        batch.drop_column("optional_capabilities")
