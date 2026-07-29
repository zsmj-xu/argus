"""Add persistent SourceSnapshot records."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_source_snapshots"
down_revision: str | None = "0001_control_store"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("repository_path", sa.Text(), nullable=False),
        sa.Column("vcs_type", sa.String(length=16), nullable=False),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("tree_hash", sa.String(length=64), nullable=False),
        sa.Column("dirty", sa.Boolean(), nullable=False),
        sa.Column("materialized_path", sa.Text(), nullable=False),
        sa.Column("manifest_artifact_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("manifest_artifact_id"),
    )
    op.create_index("ix_source_snapshots_project_id", "source_snapshots", ["project_id"], unique=False)
    op.create_index("ix_source_snapshots_tree_hash", "source_snapshots", ["tree_hash"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_source_snapshots_tree_hash", table_name="source_snapshots")
    op.drop_index("ix_source_snapshots_project_id", table_name="source_snapshots")
    op.drop_table("source_snapshots")
