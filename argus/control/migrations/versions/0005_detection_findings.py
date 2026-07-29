"""Add root-cause linkage for normalized M6 findings."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_detection_findings"
down_revision: str | None = "0004_local_executor"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("root_cause_key", sa.String(length=64), nullable=True))
        batch.create_index(
            "ix_findings_root_cause_key",
            ["root_cause_key"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("ix_findings_root_cause_key")
        batch.drop_column("root_cause_key")
