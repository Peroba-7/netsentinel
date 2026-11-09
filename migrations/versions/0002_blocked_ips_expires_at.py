"""Prazo opcional dos bloqueios: blocked_ips.expires_at

Os bloqueios já existentes ficam com o valor vazio, ou seja, permanentes.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "blocked_ips", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    # batch: no SQLite, apagar uma coluna exige recriar a tabela.
    with op.batch_alter_table("blocked_ips") as batch_op:
        batch_op.drop_column("expires_at")
