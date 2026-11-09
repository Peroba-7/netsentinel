"""Tabelas iniciais: threat_records e blocked_ips

Representa o esquema que a API criava sozinha antes do Alembic. Cada tabela só é criada se
ainda não existir: numa base já em uso, a migração não altera nada e apenas fica registada
como aplicada, sem apagar dados (o mesmo efeito de `alembic stamp 0001`).

Revision ID: 0001
Revises:
Create Date: 2026-11-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Em modo offline (--sql) não há ligação para consultar: gera o SQL de uma base vazia.
    existing = (
        set() if context.is_offline_mode() else set(sa.inspect(op.get_bind()).get_table_names())
    )

    if "threat_records" not in existing:
        op.create_table(
            "threat_records",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("ip_address", sa.String(), nullable=False),
            sa.Column("threat_type", sa.String(), nullable=False),
            sa.Column("description", sa.String(), nullable=True),
            sa.Column("risk_level", sa.String(), nullable=False),
            sa.Column("ai_analysis", sa.String(), nullable=True),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        )

    if "blocked_ips" not in existing:
        op.create_table(
            "blocked_ips",
            sa.Column("ip_address", sa.String(), primary_key=True),
            sa.Column("reason", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("dispatched", sa.Boolean(), nullable=False),
            sa.Column("result", sa.String(), nullable=True),
        )


def downgrade() -> None:
    # Apagaria todos os incidentes e bloqueios; para voltar atrás, restaure um backup.
    raise RuntimeError("A migração inicial não pode ser revertida. Restaure um backup.")
