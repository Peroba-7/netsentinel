"""Origem do IP nos incidentes (país, ASN e âmbito)

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-09

Os incidentes antigos ficam sem país nem ASN (a base de hoje não diz onde o IP estava na altura),
mas recebem o `ip_scope`, que depende só do endereço.
"""

import ipaddress
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DOCUMENTATION = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _scope(value: str) -> str | None:
    # Cópia da regra de app/services/geoip_service.py, para a migração não mudar se o código mudar.
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    reserved = (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or any(address in network for network in _DOCUMENTATION)
    )
    return "reservado" if reserved else "publico"


def upgrade() -> None:
    op.add_column("threat_records", sa.Column("country_code", sa.String(2), nullable=True))
    op.add_column("threat_records", sa.Column("country_name", sa.String(100), nullable=True))
    op.add_column("threat_records", sa.Column("asn", sa.BigInteger(), nullable=True))
    op.add_column("threat_records", sa.Column("as_org", sa.String(255), nullable=True))
    op.add_column("threat_records", sa.Column("ip_scope", sa.String(16), nullable=True))

    # Em modo offline (--sql) não há dados para ler.
    if context.is_offline_mode():
        return
    connection = op.get_bind()
    rows = connection.execute(sa.text("SELECT id, ip_address FROM threat_records")).all()
    updates = [
        {"id": row_id, "scope": scope}
        for row_id, ip_address in rows
        if (scope := _scope(ip_address or "")) is not None
    ]
    if updates:
        connection.execute(
            sa.text("UPDATE threat_records SET ip_scope = :scope WHERE id = :id"), updates
        )


def downgrade() -> None:
    # batch_alter_table: o SQLite dos testes não remove colunas com um ALTER TABLE simples.
    with op.batch_alter_table("threat_records") as batch:
        for column in ("ip_scope", "as_org", "asn", "country_name", "country_code"):
            batch.drop_column(column)
