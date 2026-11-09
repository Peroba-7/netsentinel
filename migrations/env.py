"""Ambiente do Alembic: usa o DATABASE_URL e os modelos do NetSentinel."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool
from sqlmodel import SQLModel

import app.db.models  # noqa: F401  (regista as tabelas no SQLModel.metadata)
from app.config import settings

config = context.config
# Os testes desligam esta configuração para não alterarem o logging do pytest.
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = SQLModel.metadata


def include_name(name, type_, _parent_names) -> bool:
    """Ignora tabelas que não pertencem aos modelos (ex.: a antiga threat_logs).

    Sem isto, uma migração gerada com --autogenerate proporia apagá-las.
    """
    if type_ == "table":
        return name in target_metadata.tables
    return True


def _database_url() -> str:
    # Os testes passam um URL próprio; no uso normal vem das configurações da aplicação.
    return config.attributes.get("database_url") or settings.DATABASE_URL


def _configure(**kwargs) -> None:
    context.configure(
        target_metadata=target_metadata,
        include_name=include_name,
        compare_type=True,
        # O SQLite não altera colunas no lugar; o modo batch recria a tabela quando é preciso.
        render_as_batch=_database_url().startswith("sqlite"),
        **kwargs,
    )


def run_migrations_offline() -> None:
    _configure(url=_database_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()
        return

    engine = create_engine(_database_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        _configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
