from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlmodel import SQLModel

import app.db.models  # noqa: F401  (regista as tabelas)

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def database_url(tmp_path):
    return f"sqlite:///{(tmp_path / 'migrations.db').as_posix()}"


def alembic_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["database_url"] = database_url
    config.attributes["configure_logger"] = False
    return config


def head_revision(config: Config) -> str:
    return ScriptDirectory.from_config(config).get_current_head()


def current_revision(engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def test_migrations_create_schema_matching_models(database_url):
    config = alembic_config(database_url)

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        assert compare_metadata(context, SQLModel.metadata) == []
    assert current_revision(engine) == head_revision(config)


def test_initial_migration_keeps_existing_data(database_url):
    # Simula uma base criada pela versão anterior, sem Alembic, com dados e uma tabela antiga.
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE threat_records (id INTEGER PRIMARY KEY, ip_address VARCHAR NOT NULL,"
                " threat_type VARCHAR NOT NULL, description VARCHAR, risk_level VARCHAR NOT NULL,"
                " ai_analysis VARCHAR, timestamp DATETIME NOT NULL)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO threat_records (ip_address, threat_type, risk_level, timestamp)"
                " VALUES ('10.0.0.1', 'DDoS', 'ALTO', '2026-11-08 12:00:00')"
            )
        )
        connection.execute(text("CREATE TABLE threat_logs (id INTEGER PRIMARY KEY)"))

    command.upgrade(alembic_config(database_url), "0001")

    with engine.connect() as connection:
        rows = connection.execute(text("SELECT ip_address FROM threat_records")).all()
    assert rows == [("10.0.0.1",)]
    tables = set(inspect(engine).get_table_names())
    assert {"threat_records", "blocked_ips", "threat_logs"} <= tables
    assert current_revision(engine) == "0001"
