from collections.abc import Iterator

from sqlmodel import Session, create_engine

from app.config import settings

# O esquema é gerido pelo Alembic (pasta migrations/): corra `alembic upgrade head`.
_connect_args = (
    {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
)
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, connect_args=_connect_args)


def get_db() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
