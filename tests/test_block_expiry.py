import asyncio
from datetime import timedelta

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.db.models import BlockedIPModel, utcnow
from app.services import block_expiry


@pytest.fixture
def engine():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture
def unblocks(monkeypatch):
    """Simula o n8n; os testes alteram `response` e consultam `calls`."""
    state = {"response": "desbloqueado (simulado)", "calls": []}

    def fake_dispatch_unblock(ip_address):
        state["calls"].append(ip_address)
        return state["response"]

    monkeypatch.setattr(block_expiry, "dispatch_unblock", fake_dispatch_unblock)
    return state


def add_block(engine, ip_address, minutes_left, dispatched=True):
    expires_at = None if minutes_left is None else utcnow() + timedelta(minutes=minutes_left)
    with Session(engine) as db:
        db.add(BlockedIPModel(ip_address=ip_address, dispatched=dispatched, expires_at=expires_at))
        db.commit()


def remaining(engine):
    with Session(engine) as db:
        return sorted(db.exec(select(BlockedIPModel.ip_address)).all())


def expire(engine):
    with Session(engine) as db:
        return block_expiry.expire_blocks(db)


def test_expired_block_is_unblocked_and_removed(engine, unblocks):
    add_block(engine, "10.0.0.1", minutes_left=-1)

    assert expire(engine) == 1
    assert unblocks["calls"] == ["10.0.0.1"]
    assert remaining(engine) == []


def test_active_and_permanent_blocks_are_untouched(engine, unblocks):
    add_block(engine, "10.0.0.1", minutes_left=30)
    add_block(engine, "10.0.0.2", minutes_left=None)

    assert expire(engine) == 0
    assert unblocks["calls"] == []
    assert remaining(engine) == ["10.0.0.1", "10.0.0.2"]


def test_n8n_failure_keeps_block_for_retry(engine, unblocks):
    add_block(engine, "10.0.0.1", minutes_left=-1)
    unblocks["response"] = None

    assert expire(engine) == 0
    assert remaining(engine) == ["10.0.0.1"]

    unblocks["response"] = "desbloqueado (simulado)"
    assert expire(engine) == 1
    assert unblocks["calls"] == ["10.0.0.1", "10.0.0.1"]
    assert remaining(engine) == []


def test_failure_on_one_ip_does_not_stop_the_others(engine, unblocks, monkeypatch):
    add_block(engine, "10.0.0.1", minutes_left=-2)
    add_block(engine, "10.0.0.2", minutes_left=-1)
    monkeypatch.setattr(
        block_expiry,
        "dispatch_unblock",
        lambda ip: None if ip == "10.0.0.1" else "desbloqueado (simulado)",
    )

    assert expire(engine) == 1
    assert remaining(engine) == ["10.0.0.1"]


def test_expired_block_never_accepted_is_removed_without_n8n(engine, unblocks):
    add_block(engine, "10.0.0.1", minutes_left=-1, dispatched=False)

    assert expire(engine) == 1
    assert unblocks["calls"] == []
    assert remaining(engine) == []


def test_run_once_logs_errors_instead_of_raising(caplog):
    broken = create_engine("sqlite://")  # sem tabelas

    block_expiry.run_expiry_once(broken)

    assert "Falha ao verificar bloqueios expirados" in caplog.text


def test_loop_runs_until_cancelled(monkeypatch):
    runs = []
    monkeypatch.setattr(block_expiry, "run_expiry_once", lambda engine: runs.append(engine))

    async def run_briefly():
        task = asyncio.create_task(block_expiry.expiry_loop("engine", 0.01))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run_briefly())

    assert len(runs) >= 2
