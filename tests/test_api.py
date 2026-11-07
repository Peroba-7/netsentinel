import pytest

from app.agents import graph
from app.api import threats
from app.core.rate_limit import settings as rate_settings
from app.services.ollama_service import LLMUnavailableError

INCIDENT = {"ip_address": "10.0.0.1", "threat_type": "DDoS", "description": "Tráfego anormal."}


def analyze(client, **overrides):
    return client.post("/threats/analyze", json={**INCIDENT, **overrides})


def test_rejects_missing_api_key(client):
    assert client.get("/threats/", headers={"X-API-Key": ""}).status_code == 403


def test_rejects_wrong_api_key(client):
    assert client.get("/threats/", headers={"X-API-Key": "errada"}).status_code == 403


def test_liveness_is_public(client):
    assert client.get("/", headers={"X-API-Key": ""}).status_code == 200


def test_analyze_saves_and_returns_threat(client):
    response = analyze(client)

    assert response.status_code == 201
    body = response.json()
    assert body["risk_level"] == "ALTO"
    assert body["ai_analysis"] == "Bloquear a origem."
    assert body["status"] == "ANALISADO"
    assert [t["id"] for t in client.get("/threats/").json()] == [body["id"]]


def test_analyze_accepts_ipv6(client):
    assert analyze(client, ip_address="2001:db8::1").json()["ip_address"] == "2001:db8::1"


@pytest.mark.parametrize("field,value", [("ip_address", "999.0.0.1"), ("description", "")])
def test_analyze_rejects_invalid_input(client, field, value):
    assert analyze(client, **{field: value}).status_code == 422


def test_analyze_reports_llm_failure_without_saving(client, monkeypatch):
    def fail(_prompt):
        raise LLMUnavailableError("detalhe interno")

    monkeypatch.setattr(graph, "generate_analysis", fail)

    response = analyze(client)

    assert response.status_code == 503
    assert "interno" not in response.text
    assert client.get("/threats/").json() == []


def test_analyze_queues_notification(client, monkeypatch):
    sent = []
    monkeypatch.setattr(threats, "notify_threat", sent.append)

    analyze(client)

    assert sent[0]["ip_address"] == INCIDENT["ip_address"]


def test_rate_limit_blocks_excess_requests(client, monkeypatch):
    monkeypatch.setattr(rate_settings, "RATE_LIMIT_PER_MINUTE", 1)

    assert analyze(client).status_code == 201
    assert analyze(client).status_code == 429


def test_list_threats_newest_first_and_paginated(client):
    ids = [analyze(client).json()["id"] for _ in range(3)]

    assert [t["id"] for t in client.get("/threats/").json()] == ids[::-1]
    assert [t["id"] for t in client.get("/threats/?limit=1&offset=1").json()] == [ids[1]]


def test_block_marks_threats_as_blocked(client):
    analyze(client)

    response = client.post("/threats/block", json={"ip_address": "10.0.0.1"})

    assert response.status_code == 200
    assert response.json()["dispatched"] is True
    assert response.json()["result"] == "bloqueado (simulado)"
    assert client.get("/threats/").json()[0]["status"] == "BLOQUEADO (SIMULADO)"
    assert [b["ip_address"] for b in client.get("/threats/blocked").json()] == ["10.0.0.1"]


def test_block_reports_failed_dispatch_and_retries(client, monkeypatch):
    monkeypatch.setattr(threats, "dispatch_block", lambda _ip, _reason: None)
    first = client.post("/threats/block", json={"ip_address": "10.0.0.2"})
    assert first.json()["dispatched"] is False

    monkeypatch.setattr(threats, "dispatch_block", lambda _ip, _reason: "bloqueado")
    second = client.post("/threats/block", json={"ip_address": "10.0.0.2"})
    assert second.json()["dispatched"] is True
    assert len(client.get("/threats/blocked").json()) == 1


def test_block_does_not_redispatch_accepted_request(client, monkeypatch):
    client.post("/threats/block", json={"ip_address": "10.0.0.3"})

    def must_not_run(_ip, _reason):
        raise AssertionError("não devia voltar a enviar")

    monkeypatch.setattr(threats, "dispatch_block", must_not_run)

    assert client.post("/threats/block", json={"ip_address": "10.0.0.3"}).status_code == 200


def test_failed_dispatch_does_not_mark_threat_as_blocked(client, monkeypatch):
    monkeypatch.setattr(threats, "dispatch_block", lambda _ip, _reason: None)
    analyze(client)

    client.post("/threats/block", json={"ip_address": "10.0.0.1"})

    assert client.get("/threats/").json()[0]["status"] == "ANALISADO"
