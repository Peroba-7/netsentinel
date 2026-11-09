from datetime import UTC, datetime, timedelta

import pytest

from app.agents import graph
from app.api import threats
from app.core.rate_limit import settings as rate_settings
from app.services.ollama_service import LLMUnavailableError

INCIDENT = {"ip_address": "10.0.0.1", "threat_type": "DDoS", "description": "Tráfego anormal."}


def analyze(client, **overrides):
    return client.post("/threats/analyze", json={**INCIDENT, **overrides})


def test_rejects_missing_api_key(client):
    assert client.get("/threats/", headers={"X-API-Key": ""}).status_code == 401


def test_rejects_wrong_api_key(client):
    assert client.get("/threats/", headers={"X-API-Key": "errada"}).status_code == 401


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


def test_block_marks_ip_as_blocked_but_keeps_incident_status(client):
    analyze(client)

    response = client.post("/threats/block", json={"ip_address": "10.0.0.1"})

    assert response.status_code == 200
    assert response.json()["dispatched"] is True
    assert response.json()["result"] == "bloqueado (simulado)"
    threat = client.get("/threats/").json()[0]
    assert threat["status"] == "ANALISADO"
    assert threat["ip_blocked"] is True
    assert threat["ip_block_result"] == "bloqueado (simulado)"
    assert [b["ip_address"] for b in client.get("/threats/blocked").json()] == ["10.0.0.1"]


def test_ip_block_applies_to_every_incident_of_that_ip_only(client):
    analyze(client, ip_address="10.0.0.1")
    analyze(client, ip_address="10.0.0.1", threat_type="Port Scan")
    analyze(client, ip_address="10.0.0.2")

    client.post("/threats/block", json={"ip_address": "10.0.0.1"})

    threats_list = client.get("/threats/").json()
    by_ip = [(t["ip_address"], t["status"], t["ip_blocked"]) for t in threats_list]
    assert by_ip == [
        ("10.0.0.2", "ANALISADO", False),
        ("10.0.0.1", "ANALISADO", True),
        ("10.0.0.1", "ANALISADO", True),
    ]


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

    threat = client.get("/threats/").json()[0]
    assert threat["status"] == "ANALISADO"
    assert threat["ip_blocked"] is False
    assert threat["ip_block_result"] is None


def test_get_threat_by_id(client):
    created = analyze(client).json()

    assert client.get(f"/threats/{created['id']}").json()["id"] == created["id"]
    assert client.get("/threats/9999").status_code == 404


def test_list_filters_by_risk_ip_and_text(client, monkeypatch):
    analyze(client, ip_address="10.0.0.1", threat_type="DDoS", description="Tráfego anormal.")
    monkeypatch.setattr(
        graph, "generate_analysis", lambda _p: '{"risk_level": "BAIXO", "analysis": "x"}'
    )
    analyze(client, ip_address="10.0.0.2", threat_type="Port Scan", description="50 portas")

    def ips(query):
        return [t["ip_address"] for t in client.get(f"/threats/?{query}").json()]

    assert ips("risk_level=ALTO") == ["10.0.0.1"]
    assert ips("risk_level=BAIXO") == ["10.0.0.2"]
    assert ips("ip_address=10.0.0.2") == ["10.0.0.2"]
    assert ips("search=port") == ["10.0.0.2"]
    assert ips("search=TRÁFEGO") == ["10.0.0.1"]
    assert ips("search=100%25") == []


def test_list_rejects_invalid_filters(client):
    assert client.get("/threats/?risk_level=ENORME").status_code == 422
    assert client.get("/threats/?ip_address=999.0.0.1").status_code == 422


def test_unblock_removes_accepted_block(client, monkeypatch):
    analyze(client)
    client.post("/threats/block", json={"ip_address": "10.0.0.1"})
    monkeypatch.setattr(threats, "dispatch_unblock", lambda _ip: "desbloqueado (simulado)")

    response = client.delete("/threats/block/10.0.0.1")

    assert response.status_code == 200
    assert response.json() == {"ip_address": "10.0.0.1", "result": "desbloqueado (simulado)"}
    assert client.get("/threats/blocked").json() == []
    assert client.get("/threats/").json()[0]["ip_blocked"] is False


def test_unblock_keeps_block_if_n8n_does_not_accept(client, monkeypatch):
    client.post("/threats/block", json={"ip_address": "10.0.0.1"})
    monkeypatch.setattr(threats, "dispatch_unblock", lambda _ip: None)

    assert client.delete("/threats/block/10.0.0.1").status_code == 503
    assert len(client.get("/threats/blocked").json()) == 1


def test_unblock_of_unaccepted_request_does_not_call_n8n(client, monkeypatch):
    monkeypatch.setattr(threats, "dispatch_block", lambda _ip, _reason: None)
    client.post("/threats/block", json={"ip_address": "10.0.0.1"})

    def must_not_run(_ip):
        raise AssertionError("não devia contactar o n8n")

    monkeypatch.setattr(threats, "dispatch_unblock", must_not_run)

    assert client.delete("/threats/block/10.0.0.1").status_code == 200
    assert client.get("/threats/blocked").json() == []


def test_unblock_unknown_ip_returns_404(client):
    assert client.delete("/threats/block/10.0.0.9").status_code == 404
    assert client.delete("/threats/block/999.0.0.1").status_code == 422



@pytest.mark.parametrize(
    "sent,saved",
    [
        ("brute force", "Brute Force"),
        ("  SSH   Brute Force ", "Brute Force"),
        ("ddos", "DDoS"),
        ("port-scan", "Port Scan"),
        ("  SQL   Injection ", "SQL Injection"),
    ],
)
def test_analyze_normalizes_threat_type(client, sent, saved):
    response = analyze(client, threat_type=sent)

    assert response.status_code == 201
    assert response.json()["threat_type"] == saved
    assert client.get("/threats/").json()[0]["threat_type"] == saved


def test_analyze_rejects_blank_threat_type(client):
    assert analyze(client, threat_type="   ").status_code == 422


def test_block_saves_reason_and_sends_it_to_n8n(client, monkeypatch):
    sent = []
    monkeypatch.setattr(
        threats, "dispatch_block", lambda ip, reason: sent.append((ip, reason)) or "bloqueado"
    )

    response = client.post(
        "/threats/block", json={"ip_address": "10.0.0.1", "reason": "DDoS, risco ALTO"}
    )

    assert response.json()["reason"] == "DDoS, risco ALTO"
    assert sent == [("10.0.0.1", "DDoS, risco ALTO")]


def test_block_retry_updates_missing_reason(client, monkeypatch):
    monkeypatch.setattr(threats, "dispatch_block", lambda _ip, _reason: None)
    client.post("/threats/block", json={"ip_address": "10.0.0.2"})

    monkeypatch.setattr(threats, "dispatch_block", lambda _ip, _reason: "bloqueado")
    retry = client.post(
        "/threats/block", json={"ip_address": "10.0.0.2", "reason": "Port Scan, risco MÉDIO"}
    )

    assert retry.json()["reason"] == "Port Scan, risco MÉDIO"


def test_block_without_duration_is_permanent(client):
    response = client.post("/threats/block", json={"ip_address": "10.0.0.1"})

    assert response.json()["expires_at"] is None


def test_block_with_duration_sets_expiry(client):
    before = datetime.now(UTC)

    response = client.post(
        "/threats/block", json={"ip_address": "10.0.0.1", "duration_minutes": 30}
    )

    expires_at = datetime.fromisoformat(response.json()["expires_at"])
    assert before + timedelta(minutes=30) <= expires_at <= datetime.now(UTC) + timedelta(minutes=30)
    assert client.get("/threats/blocked").json()[0]["expires_at"] is not None


@pytest.mark.parametrize("minutes", [0, -5, 10081, "muito"])
def test_block_rejects_invalid_duration(client, minutes):
    response = client.post(
        "/threats/block", json={"ip_address": "10.0.0.1", "duration_minutes": minutes}
    )

    assert response.status_code == 422
    assert client.get("/threats/blocked").json() == []


def test_block_accepts_maximum_duration(client):
    response = client.post(
        "/threats/block", json={"ip_address": "10.0.0.1", "duration_minutes": 10080}
    )

    assert response.status_code == 200
