"""Correção de "a IP" para "o IP" no parecer da IA."""

import json

import pytest

from app.agents import graph
from app.agents.text_fixes import fix_ip_gender


@pytest.mark.parametrize(
    "wrong,right",
    [
        ("Bloquear a IP de origem.", "Bloquear o IP de origem."),
        ("A atividade da IP é suspeita.", "A atividade do IP é suspeita."),
        ("Aplicar regras à IP externa.", "Aplicar regras ao IP externa."),
        ("Foram vistas falhas na IP.", "Foram vistas falhas no IP."),
        ("Acessos feitos pela IP desconhecida.", "Acessos feitos pelo IP desconhecida."),
        ("Esta IP tentou 480 logins.", "Este IP tentou 480 logins."),
        ("Vigiar essa IP.", "Vigiar esse IP."),
        ("O tráfego dessa IP parou.", "O tráfego desse IP parou."),
        ("Os pedidos desta IP foram bloqueados.", "Os pedidos deste IP foram bloqueados."),
    ],
)
def test_each_feminine_form_becomes_masculine(wrong, right):
    assert fix_ip_gender(wrong) == right


@pytest.mark.parametrize(
    "wrong,right",
    [
        ("A IP 203.0.113.7 fez 480 tentativas.", "O IP 203.0.113.7 fez 480 tentativas."),
        ("Da IP de origem vieram 480 pedidos.", "Do IP de origem vieram 480 pedidos."),
        ("À IP foi aplicado um bloqueio.", "Ao IP foi aplicado um bloqueio."),
        ("Na IP não há registos.", "No IP não há registos."),
        ("Pela IP passaram 2 GB.", "Pelo IP passaram 2 GB."),
        ("Esta IP é externa.", "Este IP é externa."),
        ("Essa IP é nova.", "Esse IP é nova."),
        ("Dessa IP vieram falhas.", "Desse IP vieram falhas."),
        ("Desta IP vieram falhas.", "Deste IP vieram falhas."),
        ("BLOQUEAR DA IP", "BLOQUEAR DO IP"),
        ("Tudo veio DESTA IP.", "Tudo veio DESTE IP."),
    ],
)
def test_capital_letters_are_kept(wrong, right):
    assert fix_ip_gender(wrong) == right


def test_several_forms_and_punctuation_in_one_text():
    text = "Bloquear a IP. Vigiar esta IP, e rever os logs da IP:\nna IP\tnão há sucesso."

    assert fix_ip_gender(text) == (
        "Bloquear o IP. Vigiar este IP, e rever os logs do IP:\nno IP\tnão há sucesso."
    )


@pytest.mark.parametrize(
    "text",
    [
        "Migrar a IPv6 em breve.",  # "IP" seguido de mais letras
        "Bloquear a IPs externos.",
        "Rever a IP-table.",
        "Enviar para IP externo.",  # "a" dentro de "para"
        "Nada a fazer na rede.",
        "Uma IP interna.",  # "uma" não está na lista
        "Bloquear o IP de origem.",  # já correto
        "Vigiar este IP e esse IP.",
        "Bloquear a ip de origem.",  # "ip" em minúsculas não é tocado
        "A firewall bloqueou a origem.",
        "Rever o campo IP da tabela.",
        "",
    ],
)
def test_text_that_must_not_change(text):
    assert fix_ip_gender(text) == text


def test_analysis_is_fixed_before_it_leaves_the_graph(monkeypatch):
    answer = {"analysis": "Bloquear a IP e vigiar esta IP.", "risk_level": "ALTO"}
    monkeypatch.setattr(graph, "generate_analysis", lambda _messages: json.dumps(answer))

    result = graph.threat_graph.invoke(
        {
            "ip_address": "203.0.113.7",
            "threat_type": "Brute Force",
            "description": "480 falhas.",
            "risk_level": "INDETERMINADO",
            "ai_analysis": "",
        }
    )

    assert result["ai_analysis"] == "Bloquear o IP e vigiar este IP."
    assert result["risk_level"] == "ALTO"


def test_fixed_analysis_is_what_the_api_saves(client, monkeypatch):
    answer = {"analysis": "Bloquear a IP de origem.", "risk_level": "ALTO"}
    monkeypatch.setattr(graph, "generate_analysis", lambda _messages: json.dumps(answer))

    body = client.post(
        "/threats/analyze",
        json={"ip_address": "203.0.113.7", "threat_type": "DDoS", "description": "x"},
    ).json()

    assert body["ai_analysis"] == "Bloquear o IP de origem."
    assert client.get(f"/threats/{body['id']}").json()["ai_analysis"] == body["ai_analysis"]
