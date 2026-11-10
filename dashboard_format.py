"""Textos da origem dos IPs, partilhados pelas páginas do dashboard."""

# Atribuição exigida pela licença CC BY 4.0 do DB-IP Lite, onde os dados aparecem.
DBIP_ATTRIBUTION = (
    "Origem dos IPs: [IP Geolocation by DB-IP](https://db-ip.com) "
    "(DB-IP Lite, licença [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/))."
)

RESERVED_LABEL = "Rede reservada"


def _present(value) -> bool:
    # O pandas troca os None da API por NaN; NaN é diferente de si próprio.
    return value is not None and value == value and value != ""


def country_label(threat: dict) -> str:
    """Ex.: "BR · Brasil"; "Rede reservada" para IPs privados ou de documentação."""
    if threat.get("ip_scope") == "reservado":
        return RESERVED_LABEL
    code, name = threat.get("country_code"), threat.get("country_name")
    return " · ".join(str(part) for part in (code, name) if _present(part))


def organization_label(threat: dict) -> str:
    """Ex.: "AS64500 · Nome da organização"."""
    asn, org = threat.get("asn"), threat.get("as_org")
    parts = [f"AS{int(asn)}" if _present(asn) else "", str(org) if _present(org) else ""]
    return " · ".join(part for part in parts if part)


def origin_label(threat: dict) -> str:
    """País e organização numa linha, para o detalhe de um incidente."""
    return " — ".join(part for part in (country_label(threat), organization_label(threat)) if part)


def has_origin_data(threats: list[dict]) -> bool:
    return any(_present(t.get("country_code")) or _present(t.get("asn")) for t in threats)
