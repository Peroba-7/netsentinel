"""País e organização (ASN) de um IP, a partir de bases .mmdb locais (DB-IP Lite).

Nenhum IP sai da máquina: a consulta é feita em ficheiros descarregados por
scripts/update-geoip.ps1. Uma base em falta, corrompida ou sem o IP nunca impede a análise:
o incidente fica apenas sem país e organização.
"""

import ipaddress
import logging
import os
import re
import threading
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any

import maxminddb

from app.config import settings

logger = logging.getLogger(__name__)

SCOPE_PUBLIC = "publico"
SCOPE_RESERVED = "reservado"

# Também cobertas por `is_global`, mas listadas para ficar explícito que nunca são consultadas.
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

# O nome da organização é escolhido por quem regista o ASN: é texto de terceiros.
MAX_TEXT_LENGTH = 100
_COUNTRY_CODE = re.compile(r"[A-Z]{2}")
_MAX_ASN = 2**32 - 1


@dataclass(frozen=True)
class IpOrigin:
    ip_scope: str
    country_code: str | None = None
    country_name: str | None = None
    asn: int | None = None
    as_org: str | None = None

    def as_fields(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def has_data(self) -> bool:
        return any((self.country_code, self.country_name, self.asn, self.as_org))


def ip_scope(ip_address: str) -> str:
    """"reservado" para redes privadas, loopback, documentação e afins; senão "publico"."""
    address = ipaddress.ip_address(ip_address)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    reserved = (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or any(address in network for network in DOCUMENTATION_NETWORKS)
    )
    return SCOPE_RESERVED if reserved else SCOPE_PUBLIC


def clean_text(value: Any) -> str | None:
    """Texto numa só linha, sem caracteres de controlo nem de formatação, e com tamanho limitado.

    Impede que um nome vindo da base crie linhas falsas no prompt ou esconda texto
    (por exemplo, com caracteres de inversão de direção).
    """
    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFKC", value)
    text = "".join(" " if unicodedata.category(char).startswith("C") else char for char in text)
    text = " ".join(text.split())[:MAX_TEXT_LENGTH].strip()
    return text or None


def _clean_country_code(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    code = value.strip().upper()
    return code if _COUNTRY_CODE.fullmatch(code) else None


def _clean_asn(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 < value <= _MAX_ASN else None


class LocalDatabase:
    """Uma base .mmdb lida para memória e reaberta quando o ficheiro muda.

    MODE_MEMORY (cerca de 10 MB por base) em vez de mmap: o ficheiro pode ser substituído pelo
    script de atualização sem ficar preso pela API.
    """

    def __init__(self, label: str, path_setting: str):
        self.label = label
        self._path_setting = path_setting
        self._reader: maxminddb.Reader | None = None
        self._loaded_mtime: int | None = None
        self._warned: tuple | None = None
        self._lock = threading.Lock()

    @property
    def path(self) -> str:
        return getattr(settings, self._path_setting)

    def _warn_once(self, key: tuple, message: str, *args) -> None:
        if self._warned != key:
            self._warned = key
            logger.warning(message, *args)

    def _close(self) -> None:
        if self._reader is not None:
            self._reader.close()
        self._reader = None
        self._loaded_mtime = None

    def _ensure_loaded(self, path: str) -> bool:
        try:
            mtime = os.stat(path).st_mtime_ns
        except OSError:
            self._close()
            self._warn_once(
                ("missing", path),
                "Base %s não encontrada em %s; os incidentes ficam sem esse dado.",
                self.label,
                path,
            )
            return False
        if self._reader is not None and mtime == self._loaded_mtime:
            return True
        self._close()
        try:
            self._reader = maxminddb.open_database(path, maxminddb.MODE_MEMORY)
        except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
            self._warn_once(("invalid", path, mtime), "Base %s inválida: %s", self.label, exc)
            return False
        self._loaded_mtime = mtime
        self._warned = None
        metadata = self._reader.metadata()
        logger.info(
            "Base %s carregada: %s, gerada em %s.",
            self.label,
            metadata.database_type,
            metadata.build_epoch,
        )
        return True

    def get(self, ip_address: str) -> dict | None:
        path = self.path
        if not path:
            return None
        with self._lock:
            if not self._ensure_loaded(path):
                return None
            try:
                record = self._reader.get(ip_address)
            except (ValueError, maxminddb.InvalidDatabaseError) as exc:
                logger.warning("Consulta à base %s falhou: %s", self.label, exc)
                return None
        return record if isinstance(record, dict) else None


country_database = LocalDatabase("de países", "GEOIP_COUNTRY_DB")
asn_database = LocalDatabase("de ASN", "GEOIP_ASN_DB")


def _country_fields(record: dict | None) -> tuple[str | None, str | None]:
    country = (record or {}).get("country")
    if not isinstance(country, dict):
        return None, None
    names = country.get("names")
    names = names if isinstance(names, dict) else {}
    name = clean_text(names.get("pt-BR")) or clean_text(names.get("en"))
    return _clean_country_code(country.get("iso_code")), name


def lookup(ip_address: str) -> IpOrigin:
    """Origem de um IP. Nunca levanta exceções: na dúvida, devolve só o âmbito."""
    try:
        scope = ip_scope(ip_address)
    except ValueError:
        return IpOrigin(SCOPE_PUBLIC)
    if scope == SCOPE_RESERVED:
        # Redes privadas e de documentação não estão nas bases: nem se consulta.
        return IpOrigin(SCOPE_RESERVED)

    address = ipaddress.ip_address(ip_address)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        ip_address = str(address.ipv4_mapped)
    try:
        country_code, country_name = _country_fields(country_database.get(ip_address))
        asn_record = asn_database.get(ip_address) or {}
        return IpOrigin(
            ip_scope=SCOPE_PUBLIC,
            country_code=country_code,
            country_name=country_name,
            asn=_clean_asn(asn_record.get("autonomous_system_number")),
            as_org=clean_text(asn_record.get("autonomous_system_organization")),
        )
    except Exception:  # a origem é um extra: nunca pode impedir a análise
        logger.exception("Falha inesperada ao consultar a origem do IP.")
        return IpOrigin(SCOPE_PUBLIC)
