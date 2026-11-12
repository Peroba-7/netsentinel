"""Correções determinísticas ao texto do parecer da IA, aplicadas antes de o guardar."""

import re

# "IP" é masculino em português; o modelo às vezes o escreve no feminino.
_IP_GENDER = {
    "a": "o",
    "da": "do",
    "à": "ao",
    "na": "no",
    "pela": "pelo",
    "esta": "este",
    "essa": "esse",
    "dessa": "desse",
    "desta": "deste",
}

# Só palavras inteiras: o artigo não pode estar colado a outra palavra ("para IP" fica igual)
# e "IP" não pode continuar ("a IPv6", "a IPs" ficam iguais). "IP" tem de estar em maiúsculas.
_IP_GENDER_PATTERN = re.compile(
    r"(?<![\w-])(?i:(" + "|".join(sorted(_IP_GENDER, key=len, reverse=True)) + r"))"
    r"(\s+)IP(?![\w-])"
)


def _same_case(original: str, replacement: str) -> str:
    """Mantém "DA" em maiúsculas e "Da"/"A"/"À" com inicial maiúscula."""
    if len(original) > 1 and original.isupper():
        return replacement.upper()
    if original[0].isupper():
        return replacement[0].upper() + replacement[1:]
    return replacement


def _replace(match: re.Match) -> str:
    article, spaces = match.group(1), match.group(2)
    return f"{_same_case(article, _IP_GENDER[article.lower()])}{spaces}IP"


def fix_ip_gender(text: str) -> str:
    """Corrige "a IP" para "o IP", "da IP" para "do IP", e assim por diante."""
    return _IP_GENDER_PATTERN.sub(_replace, text)
