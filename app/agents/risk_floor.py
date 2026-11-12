"""Nível mínimo de risco a partir de sinais objetivos na descrição do incidente.

Rede de segurança para a classificação da IA: se a descrição tiver sinais claros de
comprometimento, o nível final não fica abaixo de um mínimo, mesmo que o modelo tenha sido
manipulado pelo texto do incidente. As regras só sobem o nível, nunca o baixam.

Os sinais reconhecem termos de Portugal e do Brasil. São de alta precisão: regras de CRÍTICO
exigem dois ou mais sinais na mesma frase, e há exceções para negação e origem conhecida.
O campo "Tipo" não é usado, porque é só a suspeita de quem registrou o incidente.
"""

import re
import unicodedata
from dataclasses import dataclass

UNKNOWN = "INDETERMINADO"
_ORDER = {UNKNOWN: -1, "BAIXO": 0, "MÉDIO": 1, "ALTO": 2, "CRÍTICO": 3}

SUCCESS_AFTER_FAILURES_MIN = 20
MASS_FAILURES_MIN = 100

_NEGATIONS = {
    "sem", "nao", "nenhum", "nenhuma", "nunca", "jamais", "ninguem", "nem",
    # "A firewall bloqueou o acesso com sucesso" não é um login conseguido.
    "bloqueou", "bloquearam", "impediu", "impediram", "negou", "recusou", "barrou",
    "blocked", "denied", "prevented",
}
_NEGATION_WINDOW = 4  # palavras antes do sinal

# Números como 650, 1.200, 1 200 ou 1200; não pega partes de um endereço IP.
_NUMBER = r"(?<![\d.])(\d{1,3}(?:[. ]\d{3})+|\d+)(?![\d]|\.\d)"
_COUNT = re.compile(
    _NUMBER + r"\s+(?:[a-z-]+\s+){0,3}?"
    r"(?:tentativas|falhas|erros|attempts|failures|failed|"
    r"logins?\s+(?:falhad|invalid|errad|com\s+falha))"
)

_SUCCESS = re.compile(
    r"\b(?:"
    r"(?:entrou|entraram|login|logon|logou|logaram|acesso|acessou|acessaram|autenticou|"
    r"autenticaram|autenticacao|sessao)\s+(?:[a-z0-9-]+\s+){0,3}?com\s+sucesso"
    r"|conseguiu\s+(?:entrar|acesso|acessar|autenticar|fazer\s+login)"
    r"|obteve\s+acesso|teve\s+sucesso|bem[- ]sucedid[oa]s?"
    r"|logged\s+in|successful(?:ly)?\s+log"
    r")"
)

_KNOWN_ORIGIN = re.compile(
    r"\b(?:habitual|vpn\s+(?:da\s+empresa|corporativa)|"
    r"(?:ip|rede|posto|computador)\s+do\s+escritorio|a\s+partir\s+do\s+escritorio|"
    r"propri[oa]\s+(?:utilizador|utilizadora|usuario|usuaria)|"
    r"ip\s+conhecido|origem\s+conhecida|rede\s+interna\s+da\s+empresa)\b"
)

_PRIVILEGED = re.compile(
    r"\b(?:root|admin|admins|administrador(?:a|es)?|administrator|conta\s+de\s+servico|"
    r"domain\s+admins?|superusuario|superutilizador)\b"
)
_ATTACKER_ACTION = re.compile(
    r"(?:cri(?:ou|aram|acao\s+de)\s+(?:um\s+|uma\s+)?(?:nov[oa]s?\s+)?"
    r"(?:utilizador|usuario|conta|user)"
    r"|alter(?:ou|aram|acao\s+d[aoe]s?)\s+(?:as\s+)?permiss"
    r"|(?:elevou|escalou|elevacao\s+de|escalada\s+de|escalonamento\s+de)\s+(?:os\s+)?privilegi"
    r"|adicion(?:ou|aram)\s+.{0,40}\bgrupo"
    r"|desativ(?:ou|aram)\s+(?:o\s+|a\s+|os\s+)?(?:antivirus|edr|auditoria|registos?|registros?|logs?)"
    r"|apag(?:ou|aram)\s+(?:os\s+)?(?:logs|registos|registros))"
)
# Sem um destes, criar usuários ou mudar permissões é trabalho normal de administração.
_SUSPICIOUS_ORIGIN = re.compile(
    r"\b(?:atacante|invasor|intruso|hacker|desconhecid[oa]s?|estrangeir[oa]s?|"
    r"nao\s+autorizad[oa]s?|sem\s+autorizacao|comprometid[oa]s?|malicios[oa]s?)\b"
)

_RANSOM = re.compile(
    r"\b(?:nota\s+de\s+resgate|pedido\s+de\s+resgate|ransom\s+note)\b"
    r"|\b(?:ficheiros|arquivos|files|documentos|dados)\b.{0,60}?"
    r"\b(?:a\s+ser|sendo|foram|estao\s+a\s+ser|comecaram\s+a\s+ser|being|were)\s+"
    r"(?:[a-z]+\s+)?(?:cifrad|encriptad|criptografad|encrypted)"
)

_MALWARE = re.compile(
    r"\b(?:malware|trojan|troiano|cavalo\s+de\s+troia|virus|worm|backdoor|keylogger|"
    r"spyware|ransomware)\b"
)
_ACTIVE = re.compile(
    r"\b(?:em\s+execucao|a\s+correr|executando|rodando|esta\s+ativo|"
    r"tenta\s+(?:ligar-se|se\s+ligar|conectar-se|se\s+conectar|comunicar)|a\s+ligar-se|"
    r"ligou-se\s+a|conectou-se\s+a|comunica(?:ndo)?\s+com)\b"
)

_PHISHING = re.compile(
    r"\b(?:phishing|link\s+(?:falso|malicioso)|pagina\s+falsa|site\s+falso|e-?mail\s+falso)"
)
_CREDENTIALS_ENTERED = re.compile(
    r"\b(?:introduziu|introduziram|digitou|digitaram|inseriu|inseriram|forneceu|forneceram|"
    r"preencheu|entregou|submeteu|colocou)\s+(?:[a-z-]+\s+){0,3}?"
    r"(?:palavras?-passe|senhas?|credenciais|password)"
)

_MANIPULATION = [
    re.compile(
        r"\bignor(?:a|e|ar|em)\s+(?:todas\s+|all\s+)?(?:as\s+|os\s+|the\s+)?(?:[a-z]+\s+)?"
        r"(?:regras|instrucoes|criterios|instructions|rules)\b"
    ),
    re.compile(
        r"\b(?:classifica|classifique|classificar|classify)(?:-o|-a|-lo|-la)?\s+"
        r"(?:[a-z]+\s+){0,3}?(?:como|as)\s+(?:baixo|medio|alto|critico|low|medium|high)\b"
    ),
    re.compile(r"\b(?:responde|responda|responder|respond|reply)\s+(?:apenas|somente|so|only)\b"),
    re.compile(r"risk_level"),
    re.compile(
        r"\b(?:nota|instrucao|instrucoes)\s+(?:para|ao|a)\s+(?:o\s+)?"
        r"(?:sistema\s+de\s+analise|modelo|ia|assistente|analisador)\b"
    ),
]


@dataclass(frozen=True)
class Signal:
    rule: str
    minimum: str
    reason: str  # em português do Brasil, sem copiar a descrição


@dataclass(frozen=True)
class FloorResult:
    risk_level: str
    model_risk_level: str
    signals: tuple[Signal, ...]

    @property
    def adjusted(self) -> bool:
        return self.risk_level != self.model_risk_level


def normalize(text: str) -> str:
    """Minúsculas, sem acentos e com os espaços arrumados."""
    decomposed = unicodedata.normalize("NFD", text or "")
    plain = "".join(char for char in decomposed if unicodedata.category(char) != "Mn")
    return " ".join(plain.lower().split())


def _sentences(text: str) -> list[str]:
    # O ponto só separa frases quando não está entre algarismos (1.200 ou 203.0.113.7).
    return [part.strip() for part in re.split(r"[!?;\n]+|\.(?!\d)", text) if part.strip()]


def _negated(text: str, start: int, span: str = "") -> bool:
    words = re.findall(r"[a-z0-9-]+", text[:start])[-_NEGATION_WINDOW:]
    return any(word in _NEGATIONS for word in words) or any(
        word in _NEGATIONS for word in re.findall(r"[a-z0-9-]+", span)
    )


def _find(pattern: re.Pattern, text: str, *, check_inside: bool = False) -> bool:
    """Há uma ocorrência do sinal que não esteja negada?"""
    for match in pattern.finditer(text):
        if not _negated(text, match.start(), match.group(0) if check_inside else ""):
            return True
    return False


def _max_count(text: str) -> int:
    counts = [int(re.sub(r"[. ]", "", match.group(1))) for match in _COUNT.finditer(text)]
    return max(counts, default=0)


def find_signals(description: str) -> tuple[Signal, ...]:
    text = normalize(description)
    found: dict[str, Signal] = {}

    def add(rule: str, minimum: str, reason: str) -> None:
        found.setdefault(rule, Signal(rule, minimum, reason))

    for sentence in _sentences(text):
        count = _max_count(sentence)
        known_origin = bool(_KNOWN_ORIGIN.search(sentence))
        success = _find(_SUCCESS, sentence)

        if success and count >= SUCCESS_AFTER_FAILURES_MIN and not known_origin:
            add("sucesso_apos_falhas", "CRÍTICO", f"login com sucesso depois de {count} falhas")
        if (
            not known_origin
            and _PRIVILEGED.search(sentence)
            and _find(_ATTACKER_ACTION, sentence)
            and (
                _SUSPICIOUS_ORIGIN.search(sentence)
                or (success and count >= SUCCESS_AFTER_FAILURES_MIN)
            )
        ):
            add(
                "conta_privilegiada_usada",
                "CRÍTICO",
                "conta privilegiada usada para uma ação típica de atacante, a partir de origem "
                "suspeita",
            )
        if _find(_RANSOM, sentence, check_inside=True):
            add("ransomware", "CRÍTICO", "arquivos sendo criptografados ou nota de resgate")
        if count >= MASS_FAILURES_MIN:
            add("falhas_em_massa", "ALTO", f"{count} falhas ou tentativas de login")
        if _MALWARE.search(sentence) and _find(_ACTIVE, sentence):
            add(
                "malware_ativo",
                "ALTO",
                "malware em execução ou se comunicando com servidor externo",
            )
        if _PHISHING.search(text) and _find(_CREDENTIALS_ENTERED, sentence):
            add("credenciais_introduzidas", "ALTO", "senha ou credenciais digitadas em phishing")

    if any(pattern.search(text) for pattern in _MANIPULATION):
        add(
            "tentativa_de_manipulacao",
            "MÉDIO",
            "a descrição contém instruções dirigidas ao sistema de análise",
        )
    return tuple(found.values())


def apply_risk_floor(description: str, risk_level: str) -> FloorResult:
    """Sobe o nível até o mínimo exigido pelos sinais; nunca o baixa."""
    signals = find_signals(description)
    final = risk_level
    if signals:
        floor = max((signal.minimum for signal in signals), key=_ORDER.__getitem__)
        if _ORDER.get(risk_level, -1) < _ORDER[floor]:
            final = floor
    return FloorResult(risk_level=final, model_risk_level=risk_level, signals=signals)


def floor_note(result: FloorResult) -> str:
    """Nota acrescentada ao parecer quando o nível sobe (em português do Brasil)."""
    before = result.model_risk_level
    if before == UNKNOWN:
        before = "INDETERMINADO (resposta da IA fora do formato)"
    reasons = "; ".join(signal.reason for signal in result.signals)
    return (
        f"Nível ajustado automaticamente de {before} para {result.risk_level} por regras fixas "
        f"do sistema. Motivo: {reasons}. O parecer acima pode ter sido influenciado pelo texto "
        "do incidente; revise antes de tomar qualquer decisão."
    )
