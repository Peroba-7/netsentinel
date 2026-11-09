"""Hash de palavras-passe com argon2id."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Parâmetros predefinidos do argon2-cffi (argon2id, recomendados pela RFC 9106).
_hasher = PasswordHasher()
_dummy_hash: str | None = None


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def burn_verification_time(password: str) -> None:
    """Faz uma verificação falsa, com o mesmo custo de uma verdadeira.

    Usada quando o utilizador não existe ou está bloqueado: sem ela, a resposta mais rápida
    revelaria que o nome não corresponde a uma conta.
    """
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = _hasher.hash("palavra-passe-inexistente")
    verify_password(_dummy_hash, password)
