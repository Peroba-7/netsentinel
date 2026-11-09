"""Autenticação da API: sessões de utilizador (Bearer) ou a chave de serviço (X-API-Key).

As permissões são verificadas aqui, na API, e não só no dashboard: quem chamar a API
diretamente tem as mesmas regras.
"""

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.security.api_key import APIKeyHeader
from sqlmodel import Session

from app.config import settings
from app.db.database import get_db
from app.schemas.user import role_at_least
from app.services.auth_service import user_for_token

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer = HTTPBearer(auto_error=False)

SERVICE_ACCOUNT = "chave-de-servico"


@dataclass(frozen=True)
class Principal:
    """Quem fez o pedido: um utilizador com sessão, ou a chave de serviço (acesso total)."""

    username: str
    role: str
    user_id: int | None = None
    token: str | None = None


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sessão inválida ou expirada. Inicie sessão novamente.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_principal(
    api_key: str | None = Security(api_key_header),
    credentials: HTTPAuthorizationCredentials | None = Security(bearer),
    db: Session = Depends(get_db),
) -> Principal:
    if api_key is not None:
        # Uma chave errada é recusada, mesmo que também venha um token válido.
        if settings.API_KEY and secrets.compare_digest(
            api_key.encode(), settings.API_KEY.encode()
        ):
            return Principal(username=SERVICE_ACCOUNT, role="admin")
        raise _unauthorized()

    if credentials is not None:
        user = user_for_token(db, credentials.credentials)
        if user is not None:
            return Principal(
                username=user.username,
                role=user.role,
                user_id=user.id,
                token=credentials.credentials,
            )
    raise _unauthorized()


def require_role(minimum: str) -> Callable[..., Principal]:
    """Dependência que exige pelo menos este perfil (leitor < analista < admin)."""

    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not role_at_least(principal.role, minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="O seu perfil não tem permissão para esta ação.",
            )
        return principal

    return dependency
