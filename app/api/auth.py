from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlmodel import Session

from app.core.security import Principal, get_principal
from app.db.database import get_db
from app.schemas.user import LoginRequest, LoginResponse
from app.services.auth_service import LoginLockedError, authenticate, create_session, end_session

router = APIRouter(prefix="/auth", tags=["Auth"])

# A mesma mensagem para utilizador inexistente, desativado ou palavra-passe errada.
INVALID_LOGIN = "Utilizador ou palavra-passe inválidos."
LOCKED_LOGIN = "Demasiadas tentativas falhadas. Tente novamente mais tarde."


@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    try:
        user = authenticate(db, request.username, request.password)
    except LoginLockedError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=LOCKED_LOGIN
        ) from exc
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_LOGIN)

    session = create_session(db, user)
    return LoginResponse(
        token=session.token, expires_at=session.expires_at, username=user.username, role=user.role
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    if principal.token:
        end_session(db, principal.token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me")
def me(principal: Principal = Depends(get_principal)):
    return {"username": principal.username, "role": principal.role}
