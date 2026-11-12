"""Usuários, login, sessões e limite de tentativas."""

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlmodel import Session, col, delete, select

from app.config import settings
from app.core.passwords import burn_verification_time, hash_password, verify_password
from app.db.models import LoginAttemptModel, UserModel, UserSessionModel, utcnow
from app.schemas.user import MIN_PASSWORD_LENGTH, ROLES, USERNAME_PATTERN


class LoginLockedError(Exception):
    """Muitas tentativas malsucedidas para este nome de usuário."""


class UserError(ValueError):
    """Pedido inválido sobre usuários; a mensagem pode ser mostrada a quem o fez."""


@dataclass
class NewSession:
    token: str
    expires_at: datetime
    user: UserModel


def normalize_username(username: str) -> str:
    return username.strip().lower()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --- Login e sessões --------------------------------------------------------------------------


def authenticate(
    db: Session, username: str, password: str, now: datetime | None = None
) -> UserModel | None:
    """Devolve o utilizador se o login for válido; None se não for.

    Lança LoginLockedError durante o bloqueio, mesmo com a palavra-passe certa. As tentativas
    contam por nome, exista a conta ou não, e o tempo de resposta é o mesmo nos dois casos:
    assim nem a mensagem nem o bloqueio revelam quem existe.
    """
    now = now or utcnow()
    key = normalize_username(username)
    attempt = db.get(LoginAttemptModel, key)

    if attempt and attempt.locked_until and attempt.locked_until > now:
        burn_verification_time(password)
        raise LoginLockedError

    user = db.exec(select(UserModel).where(UserModel.username == key)).first()
    if user is not None and user.is_active:
        valid = verify_password(user.password_hash, password)
    else:
        burn_verification_time(password)
        valid = False

    if valid:
        if attempt:
            db.delete(attempt)
            db.commit()
        return user

    _register_failure(db, key, attempt, now)
    return None


def _register_failure(
    db: Session, key: str, attempt: LoginAttemptModel | None, now: datetime
) -> None:
    window = timedelta(minutes=settings.LOGIN_LOCK_MINUTES)
    if attempt is None:
        attempt = LoginAttemptModel(username=key, failed_count=0, window_started_at=now)
    elif attempt.window_started_at + window <= now:
        # As falhas antigas já não contam; também termina um bloqueio vencido.
        attempt.failed_count = 0
        attempt.window_started_at = now
        attempt.locked_until = None

    attempt.failed_count += 1
    if attempt.failed_count >= settings.LOGIN_MAX_ATTEMPTS:
        attempt.locked_until = now + window
    db.add(attempt)
    db.commit()


def create_session(db: Session, user: UserModel, now: datetime | None = None) -> NewSession:
    now = now or utcnow()
    token = secrets.token_urlsafe(32)
    expires_at = now + timedelta(minutes=settings.SESSION_TTL_MINUTES)
    db.add(
        UserSessionModel(
            token_hash=_token_hash(token), user_id=user.id, created_at=now, expires_at=expires_at
        )
    )
    db.commit()
    return NewSession(token=token, expires_at=expires_at, user=user)


def user_for_token(db: Session, token: str, now: datetime | None = None) -> UserModel | None:
    """Utilizador da sessão, ou None se o token não existir, tiver expirado ou a conta estiver
    desativada."""
    now = now or utcnow()
    session = db.get(UserSessionModel, _token_hash(token))
    if session is None or session.expires_at <= now:
        return None
    user = db.get(UserModel, session.user_id)
    return user if user is not None and user.is_active else None


def end_session(db: Session, token: str) -> None:
    session = db.get(UserSessionModel, _token_hash(token))
    if session is not None:
        db.delete(session)
        db.commit()


def cleanup(db: Session, now: datetime | None = None) -> None:
    """Apaga sessões expiradas e tentativas antigas, para as tabelas não crescerem sem fim."""
    now = now or utcnow()
    stale = now - timedelta(minutes=settings.LOGIN_LOCK_MINUTES)
    db.exec(delete(UserSessionModel).where(col(UserSessionModel.expires_at) <= now))
    db.exec(
        delete(LoginAttemptModel).where(
            col(LoginAttemptModel.window_started_at) <= stale,
            (col(LoginAttemptModel.locked_until).is_(None))
            | (col(LoginAttemptModel.locked_until) <= now),
        )
    )
    db.commit()


# --- Gestão de utilizadores -------------------------------------------------------------------


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise UserError(f"A senha deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres.")


def create_user(db: Session, username: str, password: str, role: str) -> UserModel:
    key = normalize_username(username)
    if not re.fullmatch(USERNAME_PATTERN, key):
        raise UserError("Usuário inválido: use 3 a 50 letras, números, '.', '_' ou '-'.")
    if role not in ROLES:
        raise UserError(f"Perfil inválido: use {', '.join(ROLES)}.")
    _check_password(password)
    if db.exec(select(UserModel).where(UserModel.username == key)).first():
        raise UserError("Já existe um usuário com esse nome.")

    user = UserModel(username=key, password_hash=hash_password(password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _active_admins(db: Session) -> int:
    return len(
        db.exec(
            select(UserModel.id).where(UserModel.role == "admin", col(UserModel.is_active))
        ).all()
    )


def update_user(
    db: Session,
    user: UserModel,
    role: str | None = None,
    is_active: bool | None = None,
    password: str | None = None,
) -> UserModel:
    """Altera perfil, estado ou palavra-passe. Desativar ou trocar a palavra-passe termina as
    sessões da conta; o sistema nunca fica sem nenhum admin ativo."""
    if role is not None and role not in ROLES:
        raise UserError(f"Perfil inválido: use {', '.join(ROLES)}.")

    loses_admin = user.role == "admin" and user.is_active and (
        (role is not None and role != "admin") or is_active is False
    )
    if loses_admin and _active_admins(db) <= 1:
        raise UserError("Não é possível retirar o último admin ativo.")

    end_sessions = False
    if role is not None:
        user.role = role
    if is_active is not None:
        end_sessions |= user.is_active and not is_active
        user.is_active = is_active
    if password is not None:
        _check_password(password)
        user.password_hash = hash_password(password)
        end_sessions = True

    if end_sessions:
        db.exec(delete(UserSessionModel).where(UserSessionModel.user_id == user.id))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user_by_name(db: Session, username: str) -> UserModel | None:
    return db.exec(
        select(UserModel).where(UserModel.username == normalize_username(username))
    ).first()
