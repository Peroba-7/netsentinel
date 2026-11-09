from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ROLES = ("leitor", "analista", "admin")
Role = Literal["leitor", "analista", "admin"]
_RANK = {role: rank for rank, role in enumerate(ROLES)}

MIN_PASSWORD_LENGTH = 12
USERNAME_PATTERN = r"^[a-z0-9._-]{3,50}$"


def role_at_least(role: str | None, minimum: str) -> bool:
    """True se `role` tem pelo menos as permissões de `minimum` (leitor < analista < admin)."""
    return role in _RANK and _RANK[role] >= _RANK[minimum]


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=200)


class LoginResponse(BaseModel):
    token: str
    expires_at: datetime
    username: str
    role: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    is_active: bool
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)
    role: Role


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=MIN_PASSWORD_LENGTH, max_length=200)
