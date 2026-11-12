from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, col, select

from app.core.security import require_role
from app.db.database import get_db
from app.db.models import UserModel
from app.schemas.user import UserCreate, UserResponse, UserUpdate
from app.services.auth_service import UserError, create_user, update_user

router = APIRouter(prefix="/users", tags=["Users"], dependencies=[Depends(require_role("admin"))])


@router.get("/", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db)):
    return db.exec(select(UserModel).order_by(col(UserModel.username))).all()


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def add_user(request: UserCreate, db: Session = Depends(get_db)):
    try:
        return create_user(db, request.username, request.password, request.role)
    except UserError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.patch("/{user_id}", response_model=UserResponse)
def change_user(user_id: int, request: UserUpdate, db: Session = Depends(get_db)):
    user = db.get(UserModel, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado."
        )
    try:
        return update_user(
            db, user, role=request.role, is_active=request.is_active, password=request.password
        )
    except UserError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
