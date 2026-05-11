import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.api.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from backend.database.dependencies import get_db
from backend.models.user import User
from backend.services.auth_service import AuthService

logger = logging.getLogger(__name__)
router = APIRouter(prefix='/auth', tags=['auth'])
auth_service = AuthService()


@router.post('/register', response_model=TokenResponse)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> TokenResponse:
    try:
        existing = db.query(User).filter(User.email == payload.email).first()
        if existing:
            raise HTTPException(status_code=409, detail='Email already registered')

        user = User(email=payload.email, hashed_password=auth_service.hash_password(payload.password))
        db.add(user)
        db.commit()
        db.refresh(user)
        return TokenResponse(access_token=auth_service.create_access_token(subject=payload.email))
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Registration failed")
        raise HTTPException(status_code=400, detail='Registration failed') from exc


@router.post('/login', response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    try:
        user = db.query(User).filter(User.email == payload.email).first()
        if not user or not auth_service.verify_password(payload.password, user.hashed_password):
            raise HTTPException(status_code=401, detail='Invalid credentials')
        return TokenResponse(access_token=auth_service.create_access_token(subject=payload.email))
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Login failed")
        raise HTTPException(status_code=400, detail='Login failed') from exc
