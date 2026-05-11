from fastapi import APIRouter

from backend.api.v1.auth import router as auth_router
from backend.api.v1.routes import router as v1_router

api_router = APIRouter()
api_router.include_router(v1_router)
api_router.include_router(auth_router)
