from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.router import api_router
from backend import models  # noqa: F401
from backend.config import get_settings
from backend.database.session import engine
from backend.logging_config import configure_logging
from backend.services.analysis_service import AnalysisService
from backend.middleware.request_id import RequestIdMiddleware
from backend.models.base import Base

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s in %s mode", settings.app_name, settings.app_env)
    Base.metadata.create_all(bind=engine)
    try:
        svc = AnalysisService()
        # warm up URL model (downloads pretrained classifier if missing)
        try:
            svc.url_analyzer.model._load_model()
        except Exception:
            logger.warning("URL model warmup failed, continuing startup")
        # warm up NLP model (DistilBERT) to ensure HF models are cached on first run
        try:
            svc.text_analyzer._load_model()
        except Exception:
            logger.warning("NLP model warmup failed or unavailable, continuing startup")
    except Exception as exc:
        logger.warning("Model warmup skipped or failed: %s", exc)
    yield
    logger.info("Shutting down %s", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestIdMiddleware)

app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name, "environment": settings.app_env}
