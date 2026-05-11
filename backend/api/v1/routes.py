from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.api.schemas.dashboard import DashboardStatsResponse, ScanHistoryItem
from backend.api.schemas.llm import DeepExplainRequest, DeepExplainResponse
from backend.api.schemas.scans import ScanResponse, TextScanRequest, UrlScanRequest
from backend.database.dependencies import get_db
from backend.database.repositories.scan_history_repository import ScanHistoryRepository
from backend.models.user import User
from backend.services.analysis_service import AnalysisService
from backend.services.openrouter_service import OpenRouterService

router = APIRouter(tags=["security"])
logger = logging.getLogger(__name__)
analysis_service = AnalysisService()
openrouter_service = OpenRouterService()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "SentinelAI API", "version": "1.0.0"}


@router.post("/scan/url", response_model=ScanResponse)
def scan_url(
    payload: UrlScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanResponse:
    try:
        response = analysis_service.scan_url(str(payload.url), payload.page_text, payload.page_html)
        ScanHistoryRepository(db).create(
            user_id=current_user.id,
            url=str(payload.url),
            scan_type="url",
            risk_score=response.risk_score,
            classification=response.classification,
            confidence=response.confidence,
            explanation=response.explanation.explanation,
            llm_used=False,
            detected_issues=[issue.model_dump() for issue in response.detected_issues],
            source_breakdown=response.source_breakdown,
        )
        return response
    except ValueError as exc:
        logger.exception("URL scan failed")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/scan/page", response_model=ScanResponse)
def scan_page(
    payload: TextScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanResponse:
    try:
        response = analysis_service.scan_text(
            payload.text,
            str(payload.url) if payload.url else None,
            payload.page_html,
        )
        ScanHistoryRepository(db).create(
            user_id=current_user.id,
            url=str(payload.url) if payload.url else None,
            scan_type="page",
            risk_score=response.risk_score,
            classification=response.classification,
            confidence=response.confidence,
            explanation=response.explanation.explanation,
            llm_used=False,
            detected_issues=[issue.model_dump() for issue in response.detected_issues],
            source_breakdown=response.source_breakdown,
        )
        return response
    except ValueError as exc:
        logger.exception("Page scan failed")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/explain-deep", response_model=DeepExplainResponse)
def explain_deep(
    payload: DeepExplainRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DeepExplainResponse:
    if not openrouter_service.is_enabled:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="OpenRouter is not configured")
    explanation = openrouter_service.explain(
        url=str(payload.url),
        page_text=payload.page_text or "",
        risk_score=payload.risk_score,
    )
    ScanHistoryRepository(db).create(
        user_id=current_user.id,
        url=str(payload.url),
        scan_type="llm_explain",
        risk_score=payload.risk_score * 10,
        classification="LLM Explained",
        confidence=1.0,
        explanation=explanation,
        llm_used=True,
        detected_issues=[],
        source_breakdown={},
    )
    return DeepExplainResponse(explanation=explanation, model=openrouter_service.model_name, used_llm=True)


@router.get("/history")
def history(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    repo = ScanHistoryRepository(db)
    items = repo.list_recent(user_id=current_user.id, limit=limit, offset=offset)
    total = repo.count_for_user(current_user.id)
    return {
        "items": [
            ScanHistoryItem(
                id=item.id,
                url=item.url,
                scan_type=item.scan_type,
                risk_score=item.risk_score,
                classification=item.classification,
                confidence=item.confidence,
                explanation=item.explanation,
                created_at=item.created_at.isoformat() if item.created_at else None,
            ).model_dump()
            for item in items
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/dashboard/stats", response_model=DashboardStatsResponse)
def dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DashboardStatsResponse:
    repo = ScanHistoryRepository(db)
    stats = repo.stats_for_user(current_user.id)
    return DashboardStatsResponse(
        classification_breakdown=stats["classification_breakdown"],
        recent_scans=stats["recent_scans"],
        total_scans=int(stats["total_scans"]),
        feature_flags={
            "llm_enabled": openrouter_service.is_enabled,
            "threat_intel_enabled": analysis_service.threat_intel.virustotal_client is not None
            or analysis_service.threat_intel.urlscan_client is not None
            or analysis_service.threat_intel.abuseipdb_client is not None,
            "vt_enabled": analysis_service.threat_intel.virustotal_client is not None,
            "urlscan_enabled": analysis_service.threat_intel.urlscan_client is not None,
            "abuseipdb_enabled": analysis_service.threat_intel.abuseipdb_client is not None,
        },
    )
