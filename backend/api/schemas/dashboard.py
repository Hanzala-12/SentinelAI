from pydantic import BaseModel


class ClassificationStat(BaseModel):
    classification: str
    count: int
    avg_risk_score: float


class ScanHistoryItem(BaseModel):
    id: int
    url: str | None
    scan_type: str
    risk_score: int
    classification: str
    confidence: float
    explanation: str
    created_at: str | None


class DashboardStatsResponse(BaseModel):
    classification_breakdown: list[ClassificationStat]
    recent_scans: list[ScanHistoryItem]
    total_scans: int
    feature_flags: dict[str, bool]
