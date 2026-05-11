from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class UrlScanRequest(BaseModel):
    url: HttpUrl
    page_text: str | None = Field(default=None, max_length=100000)
    page_html: str | None = Field(default=None, max_length=250000)


class TextScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=100000)
    url: HttpUrl | None = None
    page_html: str | None = Field(default=None, max_length=250000)


class DetectedIssue(BaseModel):
    code: str
    title: str
    description: str
    severity: str


class ThreatExplanation(BaseModel):
    explanation: str
    detected_patterns: list[str]
    confidence: float


class EvidenceItem(BaseModel):
    code: str
    title: str
    description: str
    severity: str
    source: str
    category: str
    score_impact: int
    confidence: float
    value: Any | None = None


class ThreatReport(BaseModel):
    threat_level: str
    executive_summary: str
    reasoning_chain: list[str]
    recommended_actions: list[str]
    component_scores: dict[str, int]
    weighted_contributions: dict[str, float]
    indicators: dict[str, list[str]]
    signal_counts: dict[str, int]
    evidence: list[EvidenceItem]
    fetch_error: str | None = None


class TechnicalFindings(BaseModel):
    normalized_url: str | None = None
    redirect_chain: list[str]
    fetched_html: bool
    url_signals: list[EvidenceItem]
    dom_signals: list[EvidenceItem]
    content_signals: list[EvidenceItem]
    reputation_signals: list[EvidenceItem]
    model_signals: list[EvidenceItem]
    metadata: dict[str, Any]


class ScanResponse(BaseModel):
    risk_score: int
    classification: str
    confidence: float
    detected_issues: list[DetectedIssue]
    explanation: ThreatExplanation
    source_breakdown: dict[str, int]
    threat_report: ThreatReport | None = None
    technical_findings: TechnicalFindings | None = None
