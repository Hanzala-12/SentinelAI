from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_DEFAULT_IMPACT: dict[str, int] = {
    "info": 2,
    "low": 6,
    "medium": 12,
    "high": 20,
    "critical": 28,
}


@dataclass(slots=True)
class SignalEvidence:
    code: str
    title: str
    description: str
    severity: str
    source: str
    category: str
    score_impact: int
    confidence: float
    value: Any | None = None


@dataclass(slots=True)
class SignalExtractionResult:
    normalized_url: str
    hostname: str
    url_signals: list[SignalEvidence] = field(default_factory=list)
    dom_signals: list[SignalEvidence] = field(default_factory=list)
    content_signals: list[SignalEvidence] = field(default_factory=list)
    reputation_signals: list[SignalEvidence] = field(default_factory=list)
    model_signals: list[SignalEvidence] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    fetched_html: bool = False
    page_text_excerpt: str = ""
    fetch_error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def all_signals(self) -> list[SignalEvidence]:
        return (
            self.url_signals
            + self.dom_signals
            + self.content_signals
            + self.reputation_signals
            + self.model_signals
        )


@dataclass(slots=True)
class ReasoningWeights:
    phishing_probability: float = 0.30
    dom_suspicion: float = 0.25
    content_scam_score: float = 0.20
    reputation_score: float = 0.15
    redirect_risk: float = 0.10


@dataclass(slots=True)
class ReasoningResult:
    final_score: int
    classification: str
    confidence: float
    component_scores: dict[str, int]
    weighted_components: dict[str, float]
    top_evidence: list[SignalEvidence]
    reason_chain: list[str]
    summary: str
    recommended_actions: list[str]
    indicators: dict[str, list[str]]
    signal_counts: dict[str, int]
