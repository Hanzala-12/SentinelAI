from __future__ import annotations

from dataclasses import dataclass

from backend.api.schemas.scans import DetectedIssue


@dataclass(slots=True)
class ProviderFinding:
    provider: str
    score: int
    confidence: float
    summary: str
    verdict: str


@dataclass(slots=True)
class ThreatIntelResult:
    score: int
    confidence: float
    issues: list[DetectedIssue]
    notes: list[str]
    provider_findings: list[ProviderFinding]
