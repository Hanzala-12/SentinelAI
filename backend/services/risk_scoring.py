from __future__ import annotations

from backend.api.schemas.scans import DetectedIssue, ScanResponse
from backend.intelligence.models import ReasoningResult, SignalEvidence, SignalExtractionResult
from backend.services.explainability import ExplainabilityService


class RiskScoringService:
    def build_response(
        self,
        *,
        url: str | None,
        extraction: SignalExtractionResult,
        reasoning: ReasoningResult,
        explainer: ExplainabilityService,
        model_issue: str | None = None,
        text_model_name: str | None = None,
        intel_notes: list[str] | None = None,
    ) -> ScanResponse:
        detected_issues = self._issues_from_evidence(reasoning.top_evidence)
        explanation = explainer.build_explanation(
            reasoning=reasoning,
            extraction=extraction,
            url=url,
            model_issue=model_issue,
            text_model_name=text_model_name,
            intel_notes=intel_notes,
        )

        source_breakdown = {
            "phishing_probability": reasoning.component_scores.get("phishing_probability", 0),
            "dom_suspicion": reasoning.component_scores.get("dom_suspicion", 0),
            "content_scam_score": reasoning.component_scores.get("content_scam_score", 0),
            "reputation_score": reasoning.component_scores.get("reputation_score", 0),
            "redirect_risk": reasoning.component_scores.get("redirect_risk", 0),
        }

        return ScanResponse(
            risk_score=reasoning.final_score,
            classification=reasoning.classification,
            confidence=reasoning.confidence,
            detected_issues=detected_issues,
            explanation=explanation,
            source_breakdown=source_breakdown,
            threat_report=explainer.build_threat_report(reasoning, extraction),
            technical_findings=explainer.build_technical_findings(extraction),
        )

    def _issues_from_evidence(self, evidence: list[SignalEvidence]) -> list[DetectedIssue]:
        issues: list[DetectedIssue] = []
        seen: set[str] = set()
        for signal in evidence:
            if signal.code in seen:
                continue
            seen.add(signal.code)
            issues.append(
                DetectedIssue(
                    code=signal.code,
                    title=signal.title,
                    description=signal.description,
                    severity=signal.severity,
                )
            )
        return issues
