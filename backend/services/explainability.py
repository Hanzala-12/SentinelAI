from __future__ import annotations

from backend.api.schemas.scans import EvidenceItem, TechnicalFindings, ThreatExplanation, ThreatReport
from backend.intelligence.models import ReasoningResult, SignalEvidence, SignalExtractionResult


class ExplainabilityService:
    def build_explanation(
        self,
        reasoning: ReasoningResult,
        extraction: SignalExtractionResult,
        *,
        url: str | None,
        model_issue: str | None = None,
        text_model_name: str | None = None,
        intel_notes: list[str] | None = None,
    ) -> ThreatExplanation:
        pattern_codes = [signal.code for signal in reasoning.top_evidence[:10]]
        if not pattern_codes:
            pattern_codes = ["no-strong-patterns"]

        segments = [
            f"Threat level is {reasoning.classification} with score {reasoning.final_score}/100.",
            reasoning.summary,
        ]
        if url:
            segments.append(f"Target analyzed: {url}.")
        if text_model_name:
            segments.append(f"NLP support model: {text_model_name}.")
        if model_issue:
            segments.append(f"Model fallback note: {model_issue}.")
        if intel_notes:
            segments.extend(intel_notes[:2])
        if extraction.fetch_error:
            segments.append("Remote page fetch failed; DOM evidence may be partial.")
        if reasoning.top_evidence:
            segments.append(
                "Primary evidence: " + "; ".join(signal.title for signal in reasoning.top_evidence[:4]) + "."
            )

        return ThreatExplanation(
            explanation=" ".join(segment.strip() for segment in segments if segment.strip()),
            detected_patterns=pattern_codes,
            confidence=reasoning.confidence,
        )

    def build_threat_report(
        self,
        reasoning: ReasoningResult,
        extraction: SignalExtractionResult,
    ) -> ThreatReport:
        return ThreatReport(
            threat_level=reasoning.classification,
            executive_summary=reasoning.summary,
            reasoning_chain=reasoning.reason_chain,
            recommended_actions=reasoning.recommended_actions,
            component_scores=reasoning.component_scores,
            weighted_contributions=reasoning.weighted_components,
            indicators=reasoning.indicators,
            signal_counts=reasoning.signal_counts,
            evidence=[self._as_evidence_item(signal) for signal in reasoning.top_evidence],
            fetch_error=extraction.fetch_error,
        )

    def build_technical_findings(self, extraction: SignalExtractionResult) -> TechnicalFindings:
        return TechnicalFindings(
            normalized_url=extraction.normalized_url,
            redirect_chain=extraction.redirect_chain,
            fetched_html=extraction.fetched_html,
            url_signals=[self._as_evidence_item(signal) for signal in extraction.url_signals],
            dom_signals=[self._as_evidence_item(signal) for signal in extraction.dom_signals],
            content_signals=[self._as_evidence_item(signal) for signal in extraction.content_signals],
            reputation_signals=[self._as_evidence_item(signal) for signal in extraction.reputation_signals],
            model_signals=[self._as_evidence_item(signal) for signal in extraction.model_signals],
            metadata=extraction.metadata,
        )

    def _as_evidence_item(self, signal: SignalEvidence) -> EvidenceItem:
        return EvidenceItem(
            code=signal.code,
            title=signal.title,
            description=signal.description,
            severity=signal.severity,
            source=signal.source,
            category=signal.category,
            score_impact=signal.score_impact,
            confidence=signal.confidence,
            value=signal.value,
        )
