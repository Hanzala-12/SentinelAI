from __future__ import annotations

from backend.api.schemas.scans import (
    AttackPattern,
    EvidenceItem,
    InteractionReplayEvent,
    TechnicalFindings,
    ThreatExplanation,
    ThreatReport,
    TimelineEvent,
)
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

        segments = [f"Threat classification: {reasoning.classification} ({reasoning.final_score}/100)."]
        if reasoning.top_evidence:
            lead = reasoning.top_evidence[0]
            segments.append(
                "Lead indicator: "
                f"{lead.title} [{lead.code}] with confidence {round(lead.confidence, 2)}."
            )
            segments.append(
                "Correlated evidence count: "
                f"{reasoning.signal_counts.get('total', 0)} signals across URL, DOM, content, model, and reputation."
            )
        segments.append(reasoning.summary)
        if url:
            segments.append(f"Target analyzed: {url}.")
        if text_model_name:
            segments.append(f"NLP inference artifact: {text_model_name}.")
        if model_issue:
            segments.append(f"URL model runtime note: {model_issue}.")
        if intel_notes:
            segments.extend(intel_notes[:2])
        if extraction.fetch_error:
            segments.append(f"DOM collection warning: {extraction.fetch_error}.")
        if reasoning.top_evidence:
            segments.append(
                "Primary forensic findings: "
                + "; ".join(
                    f"{signal.title} ({signal.source}/{signal.severity}, impact {signal.score_impact})"
                    for signal in reasoning.top_evidence[:4]
                )
                + "."
            )
        if extraction.interaction_events:
            segments.append(
                f"Interaction simulation executed {len(extraction.interaction_events)} controlled probes, "
                "revealing dynamic phishing behavior not present in static inspection."
            )
        if extraction.attack_patterns:
            segments.append(
                "Likely attack patterns: "
                + ", ".join(pattern.title for pattern in extraction.attack_patterns[:4])
                + "."
            )
        narrative = extraction.social_engineering_insights.get("narrative_summary")
        if narrative:
            segments.append(str(narrative))

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
            attack_patterns=[self._as_attack_pattern(item) for item in reasoning.attack_patterns],
            confidence_progression=reasoning.confidence_progression,
            social_engineering_analysis=extraction.social_engineering_insights,
            timeline=[self._as_timeline_item(event) for event in reasoning.timeline],
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
            interaction_events=[self._as_interaction_event(item) for item in extraction.interaction_events],
            attack_patterns=[self._as_attack_pattern(item) for item in extraction.attack_patterns],
            social_engineering_analysis=extraction.social_engineering_insights,
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

    def _as_timeline_item(self, event) -> TimelineEvent:
        return TimelineEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            stage=event.stage,
            source=event.source,
            title=event.title,
            detail=event.detail,
            severity=event.severity,
            score_before=event.score_before,
            score_after=event.score_after,
            score_delta=event.score_delta,
            confidence_before=event.confidence_before,
            confidence_after=event.confidence_after,
            classification_after=event.classification_after,
            evidence_codes=event.evidence_codes,
        )

    def _as_attack_pattern(self, pattern) -> AttackPattern:
        return AttackPattern(
            code=pattern.code,
            title=pattern.title,
            description=pattern.description,
            confidence=pattern.confidence,
            evidence_codes=pattern.evidence_codes,
        )

    def _as_interaction_event(self, event) -> InteractionReplayEvent:
        return InteractionReplayEvent(
            step_id=event.step_id,
            timestamp=event.timestamp,
            action=event.action,
            target=event.target,
            url_before=event.url_before,
            url_after=event.url_after,
            redirect_triggered=event.redirect_triggered,
            new_indicator_codes=event.new_indicator_codes,
            dom_mutations=event.dom_mutations,
            confidence_after=event.confidence_after,
        )
