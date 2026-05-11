from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from backend.intelligence.models import (
    SEVERITY_RANK,
    ReasoningResult,
    ReasoningWeights,
    SignalEvidence,
    SignalExtractionResult,
    TimelineEvent,
)

CLASSIFICATION_RANK = {
    "safe": 0,
    "suspicious": 1,
    "dangerous": 2,
    "critical": 3,
}


class ThreatReasoningEngine:
    def __init__(self, weights: ReasoningWeights | None = None) -> None:
        self.weights = weights or ReasoningWeights()

    def reason(
        self,
        extraction: SignalExtractionResult,
        *,
        url_model_score: int,
        url_model_confidence: float,
        nlp_score: int,
        nlp_confidence: float,
        reputation_score: int,
        reputation_confidence: float,
    ) -> ReasoningResult:
        url_structural_score = self._aggregate(extraction.url_signals)
        model_signal_score = self._aggregate(extraction.model_signals)
        phishing_probability = max(url_structural_score, model_signal_score, self._clamp_score(url_model_score))

        dom_suspicion = self._aggregate(extraction.dom_signals)
        content_rule_score = self._aggregate(extraction.content_signals)
        content_scam_score = max(content_rule_score, self._clamp_score(nlp_score))

        reputation_signal_score = self._aggregate(extraction.reputation_signals)
        reputation_component = max(reputation_signal_score, self._clamp_score(reputation_score))

        redirect_risk = self._redirect_risk(extraction.redirect_chain, extraction.dom_signals)

        component_scores = {
            "phishing_probability": phishing_probability,
            "dom_suspicion": dom_suspicion,
            "content_scam_score": content_scam_score,
            "reputation_score": reputation_component,
            "redirect_risk": redirect_risk,
        }
        effective_weights = self._effective_weights(component_scores)

        weighted_components = {
            "phishing_probability": phishing_probability * effective_weights["phishing_probability"],
            "dom_suspicion": dom_suspicion * effective_weights["dom_suspicion"],
            "content_scam_score": content_scam_score * effective_weights["content_scam_score"],
            "reputation_score": reputation_component * effective_weights["reputation_score"],
            "redirect_risk": redirect_risk * effective_weights["redirect_risk"],
        }
        final_score = int(round(sum(weighted_components.values())))
        classification = self._classify(final_score)

        all_signals = extraction.all_signals
        top_evidence = self._rank_evidence(all_signals)[:14]
        reason_chain = self._reason_chain(top_evidence, weighted_components)
        summary = self._summary(classification, top_evidence)
        actions = self._recommended_actions(classification, top_evidence)
        indicators = self._indicators(extraction)

        confidence = self._confidence_score(
            top_evidence=top_evidence,
            url_model_confidence=url_model_confidence,
            nlp_confidence=nlp_confidence,
            reputation_confidence=reputation_confidence,
            component_scores={
                "phishing_probability": phishing_probability,
                "dom_suspicion": dom_suspicion,
                "content_scam_score": content_scam_score,
                "reputation_score": reputation_component,
                "redirect_risk": redirect_risk,
            },
        )

        severity_counter = Counter(signal.severity for signal in all_signals)
        signal_counts = {
            "total": len(all_signals),
            "critical": severity_counter.get("critical", 0),
            "high": severity_counter.get("high", 0),
            "medium": severity_counter.get("medium", 0),
            "low": severity_counter.get("low", 0),
            "info": severity_counter.get("info", 0),
        }
        timeline = self._build_timeline(
            extraction=extraction,
            weighted_components=weighted_components,
            final_score=self._clamp_score(final_score),
            final_confidence=confidence,
        )
        confidence_progression = [
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "score": event.score_after,
                "confidence": event.confidence_after,
                "classification": event.classification_after,
                "stage": event.stage,
            }
            for event in timeline
        ]

        return ReasoningResult(
            final_score=self._clamp_score(final_score),
            classification=classification,
            confidence=confidence,
            component_scores=component_scores,
            weighted_components={key: round(value, 2) for key, value in weighted_components.items()},
            top_evidence=top_evidence,
            reason_chain=reason_chain,
            summary=summary,
            recommended_actions=actions,
            indicators=indicators,
            signal_counts=signal_counts,
            timeline=timeline,
            attack_patterns=extraction.attack_patterns,
            confidence_progression=confidence_progression,
        )

    def _aggregate(self, signals: list[SignalEvidence]) -> int:
        if not signals:
            return 0
        weighted_sum = 0.0
        for signal in signals:
            severity_multiplier = {
                "info": 0.4,
                "low": 0.6,
                "medium": 1.0,
                "high": 1.18,
                "critical": 1.32,
            }.get(signal.severity, 1.0)
            weighted_sum += signal.score_impact * severity_multiplier
        return self._clamp_score(int(round(weighted_sum)))

    def _redirect_risk(self, redirect_chain: list[str], dom_signals: list[SignalEvidence]) -> int:
        chain_risk = 0
        if len(redirect_chain) >= 1:
            chain_risk = min(65, len(redirect_chain) * 22)
        redirect_signals = [
            signal for signal in dom_signals if signal.code in {"dom-meta-refresh-redirect", "dom-scripted-redirect-logic"}
        ]
        behavior_risk = min(35, sum(signal.score_impact for signal in redirect_signals))
        return self._clamp_score(chain_risk + behavior_risk)

    def _rank_evidence(self, signals: list[SignalEvidence]) -> list[SignalEvidence]:
        return sorted(
            signals,
            key=lambda signal: (
                SEVERITY_RANK.get(signal.severity, 0),
                signal.score_impact,
                signal.confidence,
            ),
            reverse=True,
        )

    def _reason_chain(self, top_evidence: list[SignalEvidence], weighted_components: dict[str, float]) -> list[str]:
        chain: list[str] = []
        for signal in top_evidence[:6]:
            chain.append(f"{signal.title}: {signal.description}")

        component_rank = sorted(weighted_components.items(), key=lambda item: item[1], reverse=True)
        for component, contribution in component_rank[:2]:
            chain.append(f"Component '{component}' contributed {contribution:.1f} risk points.")
        return chain

    def _summary(self, classification: str, top_evidence: list[SignalEvidence]) -> str:
        if not top_evidence and classification == "Safe":
            return "No high-confidence phishing indicators were detected across URL, content, and behavior signals."

        if not top_evidence:
            return "Risk is elevated, but the available evidence is limited. Additional page telemetry is recommended."

        lead = ", ".join(signal.title for signal in top_evidence[:3])
        if classification in {"Critical", "Dangerous"}:
            return (
                f"Threat profile is {classification.upper()} based on correlated phishing indicators: {lead}. "
                "The page should be treated as hostile until proven otherwise."
            )
        if classification == "Suspicious":
            return (
                f"Threat profile is SUSPICIOUS due to mixed-risk evidence including {lead}. "
                "User interaction should be restricted pending validation."
            )
        return f"Threat profile is SAFE with minor cautionary signals: {lead}."

    def _recommended_actions(self, classification: str, top_evidence: list[SignalEvidence]) -> list[str]:
        actions: list[str] = []
        evidence_codes = {signal.code for signal in top_evidence}

        if "dom-external-credential-post" in evidence_codes:
            actions.append("Block credential submission and isolate the destination domain immediately.")
        if "url-typosquat-pattern" in evidence_codes or "dom-brand-impersonation-cues" in evidence_codes:
            actions.append("Validate brand ownership and enforce navigation only through official bookmarked domains.")
        if "dom-obfuscated-javascript" in evidence_codes:
            actions.append("Capture page artifacts and inspect script payloads in a sandbox before user access.")
        if "url-idn-spoof-risk" in evidence_codes:
            actions.append("Render and review Punycode representation to detect homoglyph spoofing attempts.")
        if "interaction-triggered-redirect" in evidence_codes:
            actions.append("Block click-through navigation path and monitor for staged redirect infrastructure.")
        if "interaction-hidden-credential-reveal" in evidence_codes:
            actions.append("Treat revealed post-click credential flow as active phishing and isolate immediately.")
        if "interaction-overlay-injection" in evidence_codes:
            actions.append("Capture full-page screenshots and DOM snapshots for deceptive overlay attribution.")

        if classification == "Critical":
            actions.extend(
                [
                    "Quarantine the URL in gateway controls and block at DNS/proxy layers.",
                    "Trigger incident response workflow for potential credential compromise.",
                    "Reset potentially exposed user credentials and enforce MFA re-validation.",
                ]
            )
        elif classification == "Dangerous":
            actions.extend(
                [
                    "Prevent user interaction with the page and escalate to SOC triage.",
                    "Submit indicators to email/web filtering controls for preventive blocking.",
                ]
            )
        elif classification == "Suspicious":
            actions.extend(
                [
                    "Flag the URL for analyst review before allowing broad user access.",
                    "Monitor outbound traffic for related domains and redirect chains.",
                ]
            )
        else:
            actions.append("Keep the URL under passive monitoring and rescan if content changes.")

        deduped: list[str] = []
        seen = set()
        for action in actions:
            if action in seen:
                continue
            seen.add(action)
            deduped.append(action)
        return deduped[:6]

    def _indicators(self, extraction: SignalExtractionResult) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = defaultdict(list)
        for signal in extraction.all_signals:
            grouped[signal.source].append(signal.code)
        return {key: sorted(set(values)) for key, values in grouped.items()}

    def _confidence_score(
        self,
        top_evidence: list[SignalEvidence],
        url_model_confidence: float,
        nlp_confidence: float,
        reputation_confidence: float,
        component_scores: dict[str, int],
    ) -> float:
        evidence_density = min(1.0, len(top_evidence) / 10.0)
        populated_components = sum(1 for value in component_scores.values() if value > 0)
        coverage_ratio = populated_components / max(1, len(component_scores))
        severe_evidence = sum(1 for signal in top_evidence if signal.severity in {"high", "critical"})
        severe_ratio = min(1.0, severe_evidence / 5.0)

        confidence = (
            0.34
            + evidence_density * 0.22
            + coverage_ratio * 0.18
            + severe_ratio * 0.1
            + max(0.0, min(1.0, url_model_confidence)) * 0.08
            + max(0.0, min(1.0, nlp_confidence)) * 0.04
            + max(0.0, min(1.0, reputation_confidence)) * 0.04
        )
        return round(max(0.15, min(0.99, confidence)), 2)

    def _classify(self, score: int) -> str:
        if score < 25:
            return "Safe"
        if score < 50:
            return "Suspicious"
        if score < 75:
            return "Dangerous"
        return "Critical"

    def _clamp_score(self, score: int) -> int:
        return max(0, min(100, score))

    def _effective_weights(self, component_scores: dict[str, int]) -> dict[str, float]:
        base_weights = {
            "phishing_probability": self.weights.phishing_probability,
            "dom_suspicion": self.weights.dom_suspicion,
            "content_scam_score": self.weights.content_scam_score,
            "reputation_score": self.weights.reputation_score,
            "redirect_risk": self.weights.redirect_risk,
        }
        active_components = [name for name, value in component_scores.items() if value > 0]
        if not active_components:
            return base_weights

        active_weight_total = sum(base_weights[name] for name in active_components)
        if active_weight_total <= 0:
            return base_weights

        adjusted = {name: 0.0 for name in base_weights}
        for name in active_components:
            adjusted[name] = base_weights[name] / active_weight_total
        return adjusted

    def _build_timeline(
        self,
        *,
        extraction: SignalExtractionResult,
        weighted_components: dict[str, float],
        final_score: int,
        final_confidence: float,
    ) -> list[TimelineEvent]:
        timeline: list[TimelineEvent] = []
        now = datetime.now(timezone.utc)
        running_score = 0
        running_confidence = 0.2
        running_classification = self._classify(running_score)

        def emit(
            *,
            stage: str,
            source: str,
            title: str,
            detail: str,
            severity: str,
            score_delta: int,
            evidence_codes: list[str] | None = None,
        ) -> None:
            nonlocal running_score, running_classification, running_confidence
            before = running_score
            confidence_before = running_confidence
            previous_classification = running_classification
            running_score = self._clamp_score(running_score + max(0, score_delta))
            running_confidence = self._next_confidence(
                running_confidence=running_confidence,
                severity=severity,
                score_delta=score_delta,
            )
            running_classification = self._classify(running_score)
            event_index = len(timeline)
            timestamp = (now + timedelta(seconds=event_index)).isoformat()
            timeline.append(
                TimelineEvent(
                    event_id=f"evt-{event_index + 1:03d}",
                    timestamp=timestamp,
                    stage=stage,
                    source=source,
                    title=title,
                    detail=detail,
                    severity=severity,
                    score_before=before,
                    score_after=running_score,
                    score_delta=max(0, score_delta),
                    confidence_before=round(confidence_before, 2),
                    confidence_after=round(running_confidence, 2),
                    classification_after=running_classification,
                    evidence_codes=evidence_codes or [],
                )
            )

            if CLASSIFICATION_RANK.get(running_classification.lower(), 0) > CLASSIFICATION_RANK.get(
                previous_classification.lower(), 0
            ):
                escalation_index = len(timeline)
                escalation_timestamp = (now + timedelta(seconds=escalation_index)).isoformat()
                timeline.append(
                    TimelineEvent(
                        event_id=f"evt-{escalation_index + 1:03d}",
                        timestamp=escalation_timestamp,
                        stage="escalation",
                        source="reasoning",
                        title=f"Threat escalated to {running_classification.upper()}",
                        detail=(
                            f"Accumulated evidence raised score from {before}/100 to "
                            f"{running_score}/100."
                        ),
                        severity=self._classification_severity(running_classification),
                        score_before=running_score,
                        score_after=running_score,
                        score_delta=0,
                        confidence_before=round(running_confidence, 2),
                        confidence_after=round(running_confidence, 2),
                        classification_after=running_classification,
                        evidence_codes=evidence_codes or [],
                    )
                )

        emit(
            stage="collection",
            source="system",
            title="Investigation initialized",
            detail=f"Started evidence collection for {extraction.normalized_url}.",
            severity="info",
            score_delta=0,
        )

        if extraction.url_signals:
            emit(
                stage="url-analysis",
                source="url",
                title="URL structure analysis completed",
                detail=f"Detected {len(extraction.url_signals)} URL anomalies.",
                severity="low",
                score_delta=2,
                evidence_codes=[signal.code for signal in extraction.url_signals[:4]],
            )
            for signal in extraction.url_signals:
                emit(
                    stage="url-analysis",
                    source="url",
                    title=signal.title,
                    detail=signal.description,
                    severity=signal.severity,
                    score_delta=self._timeline_delta(signal, source_weight=0.24),
                    evidence_codes=[signal.code],
                )

        if extraction.redirect_chain:
            emit(
                stage="delivery-analysis",
                source="network",
                title="Redirect chain observed",
                detail=(
                    f"Navigation followed {len(extraction.redirect_chain)} redirect hops before final "
                    "content was rendered."
                ),
                severity="high" if len(extraction.redirect_chain) >= 2 else "medium",
                score_delta=min(18, len(extraction.redirect_chain) * 6),
                evidence_codes=["redirect-chain"],
            )

        if extraction.dom_signals:
            emit(
                stage="dom-analysis",
                source="dom",
                title="DOM behavior analysis completed",
                detail=f"Detected {len(extraction.dom_signals)} suspicious DOM/JS behaviors.",
                severity="medium",
                score_delta=3,
                evidence_codes=[signal.code for signal in extraction.dom_signals[:4]],
            )
            for signal in extraction.dom_signals:
                emit(
                    stage="dom-analysis",
                    source="dom",
                    title=signal.title,
                    detail=signal.description,
                    severity=signal.severity,
                    score_delta=self._timeline_delta(signal, source_weight=0.26),
                    evidence_codes=[signal.code],
                )

        if extraction.interaction_events:
            emit(
                stage="interaction-simulation",
                source="interaction",
                title="Controlled interaction simulation completed",
                detail=(
                    f"Executed {len(extraction.interaction_events)} interaction probes to uncover "
                    "dynamic phishing behavior."
                ),
                severity="medium",
                score_delta=4,
                evidence_codes=["interaction-simulation"],
            )
            for event in extraction.interaction_events:
                mutation_summary = ", ".join(
                    f"{key}={value}"
                    for key, value in event.dom_mutations.items()
                    if isinstance(value, int) and value > 0
                )
                detail = (
                    f"Action '{event.action}' on target '{event.target}' "
                    f"{'triggered redirect' if event.redirect_triggered else 'completed without redirect'}."
                )
                if mutation_summary:
                    detail += f" DOM mutations: {mutation_summary}."
                emit(
                    stage="interaction-simulation",
                    source="interaction",
                    title=f"Interaction step {event.step_id}",
                    detail=detail,
                    severity="high" if event.new_indicator_codes else "low",
                    score_delta=8 if event.new_indicator_codes else 2,
                    evidence_codes=event.new_indicator_codes or [event.step_id],
                )

        if extraction.content_signals:
            emit(
                stage="content-analysis",
                source="content",
                title="Content and social-engineering analysis completed",
                detail=f"Detected {len(extraction.content_signals)} phishing-language indicators.",
                severity="medium",
                score_delta=2,
                evidence_codes=[signal.code for signal in extraction.content_signals[:4]],
            )
            for signal in extraction.content_signals:
                emit(
                    stage="content-analysis",
                    source="content",
                    title=signal.title,
                    detail=signal.description,
                    severity=signal.severity,
                    score_delta=self._timeline_delta(signal, source_weight=0.2),
                    evidence_codes=[signal.code],
                )

        if extraction.model_signals:
            emit(
                stage="model-correlation",
                source="model",
                title="Local model inference correlated",
                detail=f"Integrated {len(extraction.model_signals)} model-backed indicators.",
                severity="medium",
                score_delta=2,
                evidence_codes=[signal.code for signal in extraction.model_signals[:4]],
            )
            for signal in extraction.model_signals:
                emit(
                    stage="model-correlation",
                    source="model",
                    title=signal.title,
                    detail=signal.description,
                    severity=signal.severity,
                    score_delta=self._timeline_delta(signal, source_weight=0.18),
                    evidence_codes=[signal.code],
                )

        if extraction.reputation_signals:
            emit(
                stage="intel-correlation",
                source="reputation",
                title="Threat intelligence correlation completed",
                detail=f"Integrated {len(extraction.reputation_signals)} provider reputation findings.",
                severity="medium",
                score_delta=2,
                evidence_codes=[signal.code for signal in extraction.reputation_signals[:4]],
            )
            for signal in extraction.reputation_signals:
                emit(
                    stage="intel-correlation",
                    source="reputation",
                    title=signal.title,
                    detail=signal.description,
                    severity=signal.severity,
                    score_delta=self._timeline_delta(signal, source_weight=0.16),
                    evidence_codes=[signal.code],
                )

        for component, contribution in sorted(weighted_components.items(), key=lambda item: item[1], reverse=True)[:3]:
            emit(
                stage="reasoning",
                source="reasoning",
                title=f"Weighted component contribution: {component}",
                detail=f"Component contributed {contribution:.1f} points to final score aggregation.",
                severity="info",
                score_delta=max(1, int(round(contribution * 0.15))),
                evidence_codes=[component],
            )

        if running_score != final_score:
            delta = final_score - running_score
            if delta > 0:
                emit(
                    stage="reasoning",
                    source="reasoning",
                    title="Final evidence normalization",
                    detail="Adjusted accumulated score to normalized threat score.",
                    severity="info",
                    score_delta=delta,
                    evidence_codes=["normalization"],
                )
            else:
                before = running_score
                confidence_before = running_confidence
                running_score = final_score
                running_confidence = max(running_confidence, final_confidence)
                timeline.append(
                    TimelineEvent(
                        event_id=f"evt-{len(timeline) + 1:03d}",
                        timestamp=(now + timedelta(seconds=len(timeline))).isoformat(),
                        stage="reasoning",
                        source="reasoning",
                        title="Final evidence normalization",
                        detail="Applied normalization cap to finalize threat score.",
                        severity="info",
                        score_before=before,
                        score_after=final_score,
                        score_delta=0,
                        confidence_before=round(confidence_before, 2),
                        confidence_after=round(running_confidence, 2),
                        classification_after=self._classify(final_score),
                        evidence_codes=["normalization"],
                    )
                )
        else:
            running_confidence = max(running_confidence, final_confidence)

        timeline.append(
            TimelineEvent(
                event_id=f"evt-{len(timeline) + 1:03d}",
                timestamp=(now + timedelta(seconds=len(timeline))).isoformat(),
                stage="conclusion",
                source="reasoning",
                title=f"Investigation concluded: {self._classify(final_score).upper()}",
                detail=f"Final threat score computed as {final_score}/100.",
                severity=self._classification_severity(self._classify(final_score)),
                score_before=final_score,
                score_after=final_score,
                score_delta=0,
                confidence_before=round(running_confidence, 2),
                confidence_after=round(max(running_confidence, final_confidence), 2),
                classification_after=self._classify(final_score),
                evidence_codes=["final-score"],
            )
        )
        return timeline

    def _timeline_delta(self, signal: SignalEvidence, source_weight: float) -> int:
        base = signal.score_impact * source_weight
        confidence_factor = max(0.45, min(1.0, signal.confidence))
        severity_bonus = {
            "critical": 3,
            "high": 2,
            "medium": 1,
            "low": 0,
            "info": 0,
        }.get(signal.severity, 0)
        return min(20, max(1, int(round(base * confidence_factor)) + severity_bonus))

    def _classification_severity(self, classification: str) -> str:
        normalized = classification.lower()
        if normalized == "critical":
            return "critical"
        if normalized == "dangerous":
            return "high"
        if normalized == "suspicious":
            return "medium"
        return "info"

    def _next_confidence(self, running_confidence: float, severity: str, score_delta: int) -> float:
        severity_boost = {
            "critical": 0.11,
            "high": 0.09,
            "medium": 0.07,
            "low": 0.04,
            "info": 0.02,
        }.get(severity, 0.03)
        score_factor = min(0.08, max(0.0, score_delta) * 0.002)
        return min(0.97, running_confidence + severity_boost + score_factor)
