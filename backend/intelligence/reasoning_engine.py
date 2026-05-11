from __future__ import annotations

from collections import Counter, defaultdict

from backend.intelligence.models import (
    SEVERITY_RANK,
    ReasoningResult,
    ReasoningWeights,
    SignalEvidence,
    SignalExtractionResult,
)


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
