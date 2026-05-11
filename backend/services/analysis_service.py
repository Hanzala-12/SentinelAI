from __future__ import annotations

from backend.ai_engine.text_analyzer import TextAnalysisResult, TextAnalyzer
from backend.ai_engine.url_analyzer import UrlAnalysisResult, UrlAnalyzer
from backend.api.schemas.scans import DetectedIssue
from backend.config import get_settings
from backend.intelligence.attack_pattern_classifier import AttackPatternClassifier
from backend.intelligence.models import SignalEvidence
from backend.intelligence.interaction_simulator import InteractionSimulationEngine
from backend.intelligence.models import ReasoningWeights
from backend.intelligence.narrative_analyzer import PhishingNarrativeAnalyzer
from backend.intelligence.reasoning_engine import ThreatReasoningEngine
from backend.intelligence.signal_extractor import ThreatSignalExtractor
from backend.services.explainability import ExplainabilityService
from backend.services.risk_scoring import RiskScoringService
from backend.services.threat_intel.models import ThreatIntelResult
from backend.services.threat_intel.service import ThreatIntelService


class AnalysisService:
    def __init__(self) -> None:
        settings = get_settings()
        self.url_analyzer = UrlAnalyzer(
            model_path=settings.sentinelai_url_model_path,
            metadata_path=settings.sentinelai_url_model_metadata_path,
        )
        self.text_analyzer = TextAnalyzer(
            model_name=settings.sentinelai_nlp_model,
            model_dir=settings.sentinelai_nlp_model_dir,
            local_only=settings.sentinelai_nlp_local_only,
            cpu_threads=settings.sentinelai_nlp_threads,
        )
        self.threat_intel = ThreatIntelService()
        self.signal_extractor = ThreatSignalExtractor()
        self.interaction_simulator = InteractionSimulationEngine(
            enabled=settings.interaction_simulation_enabled,
            timeout_ms=settings.interaction_timeout_ms,
            max_actions=settings.interaction_max_actions,
            headless=settings.interaction_headless,
        )
        self.attack_patterns = AttackPatternClassifier()
        self.narrative_analyzer = PhishingNarrativeAnalyzer()
        self.reasoning = ThreatReasoningEngine(
            ReasoningWeights(
                phishing_probability=settings.reason_weight_phishing_probability,
                dom_suspicion=settings.reason_weight_dom_suspicion,
                content_scam_score=settings.reason_weight_content_scam_score,
                reputation_score=settings.reason_weight_reputation_score,
                redirect_risk=settings.reason_weight_redirect_risk,
            )
        )
        self.scoring = RiskScoringService()
        self.explainer = ExplainabilityService()

    def scan_url(self, url: str, page_text: str | None = None, page_html: str | None = None):
        extraction = self.signal_extractor.extract(
            url=url,
            page_text=page_text,
            page_html=page_html,
            fetch_remote=True,
        )
        text_input = page_text or extraction.page_text_excerpt

        url_result = self.url_analyzer.analyze(url)
        text_result = self.text_analyzer.analyze(text_input) if text_input else None
        intel_result = self.threat_intel.lookup_url(url)
        interaction_result = self.interaction_simulator.simulate(extraction.normalized_url)
        extraction.interaction_events = interaction_result.events
        extraction.metadata["interaction_simulation"] = interaction_result.metadata
        if interaction_result.runtime_note:
            extraction.metadata["interaction_runtime_note"] = interaction_result.runtime_note
        self._append_interaction_signals(extraction.dom_signals, interaction_result.signals)

        calibrated_url_score = self._calibrate_url_model_score(
            raw_score=url_result.score,
            extraction=extraction,
            model_loaded=url_result.model_loaded,
        )
        self._append_url_model_signals(extraction.model_signals, url_result, calibrated_url_score)
        if text_result:
            self._append_text_model_signals(extraction.model_signals, text_result)
        self._append_issue_signals(extraction.model_signals, url_result.issues, source="model", category="url-model")
        if text_result:
            self._append_issue_signals(
                extraction.content_signals,
                text_result.issues,
                source="content",
                category="language-anomaly",
            )
        self._append_reputation_signals(extraction.reputation_signals, intel_result)
        extraction.attack_patterns = self.attack_patterns.classify(extraction)
        extraction.social_engineering_insights = self.narrative_analyzer.analyze(
            extraction=extraction,
            text_result=text_result,
        )

        reasoning = self.reasoning.reason(
            extraction,
            url_model_score=calibrated_url_score,
            url_model_confidence=url_result.confidence,
            nlp_score=text_result.score if text_result else 0,
            nlp_confidence=text_result.confidence if text_result else 0.0,
            reputation_score=intel_result.score,
            reputation_confidence=intel_result.confidence,
        )
        combined_model_issue = self._combine_model_issues(
            url_result.model_issue,
            text_result.model_issue if text_result else None,
        )

        return self.scoring.build_response(
            url=url,
            extraction=extraction,
            reasoning=reasoning,
            explainer=self.explainer,
            model_issue=combined_model_issue,
            text_model_name=text_result.model_name if text_result else None,
            intel_notes=intel_result.notes,
        )

    def scan_text(self, text: str, url: str | None = None, page_html: str | None = None):
        extraction = self.signal_extractor.extract(
            url=url or "https://local-text-analysis.invalid",
            page_text=text,
            page_html=page_html,
            fetch_remote=bool(url),
        )
        text_result = self.text_analyzer.analyze(text)
        url_result = self.url_analyzer.analyze(url) if url else None
        intel_result = self.threat_intel.lookup_url(url) if url else self._empty_intel_result()
        if url:
            interaction_result = self.interaction_simulator.simulate(extraction.normalized_url)
            extraction.interaction_events = interaction_result.events
            extraction.metadata["interaction_simulation"] = interaction_result.metadata
            if interaction_result.runtime_note:
                extraction.metadata["interaction_runtime_note"] = interaction_result.runtime_note
            self._append_interaction_signals(extraction.dom_signals, interaction_result.signals)

        if url_result:
            calibrated_url_score = self._calibrate_url_model_score(
                raw_score=url_result.score,
                extraction=extraction,
                model_loaded=url_result.model_loaded,
            )
            self._append_url_model_signals(extraction.model_signals, url_result, calibrated_url_score)
            self._append_issue_signals(extraction.model_signals, url_result.issues, source="model", category="url-model")
        else:
            calibrated_url_score = 0
        self._append_text_model_signals(extraction.model_signals, text_result)
        self._append_issue_signals(
            extraction.content_signals,
            text_result.issues,
            source="content",
            category="language-anomaly",
        )
        self._append_reputation_signals(extraction.reputation_signals, intel_result)
        extraction.attack_patterns = self.attack_patterns.classify(extraction)
        extraction.social_engineering_insights = self.narrative_analyzer.analyze(
            extraction=extraction,
            text_result=text_result,
        )

        reasoning = self.reasoning.reason(
            extraction,
            url_model_score=calibrated_url_score,
            url_model_confidence=url_result.confidence if url_result else 0.0,
            nlp_score=text_result.score,
            nlp_confidence=text_result.confidence,
            reputation_score=intel_result.score,
            reputation_confidence=intel_result.confidence,
        )
        combined_model_issue = self._combine_model_issues(
            url_result.model_issue if url_result else None,
            text_result.model_issue,
        )

        return self.scoring.build_response(
            url=url,
            extraction=extraction,
            reasoning=reasoning,
            explainer=self.explainer,
            model_issue=combined_model_issue,
            text_model_name=text_result.model_name,
            intel_notes=intel_result.notes,
        )

    def _append_url_model_signals(
        self,
        target: list[SignalEvidence],
        url_result: UrlAnalysisResult,
        calibrated_score: int,
    ) -> None:
        if calibrated_score >= 80:
            severity = "critical"
        elif calibrated_score >= 60:
            severity = "high"
        elif calibrated_score >= 40:
            severity = "medium"
        else:
            severity = "low"

        target.append(
            SignalEvidence(
                code="model-url-phishing-probability",
                title="URL phishing model probability",
                description=(
                    f"Pretrained URL model produced raw score {url_result.score}/100 and "
                    f"calibrated score {calibrated_score}/100 with confidence {round(url_result.confidence, 2)}."
                ),
                severity=severity,
                source="model",
                category="url-model",
                score_impact=max(2, int(calibrated_score * 0.24)),
                confidence=max(0.2, min(0.99, url_result.confidence)),
                reliability=max(0.3, min(0.98, url_result.confidence)),
                reasoning_context="Local URL classifier probability transformed into model evidence signal.",
                escalation_contribution=max(2, int(calibrated_score * 0.24)),
                source_module="url_analyzer",
                value={
                    "raw_score": url_result.score,
                    "calibrated_score": calibrated_score,
                    "model_loaded": url_result.model_loaded,
                },
            )
        )

        if not url_result.model_loaded:
            target.append(
                SignalEvidence(
                    code="model-url-fallback",
                    title="URL model fallback mode",
                    description=(
                        "Pretrained model was unavailable during inference; heuristic fallback scoring was applied."
                    ),
                    severity="medium",
                    source="model",
                    category="runtime",
                    score_impact=9,
                    confidence=0.74,
                    reliability=0.6,
                    reasoning_context="URL model unavailable; runtime fallback degraded model certainty.",
                    escalation_contribution=6,
                    source_module="url_analyzer",
                    value=url_result.model_issue,
                )
            )

    def _append_text_model_signals(self, target: list[SignalEvidence], text_result: TextAnalysisResult) -> None:
        if text_result.score <= 0:
            return

        if text_result.score >= 70:
            severity = "high"
        elif text_result.score >= 45:
            severity = "medium"
        else:
            severity = "low"

        target.append(
            SignalEvidence(
                code="model-text-scam-likelihood",
                title="NLP scam-language likelihood",
                description=(
                    f"Text model produced score {text_result.score}/100 with confidence "
                    f"{round(text_result.confidence, 2)} (mode: {text_result.runtime_mode})."
                ),
                severity=severity,
                source="model",
                category="nlp-model",
                score_impact=max(3, int(text_result.score * 0.24)),
                confidence=max(0.2, min(0.99, text_result.confidence)),
                reliability=max(0.3, min(0.95, text_result.confidence)),
                reasoning_context="Local NLP inference used for social-engineering support scoring.",
                escalation_contribution=max(3, int(text_result.score * 0.24)),
                source_module="text_analyzer",
                value={
                    "model_name": text_result.model_name,
                    "runtime_mode": text_result.runtime_mode,
                    "sub_scores": text_result.sub_scores,
                },
            )
        )

        if text_result.model_issue:
            target.append(
                SignalEvidence(
                    code="model-text-runtime-warning",
                    title="NLP local transformer runtime warning",
                    description=text_result.model_issue,
                    severity="medium",
                    source="model",
                    category="runtime",
                    score_impact=8,
                    confidence=0.7,
                    reliability=0.58,
                    reasoning_context="NLP inference warning reduced model-assisted narrative certainty.",
                    escalation_contribution=4,
                    source_module="text_analyzer",
                    value={"runtime_mode": text_result.runtime_mode},
                )
            )

    def _append_reputation_signals(self, target: list[SignalEvidence], intel_result: ThreatIntelResult) -> None:
        for finding in intel_result.provider_findings:
            if finding.verdict in {"error", "unavailable", "submitted"}:
                continue
            if finding.score >= 75:
                severity = "high"
            elif finding.score >= 45:
                severity = "medium"
            elif finding.score > 0:
                severity = "low"
            else:
                continue
            target.append(
                SignalEvidence(
                    code=f"reputation-{finding.provider}-{finding.verdict}",
                    title=f"{finding.provider.title()} reputation verdict: {finding.verdict}",
                    description=finding.summary,
                    severity=severity,
                    source="reputation",
                    category=finding.provider,
                    score_impact=max(4, int(finding.score * 0.25)),
                    confidence=max(0.2, min(0.99, finding.confidence)),
                    reliability=max(0.3, min(0.98, finding.confidence)),
                    reasoning_context="External provider verdict correlated with local investigation evidence.",
                    escalation_contribution=max(4, int(finding.score * 0.25)),
                    source_module="threat_intel_service",
                    value={"provider_score": finding.score, "verdict": finding.verdict},
                )
            )

        self._append_issue_signals(target, intel_result.issues, source="reputation", category="provider-alert")

    def _append_interaction_signals(self, target: list[SignalEvidence], signals: list[SignalEvidence]) -> None:
        existing_codes = {signal.code for signal in target}
        for signal in signals:
            if signal.code in existing_codes:
                continue
            if signal.escalation_contribution <= 0:
                signal.escalation_contribution = signal.score_impact
            if not signal.source_module:
                signal.source_module = "interaction_simulator"
            target.append(signal)
            existing_codes.add(signal.code)

    def _append_issue_signals(
        self,
        target: list[SignalEvidence],
        issues: list[DetectedIssue],
        *,
        source: str,
        category: str,
    ) -> None:
        for issue in issues:
            target.append(
                SignalEvidence(
                    code=issue.code,
                    title=issue.title,
                    description=issue.description,
                    severity=issue.severity,
                    source=source,
                    category=category,
                    score_impact={
                        "critical": 28,
                        "high": 21,
                        "medium": 13,
                        "low": 6,
                        "info": 2,
                    }.get(issue.severity, 8),
                    confidence=0.72,
                    reliability=0.68,
                    reasoning_context=f"Converted detection issue from {source} module into normalized signal evidence.",
                    escalation_contribution={
                        "critical": 28,
                        "high": 21,
                        "medium": 13,
                        "low": 6,
                        "info": 2,
                    }.get(issue.severity, 8),
                    source_module=source,
                )
            )

    def _empty_intel_result(self) -> ThreatIntelResult:
        return ThreatIntelResult(
            score=0,
            confidence=0.0,
            issues=[],
            notes=["Threat intelligence unavailable because no URL was supplied."],
            provider_findings=[],
        )

    def _combine_model_issues(self, *issues: str | None) -> str | None:
        valid = [issue for issue in issues if issue]
        if not valid:
            return None
        return " | ".join(valid)

    def _calibrate_url_model_score(
        self,
        *,
        raw_score: int,
        extraction,
        model_loaded: bool,
    ) -> int:
        score = raw_score
        normalized_url = extraction.normalized_url.lower()
        trust_profile = extraction.metadata.get("domain_trust", {}) if extraction.metadata else {}

        trusted_oauth_context = any(
            token in normalized_url
            for token in (
                "accounts.google.com",
                "login.microsoftonline.com",
                "appleid.apple.com",
                "okta.com",
                "auth0.com",
            )
        )
        if trusted_oauth_context:
            score = min(score, 45)
        if trust_profile.get("is_trusted"):
            score = min(score, 35)

        high_url_signals = sum(1 for signal in extraction.url_signals if signal.severity in {"high", "critical"})
        high_dom_signals = sum(1 for signal in extraction.dom_signals if signal.severity in {"high", "critical"})
        high_content_signals = sum(
            1 for signal in extraction.content_signals if signal.severity in {"high", "critical"}
        )
        corroboration = high_url_signals + high_dom_signals + high_content_signals

        if corroboration == 0:
            score = int(round(score * 0.45))
        elif corroboration == 1:
            score = int(round(score * 0.68))
        elif corroboration == 2:
            score = int(round(score * 0.9))

        behavioral_indicator_detected = any(
            signal.code
            in {
                "dom-external-credential-post",
                "dom-hidden-password-field",
                "dom-hidden-credential-form",
                "dom-credential-form-blank-action",
                "dom-downgraded-form-post",
                "dom-meta-refresh-redirect",
                "dom-scripted-redirect-logic",
                "interaction-triggered-redirect",
                "interaction-hidden-credential-reveal",
                "interaction-dynamic-form-injection",
                "interaction-overlay-injection",
                "content-credential-request",
                "content-scare-tactics",
            }
            for signal in extraction.all_signals
        )
        if not behavioral_indicator_detected:
            score = min(score, 20)

        if not model_loaded:
            score = int(round(score * 0.82))

        return max(0, min(100, score))
