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

        self._append_url_model_signals(extraction.model_signals, url_result)
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
            url_model_score=url_result.score,
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
            self._append_url_model_signals(extraction.model_signals, url_result)
            self._append_issue_signals(extraction.model_signals, url_result.issues, source="model", category="url-model")
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
            url_model_score=url_result.score if url_result else 0,
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

    def _append_url_model_signals(self, target: list[SignalEvidence], url_result: UrlAnalysisResult) -> None:
        if url_result.score >= 80:
            severity = "critical"
        elif url_result.score >= 60:
            severity = "high"
        elif url_result.score >= 40:
            severity = "medium"
        else:
            severity = "low"

        target.append(
            SignalEvidence(
                code="model-url-phishing-probability",
                title="URL phishing model probability",
                description=(
                    f"Pretrained URL model produced score {url_result.score}/100 with confidence "
                    f"{round(url_result.confidence, 2)}."
                ),
                severity=severity,
                source="model",
                category="url-model",
                score_impact=max(4, int(url_result.score * 0.28)),
                confidence=max(0.2, min(0.99, url_result.confidence)),
                value={"score": url_result.score, "model_loaded": url_result.model_loaded},
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
                    value={"provider_score": finding.score, "verdict": finding.verdict},
                )
            )

        self._append_issue_signals(target, intel_result.issues, source="reputation", category="provider-alert")

    def _append_interaction_signals(self, target: list[SignalEvidence], signals: list[SignalEvidence]) -> None:
        existing_codes = {signal.code for signal in target}
        for signal in signals:
            if signal.code in existing_codes:
                continue
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
