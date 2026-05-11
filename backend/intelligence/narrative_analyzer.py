from __future__ import annotations

from typing import Any

from backend.ai_engine.text_analyzer import TextAnalysisResult
from backend.intelligence.models import SignalExtractionResult


class PhishingNarrativeAnalyzer:
    def analyze(
        self,
        *,
        extraction: SignalExtractionResult,
        text_result: TextAnalysisResult | None,
    ) -> dict[str, Any]:
        codes = {signal.code for signal in extraction.content_signals + extraction.dom_signals}
        sub_scores = text_result.sub_scores if text_result else {}

        authority_impersonation = int(
            "content-impersonation-language" in codes or "dom-brand-impersonation-cues" in codes
        )
        fear_coercion = int(
            "content-scare-tactics" in codes or "dom-account-suspension-language" in codes
        )
        urgency_manipulation = int(
            "content-urgency-pressure" in codes or "dom-urgency-banner-language" in codes
        )
        reward_baiting = int("content-fake-reward" in codes)
        financial_pressure = int("content-payment-pressure" in codes)

        nlp_total = min(100, sum(int(value) for value in sub_scores.values()))
        coercion_score = min(
            100,
            nlp_total
            + authority_impersonation * 10
            + fear_coercion * 12
            + urgency_manipulation * 9
            + reward_baiting * 7
            + financial_pressure * 8,
        )

        profile_tokens: list[str] = []
        if authority_impersonation:
            profile_tokens.append("authority impersonation")
        if fear_coercion:
            profile_tokens.append("fear-based coercion")
        if urgency_manipulation:
            profile_tokens.append("urgency pressure")
        if reward_baiting:
            profile_tokens.append("reward baiting")
        if financial_pressure:
            profile_tokens.append("financial coercion")

        if profile_tokens:
            narrative = (
                "Detected social-engineering narrative profile: "
                + ", ".join(profile_tokens)
                + "."
            )
        else:
            narrative = "No strong social-engineering narrative profile was detected in available content."

        return {
            "coercion_score": coercion_score,
            "authority_impersonation": bool(authority_impersonation),
            "fear_coercion": bool(fear_coercion),
            "urgency_manipulation": bool(urgency_manipulation),
            "reward_baiting": bool(reward_baiting),
            "financial_coercion": bool(financial_pressure),
            "nlp_sub_scores": sub_scores,
            "narrative_summary": narrative,
        }
