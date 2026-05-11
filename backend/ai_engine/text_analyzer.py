from __future__ import annotations

import os
import logging
from dataclasses import dataclass

from backend.api.schemas.scans import DetectedIssue

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TextAnalysisResult:
    score: int
    confidence: float
    issues: list[DetectedIssue]
    model_name: str | None


class TextAnalyzer:
    def __init__(self, model_name: str | None = None) -> None:
        self.model_name = model_name or os.getenv(
            "SENTINELAI_NLP_MODEL",
            "distilbert-base-uncased-finetuned-sst-2-english",
        )
        self._pipeline = None
        self._pipeline_disabled = False

    def _load_model(self) -> None:
        if self._pipeline is not None or self._pipeline_disabled:
            return
        # Ensure HuggingFace cache respects HF_HOME if provided (docker-compose maps this)
        hf_home = os.getenv("HF_HOME")
        if hf_home:
            os.environ.setdefault("HF_HOME", hf_home)
        try:
            import torch  # noqa: F401
        except Exception:
            logger.warning("PyTorch is not installed; skipping transformer pipeline and using heuristic NLP scoring.")
            self._pipeline = None
            self._pipeline_disabled = True
            return
        try:
            from transformers import pipeline

            logger.info("Loading NLP pipeline: %s", self.model_name)
            self._pipeline = pipeline("text-classification", model=self.model_name)
        except Exception as exc:
            logger.warning("Failed to load NLP pipeline %s: %s", self.model_name, exc)
            self._pipeline = None
            self._pipeline_disabled = True

    def analyze(self, text: str) -> TextAnalysisResult:
        if not text:
            return TextAnalysisResult(score=0, confidence=0.0, issues=[], model_name=None)

        # lazy-load model
        try:
            self._load_model()
        except Exception:
            pass

        issues: list[DetectedIssue] = []

        # simple keyword heuristics for scam-like language
        suspicious_tokens = (
            "verify your account",
            "confirm your password",
            "re-enter credentials",
            "account suspended",
            "security alert",
            "unauthorized access",
            "urgent",
            "limited time",
            "act now",
            "click here",
            "claim your reward",
            "reset password",
            "bank account",
            "payment failed",
        )
        lowered = text.lower()
        matched_tokens = 0
        for token in suspicious_tokens:
            if token in lowered:
                matched_tokens += 1
                issues.append(
                    DetectedIssue(
                        code=f"nlp-{token.replace(' ', '-')}",
                        title=f"Suspicious phrase: {token}",
                        description=f"The page contains the phrase '{token}', often used in phishing or scam copy.",
                        severity="medium",
                    )
                )

        model_name = None
        heuristic_score = min(100, 8 + matched_tokens * 11) if matched_tokens else 0
        score = heuristic_score
        confidence = 0.0
        if self._pipeline is not None:
            try:
                result = self._pipeline(text[:1000])
                if isinstance(result, list) and result:
                    label = result[0].get("label")
                    prob = float(result[0].get("score", 0.0))
                    model_name = self.model_name
                    model_score = 0
                    # Use sentiment model as weak support, not as primary decision logic.
                    if label and label.lower().startswith("neg"):
                        model_score = int(round(prob * 55))
                    else:
                        model_score = int(round((1.0 - prob) * 30))
                    score = max(score, model_score)
                    confidence = prob
            except Exception as exc:
                logger.warning("NLP pipeline failed: %s", exc)

        # ensure score 0..100
        score = max(0, min(100, score))

        return TextAnalysisResult(score=score, confidence=confidence, issues=issues, model_name=model_name)
