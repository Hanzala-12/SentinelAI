from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from backend.api.schemas.scans import DetectedIssue

logger = logging.getLogger(__name__)


NLP_SIGNAL_PATTERNS: dict[str, tuple[str, int, str, str]] = {
    "credential_harvest": (
        r"\b(verify your account|confirm your password|re-enter your password|"
        r"validate credentials|login verification|security verification)\b",
        24,
        "high",
        "Credential harvesting language",
    ),
    "urgency_pressure": (
        r"\b(urgent|act now|immediately|final warning|within \d+ (hours?|minutes?)|"
        r"limited time)\b",
        14,
        "medium",
        "Urgency coercion language",
    ),
    "account_suspension": (
        r"\b(account suspended|account locked|account disabled|security hold|"
        r"unauthorized login detected)\b",
        20,
        "high",
        "Account suspension scare tactic",
    ),
    "financial_pressure": (
        r"\b(payment failed|update billing|confirm payment method|invoice overdue|"
        r"bank account verification)\b",
        16,
        "medium",
        "Financial remediation pressure",
    ),
    "reward_lure": (
        r"\b(claim your prize|gift card|reward bonus|winner|airdrop)\b",
        10,
        "medium",
        "Fraudulent reward lure",
    ),
    "impersonation_cue": (
        r"\b(official notice|support team|security team|dear customer|service desk)\b",
        11,
        "medium",
        "Institution impersonation cue",
    ),
}


@dataclass(slots=True)
class TextAnalysisResult:
    score: int
    confidence: float
    issues: list[DetectedIssue]
    model_name: str | None
    runtime_mode: str
    model_issue: str | None = None
    sub_scores: dict[str, int] = field(default_factory=dict)


class TextAnalyzer:
    def __init__(
        self,
        model_name: str | None = None,
        model_dir: str | None = None,
        local_only: bool | None = None,
        cpu_threads: int | None = None,
    ) -> None:
        self.model_name = model_name or os.getenv("SENTINELAI_NLP_MODEL", "distilbert-scam-detector")
        model_dir_override = model_dir or os.getenv("SENTINELAI_NLP_MODEL_DIR")
        repo_root = Path(__file__).resolve().parents[2]
        default_model_dir = Path(__file__).resolve().parents[1] / "models" / "nlp" / self.model_name
        if model_dir_override:
            candidate = Path(model_dir_override)
            self.model_dir = candidate if candidate.is_absolute() else repo_root / candidate
        else:
            self.model_dir = default_model_dir
        self.max_length = int(os.getenv("SENTINELAI_NLP_MAX_LENGTH", "256"))
        if cpu_threads is not None:
            self.cpu_threads = max(1, cpu_threads)
        else:
            self.cpu_threads = max(1, int(os.getenv("SENTINELAI_NLP_THREADS", "2")))
        if local_only is not None:
            self.local_files_only = local_only
        else:
            self.local_files_only = os.getenv("SENTINELAI_NLP_LOCAL_ONLY", "true").lower() != "false"
        self._tokenizer = None
        self._model = None
        self._risk_label_ids: set[int] = set()
        self._model_issue: str | None = None
        self._model_loaded = False
        self._load_attempted = False

    def analyze(self, text: str) -> TextAnalysisResult:
        if not text or not text.strip():
            return TextAnalysisResult(
                score=0,
                confidence=0.0,
                issues=[],
                model_name=None,
                runtime_mode="empty",
            )

        rule_score, rule_confidence, rule_issues, sub_scores = self._rule_based_analysis(text)
        model_score = 0
        model_confidence = 0.0
        runtime_mode = "rules-only"

        self._load_model()
        if self._model_loaded and self._model is not None and self._tokenizer is not None:
            inference = self._run_model(text)
            if inference:
                model_score, model_confidence = inference
                runtime_mode = "local-transformer"

        if model_score > 0:
            score = int(round(rule_score * 0.45 + model_score * 0.55))
            confidence = min(0.99, max(rule_confidence, model_confidence))
        else:
            score = rule_score
            confidence = rule_confidence

        return TextAnalysisResult(
            score=max(0, min(100, score)),
            confidence=round(max(0.1, min(0.99, confidence)), 2),
            issues=rule_issues,
            model_name=str(self.model_dir) if self._model_loaded else None,
            runtime_mode=runtime_mode,
            model_issue=self._model_issue,
            sub_scores=sub_scores,
        )

    def _load_model(self) -> None:
        if self._load_attempted:
            return
        self._load_attempted = True

        if not self.model_dir.exists():
            self._model_issue = (
                f"local-transformer-artifact-missing: expected model directory at {self.model_dir}"
            )
            logger.warning(self._model_issue)
            return

        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            torch.set_num_threads(self.cpu_threads)
            torch.set_num_interop_threads(1)
            torch.manual_seed(42)
            try:
                torch.use_deterministic_algorithms(True, warn_only=True)
            except Exception:
                pass

            self._tokenizer = AutoTokenizer.from_pretrained(
                str(self.model_dir),
                local_files_only=self.local_files_only,
            )
            self._model = AutoModelForSequenceClassification.from_pretrained(
                str(self.model_dir),
                local_files_only=self.local_files_only,
            )
            self._model.eval()
            self._risk_label_ids = self._resolve_risk_label_ids(self._model.config.id2label)
            self._model_issue = None
            self._model_loaded = True
            logger.info("Loaded local NLP model from %s", self.model_dir)
        except Exception as exc:
            self._model_loaded = False
            self._model = None
            self._tokenizer = None
            self._model_issue = f"local-transformer-load-failed: {exc}"
            logger.warning("Local NLP model loading failed: %s", exc)

    def _run_model(self, text: str) -> tuple[int, float] | None:
        try:
            import torch

            encoded = self._tokenizer(
                text[:4000],
                truncation=True,
                max_length=self.max_length,
                padding=False,
                return_tensors="pt",
            )
            with torch.no_grad():
                logits = self._model(**encoded).logits[0]
            probabilities = torch.softmax(logits, dim=-1).cpu().tolist()
            if not probabilities:
                return None

            if self._risk_label_ids:
                risk_probability = max(probabilities[index] for index in self._risk_label_ids)
            elif len(probabilities) > 1:
                risk_probability = probabilities[1]
            else:
                risk_probability = probabilities[0]

            score = int(round(risk_probability * 100))
            confidence = float(max(risk_probability, 1.0 - risk_probability))
            return max(0, min(100, score)), max(0.0, min(0.99, confidence))
        except Exception as exc:
            self._model_issue = f"local-transformer-inference-failed: {exc}"
            logger.warning("Local NLP inference failed: %s", exc)
            return None

    def _rule_based_analysis(
        self,
        text: str,
    ) -> tuple[int, float, list[DetectedIssue], dict[str, int]]:
        lowered = text.lower()
        issues: list[DetectedIssue] = []
        sub_scores: dict[str, int] = {}
        weighted_score = 0

        for key, (pattern, base_weight, severity, title) in NLP_SIGNAL_PATTERNS.items():
            matches = re.findall(pattern, lowered, flags=re.IGNORECASE)
            if not matches:
                sub_scores[key] = 0
                continue
            hit_count = len(matches)
            score = min(36, base_weight + max(0, hit_count - 1) * 4)
            sub_scores[key] = score
            weighted_score += score
            issues.append(
                DetectedIssue(
                    code=f"nlp-{key}",
                    title=title,
                    description=(
                        f"Detected {hit_count} phrase-level matches linked to phishing campaigns."
                    ),
                    severity=severity,
                )
            )

        exclamation_hits = lowered.count("!")
        all_caps_tokens = self._all_caps_token_count(text)
        pressure_score = 0
        if exclamation_hits >= 6:
            pressure_score += 5
        if all_caps_tokens >= 3:
            pressure_score += 6
        if pressure_score > 0:
            issues.append(
                DetectedIssue(
                    code="nlp-emotional-pressure-formatting",
                    title="Emotional pressure formatting",
                    description=(
                        "Detected aggressive formatting patterns (all-caps tokens or repeated punctuation) "
                        "used to accelerate user action."
                    ),
                    severity="low",
                )
            )
        sub_scores["emotional_pressure"] = pressure_score
        weighted_score += pressure_score

        final_rule_score = max(0, min(100, weighted_score))
        confidence = 0.42 + min(0.45, len(issues) * 0.07)
        return final_rule_score, confidence, issues, sub_scores

    def _resolve_risk_label_ids(self, id_to_label: dict[int, str] | None) -> set[int]:
        if not id_to_label:
            return {1}
        resolved: set[int] = set()
        for label_id, label_name in id_to_label.items():
            normalized = str(label_name).lower()
            if any(
                token in normalized
                for token in (
                    "phish",
                    "scam",
                    "fraud",
                    "malicious",
                    "suspicious",
                    "unsafe",
                    "negative",
                )
            ):
                resolved.add(int(label_id))
        if resolved:
            return resolved
        if 1 in id_to_label:
            return {1}
        return {max(id_to_label)}

    def _all_caps_token_count(self, text: str) -> int:
        tokens = re.findall(r"[A-Za-z]{3,}", text)
        return sum(1 for token in tokens if token.isupper())
