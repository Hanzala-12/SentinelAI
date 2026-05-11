from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from backend.ai_engine.phishing_url_model import PretrainedPhishingUrlModel
from backend.api.schemas.scans import DetectedIssue


@dataclass(slots=True)
class UrlAnalysisResult:
    score: int
    confidence: float
    privacy_score: int
    issues: list[DetectedIssue]
    model_loaded: bool
    model_prediction: object | None
    model_issue: str | None


class UrlAnalyzer:
    def __init__(
        self,
        model_path: str | None = None,
        metadata_path: str | None = None,
    ) -> None:
        self.model = PretrainedPhishingUrlModel(model_path=model_path, metadata_path=metadata_path)

    def analyze(self, url: str) -> UrlAnalysisResult:
        normalized_url = url if url.startswith(("http://", "https://")) else f"https://{url}"
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or ""

        model_inference, feature_pack = self.model.predict(normalized_url)
        issues: list[DetectedIssue] = list(feature_pack.issues)

        heuristic_score = 0
        if len(normalized_url) > 75:
            heuristic_score += 12
            issues.append(
                DetectedIssue(
                    code="long-url",
                    title="Unusually long URL",
                    description="Attackers often hide phishing paths in very long URLs.",
                    severity="medium",
                )
            )
        if "@" in normalized_url:
            heuristic_score += 20
            issues.append(
                DetectedIssue(
                    code="at-symbol",
                    title="Embedded credential separator",
                    description="The @ character can be used to obscure the real destination.",
                    severity="high",
                )
            )
        if hostname.count("-") >= 3:
            heuristic_score += 12
            issues.append(
                DetectedIssue(
                    code="hyphenated-host",
                    title="Suspicious hyphen-heavy host",
                    description="Phishing domains frequently imitate brands using hyphenated names.",
                    severity="medium",
                )
            )

        privacy_score = feature_pack.privacy_score
        if parsed.scheme != "https":
            privacy_score = min(100, privacy_score + 18)
            heuristic_score += 10
            issues.append(
                DetectedIssue(
                    code="non-https",
                    title="Non-HTTPS website",
                    description="Traffic is not protected by HTTPS, increasing interception risk.",
                    severity="medium",
                )
            )
        if hostname.replace(".", "").isdigit():
            heuristic_score += 18
            issues.append(
                DetectedIssue(
                    code="numeric-host",
                    title="IP-like host",
                    description="Numeric hosts are often used to evade domain reputation systems.",
                    severity="high",
                )
            )

        model_score = int(round(model_inference.phishing_probability * 100))
        combined_score = min(100, round(model_score * 0.75 + heuristic_score * 0.25))
        confidence = round(
            min(0.99, max(model_inference.phishing_probability, feature_pack.confidence_hint)),
            2,
        )

        return UrlAnalysisResult(
            score=combined_score,
            confidence=confidence,
            privacy_score=min(100, privacy_score),
            issues=issues,
            model_loaded=model_inference.model_loaded,
            model_prediction=model_inference.prediction,
            model_issue=model_inference.issue,
        )
