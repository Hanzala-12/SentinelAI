from __future__ import annotations

from backend.intelligence.models import AttackPatternLabel, SignalExtractionResult


class AttackPatternClassifier:
    def classify(self, extraction: SignalExtractionResult) -> list[AttackPatternLabel]:
        evidence_codes = {signal.code for signal in extraction.all_signals}
        evidence_map = {signal.code: signal for signal in extraction.all_signals}
        patterns: list[AttackPatternLabel] = []

        def add_pattern(
            *,
            code: str,
            title: str,
            description: str,
            confidence: float,
            required_codes: set[str],
            min_matches: int = 2,
            allow_single_strong_match: bool = False,
        ) -> None:
            matched = sorted(required_codes & evidence_codes)
            if not matched:
                return
            strong_hits = [
                evidence_map[item]
                for item in matched
                if item in evidence_map and evidence_map[item].severity in {"high", "critical"}
            ]
            if len(matched) < min_matches:
                if not (allow_single_strong_match and len(matched) == 1 and strong_hits):
                    return
            reliability_avg = sum(evidence_map[code].reliability for code in matched if code in evidence_map) / max(
                1, len(matched)
            )
            high_severity_hits = sum(
                1
                for code in matched
                if code in evidence_map and evidence_map[code].severity in {"high", "critical"}
            )
            adjusted_confidence = min(
                0.98,
                confidence
                + min(0.16, len(matched) * 0.035)
                + min(0.12, high_severity_hits * 0.03)
                + (reliability_avg - 0.65) * 0.18,
            )
            if adjusted_confidence < 0.62 and len(matched) == 1:
                return
            patterns.append(
                AttackPatternLabel(
                    code=code,
                    title=title,
                    description=description,
                    confidence=round(adjusted_confidence, 2),
                    evidence_codes=matched,
                )
            )

        add_pattern(
            code="credential-harvesting",
            title="Credential Harvesting",
            description=(
                "Evidence indicates staged credential capture behavior through hidden/external/dynamic form flows."
            ),
            confidence=0.74,
            required_codes={
                "dom-external-credential-post",
                "dom-hidden-password-field",
                "dom-hidden-credential-form",
                "interaction-hidden-credential-reveal",
                "interaction-dynamic-form-injection",
                "content-credential-request",
                "dom-credential-form-blank-action",
                "dom-downgraded-form-post",
            },
            min_matches=1,
            allow_single_strong_match=True,
        )

        add_pattern(
            code="redirect-based-phishing",
            title="Redirect-Based Phishing",
            description=(
                "Evidence indicates redirect-oriented delivery behavior with interaction-triggered navigation changes."
            ),
            confidence=0.7,
            required_codes={
                "dom-meta-refresh-redirect",
                "dom-scripted-redirect-logic",
                "interaction-triggered-redirect",
            },
            min_matches=1,
            allow_single_strong_match=True,
        )

        add_pattern(
            code="brand-impersonation",
            title="Brand Impersonation",
            description="Evidence indicates likely impersonation infrastructure and brand spoofing cues.",
            confidence=0.68,
            required_codes={
                "url-typosquat-pattern",
                "dom-brand-impersonation-cues",
                "url-idn-spoof-risk",
                "content-impersonation-language",
            },
            min_matches=2,
        )

        add_pattern(
            code="notification-abuse-scam",
            title="Notification Abuse Scam",
            description="Evidence indicates browser notification abuse patterns used for persistent phishing prompts.",
            confidence=0.72,
            required_codes={
                "dom-notification-abuse",
                "interaction-popup-scare-flow",
                "content-scare-tactics",
                "dom-urgency-banner-language",
            },
            min_matches=2,
        )

        add_pattern(
            code="fake-account-verification",
            title="Fake Account Verification",
            description=(
                "Evidence indicates coercive account verification flow using suspension pressure and credential prompts."
            ),
            confidence=0.69,
            required_codes={
                "content-credential-request",
                "dom-account-suspension-language",
                "content-scare-tactics",
                "interaction-overlay-injection",
            },
            min_matches=2,
        )

        add_pattern(
            code="social-engineering-scam",
            title="Social Engineering Scam",
            description=(
                "Evidence indicates emotional pressure, urgency, and coercive messaging typical of phishing campaigns."
            ),
            confidence=0.66,
            required_codes={
                "content-urgency-pressure",
                "content-scare-tactics",
                "content-payment-pressure",
                "content-fake-reward",
                "content-emotional-amplification",
                "dom-urgency-banner-language",
            },
            min_matches=2,
        )

        add_pattern(
            code="clipboard-hijacking-attempt",
            title="Clipboard Hijacking Attempt",
            description="Evidence indicates clipboard manipulation logic likely intended to hijack copied sensitive data.",
            confidence=0.77,
            required_codes={"dom-clipboard-manipulation"},
            min_matches=1,
            allow_single_strong_match=True,
        )

        add_pattern(
            code="fake-security-warning",
            title="Fake Security Warning",
            description=(
                "Evidence indicates security warning scare tactics combined with interaction-triggered overlays or popups."
            ),
            confidence=0.7,
            required_codes={
                "dom-account-suspension-language",
                "interaction-popup-scare-flow",
                "dom-deceptive-popup-pattern",
            },
            min_matches=2,
        )

        interaction_event_count = len(extraction.interaction_events)
        interaction_indicator_count = sum(len(event.new_indicator_codes) for event in extraction.interaction_events)
        if interaction_event_count >= 2 and interaction_indicator_count >= 2:
            interaction_confidence = (
                sum(event.confidence_after for event in extraction.interaction_events) / interaction_event_count
            )
            patterns.append(
                AttackPatternLabel(
                    code="multi-step-phishing-flow",
                    title="Multi-Step Phishing Flow",
                    description=(
                        "Controlled interaction revealed multi-stage phishing behavior with progressive indicators."
                    ),
                    confidence=round(
                        min(
                            0.96,
                            0.68
                            + min(0.16, interaction_indicator_count * 0.03)
                            + min(0.1, (interaction_confidence - 0.5) * 0.25),
                        ),
                        2,
                    ),
                    evidence_codes=sorted(
                        {
                            code
                            for event in extraction.interaction_events
                            for code in event.new_indicator_codes
                        }
                    ),
                )
            )

        patterns.sort(key=lambda item: item.confidence, reverse=True)
        return patterns[:8]
