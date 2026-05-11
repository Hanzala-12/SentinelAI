from __future__ import annotations

from backend.intelligence.models import AttackPatternLabel, SignalExtractionResult


class AttackPatternClassifier:
    def classify(self, extraction: SignalExtractionResult) -> list[AttackPatternLabel]:
        evidence_codes = {signal.code for signal in extraction.all_signals}
        patterns: list[AttackPatternLabel] = []

        def add_pattern(
            *,
            code: str,
            title: str,
            description: str,
            confidence: float,
            required_codes: set[str],
        ) -> None:
            matched = sorted(required_codes & evidence_codes)
            if not matched:
                return
            adjusted_confidence = min(0.98, confidence + min(0.2, len(matched) * 0.04))
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
            },
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
        )

        add_pattern(
            code="notification-abuse-scam",
            title="Notification Abuse Scam",
            description="Evidence indicates browser notification abuse patterns used for persistent phishing prompts.",
            confidence=0.72,
            required_codes={"dom-notification-abuse"},
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
        )

        add_pattern(
            code="clipboard-hijacking-attempt",
            title="Clipboard Hijacking Attempt",
            description="Evidence indicates clipboard manipulation logic likely intended to hijack copied sensitive data.",
            confidence=0.77,
            required_codes={"dom-clipboard-manipulation"},
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
        )

        interaction_event_count = len(extraction.interaction_events)
        interaction_indicator_count = sum(len(event.new_indicator_codes) for event in extraction.interaction_events)
        if interaction_event_count >= 2 and interaction_indicator_count >= 2:
            patterns.append(
                AttackPatternLabel(
                    code="multi-step-phishing-flow",
                    title="Multi-Step Phishing Flow",
                    description=(
                        "Controlled interaction revealed multi-stage phishing behavior with progressive indicators."
                    ),
                    confidence=round(min(0.96, 0.74 + min(0.2, interaction_indicator_count * 0.04)), 2),
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
