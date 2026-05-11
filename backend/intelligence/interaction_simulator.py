from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.intelligence.models import InteractionReplayEvent, SignalEvidence

logger = logging.getLogger(__name__)


SUSPICIOUS_CLICK_SELECTORS = [
    "button:has-text('Verify')",
    "button:has-text('Continue')",
    "button:has-text('Confirm')",
    "button:has-text('Login')",
    "button:has-text('Sign in')",
    "button:has-text('Unlock')",
    "button:has-text('Next')",
    "[role='button']:has-text('Verify')",
    "a:has-text('Verify')",
    "a:has-text('Continue')",
    "a:has-text('Login')",
    "a:has-text('Sign in')",
    "a[href*='verify']",
    "a[href*='login']",
    "a[href*='secure']",
]


@dataclass(slots=True)
class InteractionSimulationResult:
    events: list[InteractionReplayEvent] = field(default_factory=list)
    signals: list[SignalEvidence] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    runtime_note: str | None = None


class InteractionSimulationEngine:
    def __init__(
        self,
        *,
        enabled: bool = True,
        timeout_ms: int = 8000,
        max_actions: int = 4,
        headless: bool = True,
    ) -> None:
        self.enabled = enabled
        self.timeout_ms = timeout_ms
        self.max_actions = max_actions
        self.headless = headless

    def simulate(self, url: str) -> InteractionSimulationResult:
        if not self.enabled:
            return InteractionSimulationResult(
                runtime_note="interaction-simulation-disabled-by-configuration",
            )
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            return InteractionSimulationResult(
                runtime_note=f"playwright-unavailable: {exc}",
                signals=[
                    self._signal(
                        code="interaction-runtime-unavailable",
                        title="Interaction simulation runtime unavailable",
                        description=(
                            "Dynamic interaction probing was skipped because Playwright runtime "
                            "dependencies are not available."
                        ),
                        severity="low",
                        category="runtime",
                        score_impact=4,
                        confidence=0.66,
                    )
                ],
            )

        events: list[InteractionReplayEvent] = []
        signals: list[SignalEvidence] = []
        metadata: dict[str, Any] = {}
        popup_count = 0
        interaction_start = datetime.now(timezone.utc)

        def page_snapshot(page) -> dict[str, int]:
            script = """
            () => {
                const hiddenElements = Array.from(document.querySelectorAll('*')).filter((el) => {
                    const style = window.getComputedStyle(el);
                    return style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0';
                }).length;
                const hiddenCredentialFields = Array.from(
                    document.querySelectorAll("input[type='password'], input[name*='pass' i], input[name*='otp' i]")
                ).filter((el) => {
                    const style = window.getComputedStyle(el);
                    return style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0';
                }).length;
                const visibleCredentialFields = Array.from(
                    document.querySelectorAll("input[type='password'], input[name*='pass' i], input[name*='otp' i]")
                ).filter((el) => {
                    const style = window.getComputedStyle(el);
                    return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
                }).length;
                const suspiciousOverlays = Array.from(document.querySelectorAll('*')).filter((el) => {
                    const style = window.getComputedStyle(el);
                    const cls = (el.className || '').toString().toLowerCase();
                    return style.position === 'fixed' && Number(style.zIndex || 0) >= 1000 &&
                        (cls.includes('modal') || cls.includes('overlay') || cls.includes('popup'));
                }).length;
                return {
                    forms: document.querySelectorAll('form').length,
                    iframes: document.querySelectorAll('iframe').length,
                    hiddenElements,
                    hiddenCredentialFields,
                    visibleCredentialFields,
                    suspiciousOverlays,
                    urgencyTextHits: (
                        document.body?.innerText?.match(/urgent|act now|final warning|verify account|security alert/gi) || []
                    ).length
                };
            }
            """
            try:
                snapshot = page.evaluate(script)
                return snapshot if isinstance(snapshot, dict) else {}
            except Exception:
                return {}

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.set_default_timeout(self.timeout_ms)
                page.set_default_navigation_timeout(self.timeout_ms)

                def on_popup(_popup) -> None:
                    nonlocal popup_count
                    popup_count += 1

                page.on("popup", on_popup)
                dialog_count = 0

                def on_dialog(dialog) -> None:
                    nonlocal dialog_count
                    dialog_count += 1
                    try:
                        dialog.dismiss()
                    except Exception:
                        pass

                page.on("dialog", on_dialog)

                try:
                    page.goto(url, wait_until="domcontentloaded")
                except PlaywrightTimeoutError:
                    signals.append(
                        self._signal(
                            code="interaction-page-timeout",
                            title="Interaction page load timeout",
                            description=(
                                "Dynamic interaction probing timed out during initial load; "
                                "behavioral evidence may be partial."
                            ),
                            severity="medium",
                            category="runtime",
                            score_impact=8,
                            confidence=0.64,
                        )
                    )
                except Exception as exc:
                    return InteractionSimulationResult(
                        runtime_note=f"interaction-navigation-failed: {exc}",
                        signals=[
                            self._signal(
                                code="interaction-navigation-failed",
                                title="Interaction simulation navigation failure",
                                description="Dynamic interaction probing could not load the target URL.",
                                severity="low",
                                category="runtime",
                                score_impact=4,
                                confidence=0.61,
                            )
                        ],
                    )

                baseline = page_snapshot(page)
                unique_targets: list[str] = []
                for selector in SUSPICIOUS_CLICK_SELECTORS:
                    try:
                        count = page.locator(selector).count()
                    except Exception:
                        continue
                    if count <= 0:
                        continue
                    unique_targets.append(selector)
                    if len(unique_targets) >= self.max_actions:
                        break

                if not unique_targets:
                    context.close()
                    browser.close()
                    return InteractionSimulationResult(
                        events=[],
                        signals=[],
                        metadata={
                            "interaction_actions_attempted": 0,
                            "popup_count": popup_count,
                            "dialog_count": dialog_count,
                            "baseline_snapshot": baseline,
                        },
                    )

                current_confidence = 0.35
                for index, selector in enumerate(unique_targets, start=1):
                    step_time = interaction_start + timedelta(seconds=index)
                    url_before = page.url
                    before = page_snapshot(page)
                    action_name = "click"
                    try:
                        page.locator(selector).first.click(force=True, timeout=2000)
                        page.wait_for_timeout(900)
                    except Exception:
                        action_name = "click-attempt"

                    after = page_snapshot(page)
                    url_after = page.url
                    redirect_triggered = url_before != url_after
                    mutations = self._mutation_diff(before, after)
                    new_indicator_codes: list[str] = []

                    if redirect_triggered:
                        new_indicator_codes.append("interaction-triggered-redirect")
                    if mutations.get("visible_credential_fields_increase", 0) > 0:
                        new_indicator_codes.append("interaction-hidden-credential-reveal")
                    if mutations.get("forms_increase", 0) > 0:
                        new_indicator_codes.append("interaction-dynamic-form-injection")
                    if mutations.get("overlays_increase", 0) > 0:
                        new_indicator_codes.append("interaction-overlay-injection")
                    if mutations.get("iframes_increase", 0) > 0:
                        new_indicator_codes.append("interaction-iframe-insertion")
                    if dialog_count > 0 or popup_count > 0:
                        new_indicator_codes.append("interaction-popup-scare-flow")

                    if new_indicator_codes:
                        current_confidence = min(0.97, current_confidence + 0.13)
                    else:
                        current_confidence = min(0.97, current_confidence + 0.04)

                    events.append(
                        InteractionReplayEvent(
                            step_id=f"sim-{index:03d}",
                            timestamp=step_time.isoformat(),
                            action=action_name,
                            target=selector,
                            url_before=url_before,
                            url_after=url_after,
                            redirect_triggered=redirect_triggered,
                            new_indicator_codes=new_indicator_codes,
                            dom_mutations=mutations,
                            confidence_after=round(current_confidence, 2),
                        )
                    )

                    for code in new_indicator_codes:
                        if code == "interaction-triggered-redirect":
                            signals.append(
                                self._signal(
                                    code=code,
                                    title="Interaction-triggered redirect",
                                    description=(
                                        "Controlled interaction changed navigation target, indicating "
                                        "click-activated redirect behavior."
                                    ),
                                    severity="high",
                                    category="behavioral-flow",
                                    score_impact=20,
                                    confidence=0.88,
                                )
                            )
                        elif code == "interaction-hidden-credential-reveal":
                            signals.append(
                                self._signal(
                                    code=code,
                                    title="Hidden credential form revealed after interaction",
                                    description=(
                                        "Credential input fields became visible only after simulated "
                                        "user action, consistent with staged phishing flow."
                                    ),
                                    severity="critical",
                                    category="credential-harvest",
                                    score_impact=26,
                                    confidence=0.93,
                                )
                            )
                        elif code == "interaction-dynamic-form-injection":
                            signals.append(
                                self._signal(
                                    code=code,
                                    title="Dynamically injected phishing form",
                                    description=(
                                        "Additional form elements appeared after interaction, suggesting "
                                        "script-driven credential capture stages."
                                    ),
                                    severity="high",
                                    category="credential-harvest",
                                    score_impact=22,
                                    confidence=0.89,
                                )
                            )
                        elif code == "interaction-overlay-injection":
                            signals.append(
                                self._signal(
                                    code=code,
                                    title="Interaction-triggered login overlay injection",
                                    description=(
                                        "Fixed high-priority overlay/modal elements appeared after "
                                        "interaction, indicating deceptive login prompt behavior."
                                    ),
                                    severity="high",
                                    category="social-engineering",
                                    score_impact=21,
                                    confidence=0.86,
                                )
                            )
                        elif code == "interaction-iframe-insertion":
                            signals.append(
                                self._signal(
                                    code=code,
                                    title="Dynamic iframe insertion after interaction",
                                    description=(
                                        "New iframe elements were inserted following user interaction, "
                                        "a common delivery pattern for staged phishing pages."
                                    ),
                                    severity="medium",
                                    category="delivery",
                                    score_impact=15,
                                    confidence=0.79,
                                )
                            )
                        elif code == "interaction-popup-scare-flow":
                            signals.append(
                                self._signal(
                                    code=code,
                                    title="Popup or dialog scareware flow",
                                    description=(
                                        "Interaction triggered popup/dialog behavior associated with "
                                        "fake security warnings and coercive phishing flows."
                                    ),
                                    severity="medium",
                                    category="social-engineering",
                                    score_impact=14,
                                    confidence=0.76,
                                )
                            )

                metadata = {
                    "interaction_actions_attempted": len(unique_targets),
                    "popup_count": popup_count,
                    "dialog_count": dialog_count,
                    "baseline_snapshot": baseline,
                    "final_url": page.url,
                    "redirect_observed": any(event.redirect_triggered for event in events),
                }
                context.close()
                browser.close()
        except Exception as exc:
            logger.warning("Interaction simulation failed: %s", exc)
            return InteractionSimulationResult(
                runtime_note=f"interaction-runtime-failed: {exc}",
                signals=[
                    self._signal(
                        code="interaction-runtime-failed",
                        title="Interaction simulation runtime failure",
                        description="Dynamic probing encountered a runtime failure and was partially skipped.",
                        severity="low",
                        category="runtime",
                        score_impact=4,
                        confidence=0.6,
                    )
                ],
            )

        signals = self._dedupe_signals(signals)
        return InteractionSimulationResult(events=events, signals=signals, metadata=metadata)

    def _mutation_diff(self, before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
        def delta(key: str) -> int:
            return int(after.get(key, 0)) - int(before.get(key, 0))

        return {
            "forms_increase": max(0, delta("forms")),
            "iframes_increase": max(0, delta("iframes")),
            "visible_credential_fields_increase": max(0, delta("visibleCredentialFields")),
            "hidden_credential_fields_decrease": max(0, int(before.get("hiddenCredentialFields", 0)) - int(after.get("hiddenCredentialFields", 0))),
            "overlays_increase": max(0, delta("suspiciousOverlays")),
            "hidden_elements_change": delta("hiddenElements"),
            "urgency_text_hits_increase": max(0, delta("urgencyTextHits")),
        }

    def _signal(
        self,
        *,
        code: str,
        title: str,
        description: str,
        severity: str,
        category: str,
        score_impact: int,
        confidence: float,
    ) -> SignalEvidence:
        return SignalEvidence(
            code=code,
            title=title,
            description=description,
            severity=severity,
            source="interaction",
            category=category,
            score_impact=score_impact,
            confidence=confidence,
            value=None,
        )

    def _dedupe_signals(self, signals: list[SignalEvidence]) -> list[SignalEvidence]:
        deduped: list[SignalEvidence] = []
        seen: set[str] = set()
        for signal in signals:
            key = signal.code
            if key in seen:
                continue
            seen.add(key)
            deduped.append(signal)
        return deduped
