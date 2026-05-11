from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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
BENIGN_CLICK_PATTERNS = (
    "accept all",
    "cookie",
    "newsletter",
    "subscribe",
    "learn more",
    "privacy",
    "terms",
    "continue with google",
    "continue with microsoft",
    "sign in with google",
    "sign in with microsoft",
    "continue with apple",
)
SUSPICIOUS_CLICK_PATTERNS = (
    "verify",
    "unlock",
    "reactivate",
    "security",
    "confirm",
    "continue",
    "suspend",
    "password",
    "login",
    "sign in",
)


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
        self._runtime_disabled_note: str | None = None
        self._runtime_checked = False

    def simulate(self, url: str) -> InteractionSimulationResult:
        if not self.enabled:
            return InteractionSimulationResult(
                runtime_note="interaction-simulation-disabled-by-configuration",
            )
        if self._runtime_disabled_note:
            return InteractionSimulationResult(
                runtime_note=self._runtime_disabled_note,
                signals=[],
            )
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            self._runtime_disabled_note = f"playwright-unavailable: {exc}"
            return InteractionSimulationResult(
                runtime_note=self._runtime_disabled_note,
                signals=[],
            )

        if not self._runtime_checked:
            runtime_probe_error = self._probe_playwright_runtime(sync_playwright)
            self._runtime_checked = True
            if runtime_probe_error:
                self._runtime_disabled_note = runtime_probe_error
                return InteractionSimulationResult(runtime_note=runtime_probe_error, signals=[])

        events: list[InteractionReplayEvent] = []
        signals: list[SignalEvidence] = []
        metadata: dict[str, Any] = {}
        popup_count = 0
        suppressed_indicators: list[dict[str, Any]] = []
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
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

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
                raw_candidates: list[dict[str, Any]] = []
                for selector in SUSPICIOUS_CLICK_SELECTORS:
                    try:
                        count = page.locator(selector).count()
                    except Exception:
                        continue
                    if count <= 0:
                        continue
                    for idx in range(min(2, count)):
                        locator = page.locator(selector).nth(idx)
                        text = ""
                        href = ""
                        html = ""
                        try:
                            text = (locator.inner_text(timeout=800) or "").strip()
                        except Exception:
                            text = ""
                        try:
                            href = (locator.get_attribute("href", timeout=800) or "").strip()
                        except Exception:
                            href = ""
                        try:
                            html = (locator.evaluate("el => el.outerHTML") or "")[:400]
                        except Exception:
                            html = ""
                        score = self._target_suspicion_score(text=text, href=href, selector=selector)
                        if score <= 0:
                            continue
                        raw_candidates.append(
                            {
                                "selector": selector,
                                "index": idx,
                                "score": score,
                                "text": text[:120],
                                "href": href[:200],
                                "html_snippet": html,
                            }
                        )
                raw_candidates.sort(key=lambda item: item["score"], reverse=True)
                unique_targets = raw_candidates[: self.max_actions]

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
                            "calibration_note": "No high-suspicion interaction targets identified.",
                        },
                    )

                current_confidence = 0.35
                for index, target in enumerate(unique_targets, start=1):
                    selector = str(target["selector"])
                    target_index = int(target["index"])
                    step_time = interaction_start + timedelta(seconds=index)
                    url_before = page.url
                    before = page_snapshot(page)
                    action_name = "click"
                    try:
                        page.locator(selector).nth(target_index).click(force=True, timeout=2000)
                        page.wait_for_timeout(900)
                    except Exception:
                        action_name = "click-attempt"

                    after = page_snapshot(page)
                    url_after = page.url
                    redirect_triggered = self._is_suspicious_redirect(url_before=url_before, url_after=url_after)
                    mutations = self._mutation_diff(before, after)
                    significance = self._mutation_significance(mutations, redirect_triggered)
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
                    if significance < 4 and "interaction-popup-scare-flow" in new_indicator_codes:
                        new_indicator_codes.remove("interaction-popup-scare-flow")
                        suppressed_indicators.append(
                            {
                                "code": "interaction-popup-scare-flow",
                                "reason": (
                                    "Popup/dialog activity downgraded because mutation significance "
                                    "and phishing corroboration were low."
                                ),
                                "selector": selector,
                                "target_index": target_index,
                                "significance": significance,
                            }
                        )

                    if new_indicator_codes:
                        current_confidence = min(0.97, current_confidence + 0.1 + min(0.06, significance * 0.01))
                    else:
                        current_confidence = min(0.97, current_confidence + 0.02)

                    events.append(
                        InteractionReplayEvent(
                            step_id=f"sim-{index:03d}",
                            timestamp=step_time.isoformat(),
                            action=action_name,
                            target=f"{selector}#{target_index}",
                            url_before=url_before,
                            url_after=url_after,
                            redirect_triggered=redirect_triggered,
                            new_indicator_codes=new_indicator_codes,
                            dom_mutations={
                                **mutations,
                                "significance_score": significance,
                                "target_score": int(target["score"]),
                                "target_text": target["text"],
                                "target_href": target["href"],
                            },
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
                                    score_impact=18 if significance < 7 else 22,
                                    confidence=0.88,
                                    reasoning_context=(
                                        "Redirect fired only after user-action simulation and was evaluated as "
                                        "cross-origin or suspicious-path navigation."
                                    ),
                                    analyst_details={
                                        "selector": selector,
                                        "target_index": target_index,
                                        "url_before": url_before,
                                        "url_after": url_after,
                                        "mutation_significance": significance,
                                        "target_html_snippet": target.get("html_snippet"),
                                    },
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
                                    score_impact=24 if significance < 7 else 27,
                                    confidence=0.9 if significance < 7 else 0.94,
                                    reasoning_context=(
                                        "Credential fields became visible after simulated click, indicating "
                                        "staged phishing reveal flow."
                                    ),
                                    analyst_details={
                                        "selector": selector,
                                        "target_index": target_index,
                                        "mutations": mutations,
                                        "target_html_snippet": target.get("html_snippet"),
                                    },
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
                                    score_impact=19 if significance < 7 else 23,
                                    confidence=0.84 if significance < 7 else 0.9,
                                    reasoning_context=(
                                        "Post-click increase in form count indicates dynamic injection behavior."
                                    ),
                                    analyst_details={
                                        "selector": selector,
                                        "target_index": target_index,
                                        "mutations": mutations,
                                    },
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
                                    score_impact=17 if significance < 7 else 21,
                                    confidence=0.8 if significance < 7 else 0.87,
                                    reasoning_context=(
                                        "Overlay/modal surfaced after interaction with high z-index profile."
                                    ),
                                    analyst_details={
                                        "selector": selector,
                                        "target_index": target_index,
                                        "mutations": mutations,
                                    },
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
                                    score_impact=12 if significance < 7 else 16,
                                    confidence=0.73 if significance < 7 else 0.81,
                                    reasoning_context="New iframe nodes appeared during interaction replay.",
                                    analyst_details={
                                        "selector": selector,
                                        "target_index": target_index,
                                        "mutations": mutations,
                                    },
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
                                    score_impact=8 if significance < 7 else 14,
                                    confidence=0.62 if significance < 7 else 0.78,
                                    reasoning_context=(
                                        "Popup/dialog sequence triggered by interaction and correlated with "
                                        "mutation significance."
                                    ),
                                    analyst_details={
                                        "selector": selector,
                                        "target_index": target_index,
                                        "popup_count": popup_count,
                                        "dialog_count": dialog_count,
                                        "mutations": mutations,
                                    },
                                )
                            )

                metadata = {
                    "interaction_actions_attempted": len(unique_targets),
                    "popup_count": popup_count,
                    "dialog_count": dialog_count,
                    "baseline_snapshot": baseline,
                    "final_url": page.url,
                    "redirect_observed": any(event.redirect_triggered for event in events),
                    "target_candidates": unique_targets,
                    "suppressed_interaction_indicators": suppressed_indicators,
                }
                context.close()
                browser.close()
        except Exception as exc:
            if "Executable doesn't exist" in str(exc):
                self._runtime_disabled_note = (
                    "playwright-browser-missing: run `playwright install chromium` to enable interaction simulation."
                )
            logger.warning("Interaction simulation failed: %s", exc)
            return InteractionSimulationResult(
                runtime_note=f"interaction-runtime-failed: {exc}",
                signals=[],
            )

        signals = self._dedupe_signals(signals)
        return InteractionSimulationResult(events=events, signals=signals, metadata=metadata)

    def _probe_playwright_runtime(self, sync_playwright) -> str | None:
        try:
            with sync_playwright() as p:
                executable = p.chromium.executable_path
        except Exception as exc:
            return f"playwright-runtime-probe-failed: {exc}"

        if not executable:
            return "playwright-runtime-probe-failed: chromium executable path unavailable."
        if not Path(executable).exists():
            return (
                "playwright-browser-missing: run `playwright install chromium` to enable interaction simulation."
            )
        return None

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

    def _mutation_significance(self, mutations: dict[str, int], redirect_triggered: bool) -> int:
        score = 0
        score += mutations.get("visible_credential_fields_increase", 0) * 4
        score += mutations.get("forms_increase", 0) * 3
        score += mutations.get("overlays_increase", 0) * 3
        score += mutations.get("iframes_increase", 0) * 2
        score += mutations.get("urgency_text_hits_increase", 0) * 1
        if redirect_triggered:
            score += 4
        return min(25, max(0, score))

    def _target_suspicion_score(self, *, text: str, href: str, selector: str) -> int:
        normalized_text = text.lower()
        normalized_href = href.lower()
        score = 0
        if any(token in normalized_text for token in SUSPICIOUS_CLICK_PATTERNS):
            score += 6
        if any(token in normalized_href for token in ("verify", "secure", "login", "auth", "session")):
            score += 4
        if "button:has-text" in selector:
            score += 1
        if any(token in normalized_text for token in BENIGN_CLICK_PATTERNS):
            score -= 8
        if any(token in normalized_href for token in ("privacy", "terms", "cookie", "help", "support")):
            score -= 3
        return score

    def _is_suspicious_redirect(self, *, url_before: str, url_after: str) -> bool:
        if url_before == url_after:
            return False
        before = urlparse(url_before)
        after = urlparse(url_after)
        before_host = (before.hostname or "").lower()
        after_host = (after.hostname or "").lower()
        if not before_host or not after_host:
            return True
        if before_host != after_host:
            if any(
                token in after_host
                for token in ("google.com", "microsoftonline.com", "apple.com", "okta.com", "auth0.com")
            ):
                return False
            return True
        suspicious_path = re.search(r"verify|secure|session|login|account|update", after.path.lower()) is not None
        return suspicious_path and before.path != after.path

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
        reasoning_context: str | None = None,
        analyst_details: dict[str, Any] | None = None,
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
            reliability=max(0.2, min(0.98, confidence - 0.05)),
            reasoning_context=reasoning_context,
            escalation_contribution=score_impact,
            source_module="interaction_simulator",
            analyst_details=analyst_details or {},
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
