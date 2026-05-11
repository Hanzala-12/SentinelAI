from __future__ import annotations

import ipaddress
import math
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

from backend.intelligence.models import SEVERITY_DEFAULT_IMPACT, SignalEvidence, SignalExtractionResult


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "lnkd.in",
    "buff.ly",
    "rb.gy",
    "s.id",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "xyz",
    "top",
    "click",
    "link",
    "shop",
    "country",
    "work",
    "gq",
    "tk",
}

SUSPICIOUS_QUERY_KEYS = {
    "redirect",
    "redirect_uri",
    "next",
    "continue",
    "url",
    "dest",
    "destination",
    "callback",
    "token",
    "session",
    "email",
    "username",
    "user",
    "password",
    "pass",
    "otp",
    "pin",
    "verify",
    "login",
}

BRAND_KEYWORDS = {
    "paypal",
    "microsoft",
    "office365",
    "apple",
    "amazon",
    "google",
    "instagram",
    "facebook",
    "meta",
    "dropbox",
    "coinbase",
    "binance",
    "netflix",
    "bankofamerica",
    "wellsfargo",
    "chase",
}

CREDENTIAL_INPUT_NAMES = {
    "password",
    "pass",
    "passwd",
    "email",
    "username",
    "user",
    "otp",
    "pin",
    "card",
    "cvv",
    "ssn",
}

HIDDEN_STYLE_PATTERN = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|left\s*:\s*-?\d{3,}px",
    re.IGNORECASE,
)
OBFUSCATION_PATTERN = re.compile(
    r"eval\s*\(|atob\s*\(|fromcharcode\s*\(|unescape\s*\(|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}",
    re.IGNORECASE,
)
REDIRECT_SCRIPT_PATTERN = re.compile(
    r"window\.location|location\.href|location\.replace|window\.open|meta\s+http-equiv=['\"]refresh",
    re.IGNORECASE,
)
SUSPICIOUS_EVENT_LISTENER_PATTERN = re.compile(
    r"addeventlistener\s*\(\s*['\"](submit|beforeunload|keydown|keypress|copy|paste|contextmenu)['\"]",
    re.IGNORECASE,
)
CLIPBOARD_PATTERN = re.compile(
    r"navigator\.clipboard|clipboarddata|document\.execcommand\s*\(\s*['\"]copy['\"]",
    re.IGNORECASE,
)
NOTIFICATION_ABUSE_PATTERN = re.compile(
    r"notification\.requestpermission|new\s+notification\s*\(|serviceworker\.register",
    re.IGNORECASE,
)
ANTI_INTERACTION_PATTERN = re.compile(
    r"onbeforeunload|preventdefault\s*\(\s*\)|returnvalue\s*=|event\.button\s*==\s*2|contextmenu",
    re.IGNORECASE,
)
FULLSCREEN_COERCION_PATTERN = re.compile(
    r"requestfullscreen|webkitrequestfullscreen|mozrequestfullscreen|msrequestfullscreen",
    re.IGNORECASE,
)
POPUP_TRICK_PATTERN = re.compile(
    r"window\.open\s*\(|alert\s*\(|confirm\s*\(|prompt\s*\(",
    re.IGNORECASE,
)
SUSPENSION_LANGUAGE_PATTERN = re.compile(
    r"\b(account\s+(suspended|locked|disabled)|security\s+hold|verify\s+immediately)\b",
    re.IGNORECASE,
)
URGENCY_BANNER_PATTERN = re.compile(
    r"\b(urgent|act now|final warning|expires (today|soon)|limited time)\b",
    re.IGNORECASE,
)
TRUSTED_OAUTH_HINTS = (
    "accounts.google.com",
    "login.microsoftonline.com",
    "appleid.apple.com",
    "github.com/login/oauth",
    "auth0.com",
    "okta.com",
)
BENIGN_NOTIFICATION_HINTS = (
    "allow notifications for updates",
    "enable notifications",
    "get updates in browser",
)
BENIGN_MFA_HINTS = (
    "enter the 6-digit code",
    "one-time code",
    "authenticator app",
    "two-factor authentication",
)
TRUSTED_SUFFIXES = {
    "gov",
    "gov.pk",
    "gov.uk",
    "edu",
    "edu.pk",
    "ac.uk",
    "mil",
    "mil.pk",
}
TRUSTED_TRANSPORT_KEYWORDS = (
    "metro",
    "railway",
    "transit",
    "transport",
    "airline",
    "airport",
    "bus",
    "ticketing",
)
TRUSTED_ENTERPRISE_DOMAINS = {
    "microsoft.com",
    "microsoftonline.com",
    "google.com",
    "apple.com",
    "github.com",
    "okta.com",
    "auth0.com",
    "salesforce.com",
    "amazonaws.com",
    "atlassian.net",
    "zoom.us",
    "slack.com",
}
LEGIT_BRAND_DOMAIN_TOKENS = {
    "microsoftonline",
    "bankofamerica",
    "wellsfargo",
}
WEAK_CONTEXT_TERMS = (
    "mailto",
    "contact",
    "support email",
    "footer",
    "newsletter",
    "subscribe",
)


class ThreatSignalExtractor:
    def __init__(self, timeout_seconds: float = 8.0, max_text_chars: int = 20000) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_text_chars = max_text_chars

    def extract(
        self,
        url: str,
        page_text: str | None = None,
        page_html: str | None = None,
        fetch_remote: bool = True,
    ) -> SignalExtractionResult:
        normalized_url = self._normalize_url(url)
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or ""

        fetched_html = False
        redirect_chain: list[str] = []
        fetch_error: str | None = None
        html = page_html or ""

        if not html and fetch_remote:
            html, redirect_chain, fetch_error = self._fetch_page(normalized_url)
            fetched_html = bool(html)

        soup = BeautifulSoup(html, "html.parser") if html else None
        text_for_analysis = (page_text or "").strip()
        if not text_for_analysis and soup:
            text_for_analysis = soup.get_text(separator=" ", strip=True)[: self.max_text_chars]

        url_signals, url_metadata = self._extract_url_signals(normalized_url, parsed)
        trust_profile = self._build_domain_trust_profile(
            normalized_url=normalized_url,
            hostname=hostname,
            url_metadata=url_metadata,
        )
        url_metadata["domain_trust"] = trust_profile
        dom_signals = self._extract_dom_signals(
            normalized_url=normalized_url,
            hostname=hostname,
            soup=soup,
            raw_html=html,
        )
        content_signals = self._extract_content_signals(text_for_analysis)
        suppression_records = self._apply_contextual_suppression(
            normalized_url=normalized_url,
            hostname=hostname,
            soup=soup,
            page_text=text_for_analysis,
            url_signals=url_signals,
            dom_signals=dom_signals,
            content_signals=content_signals,
            trust_profile=trust_profile,
        )
        if suppression_records:
            url_metadata["suppressed_detections"] = suppression_records

        return SignalExtractionResult(
            normalized_url=normalized_url,
            hostname=hostname,
            url_signals=url_signals,
            dom_signals=dom_signals,
            content_signals=content_signals,
            redirect_chain=redirect_chain,
            fetched_html=fetched_html,
            page_text_excerpt=text_for_analysis[:800],
            fetch_error=fetch_error,
            metadata=url_metadata,
        )

    def _extract_url_signals(self, normalized_url: str, parsed) -> tuple[list[SignalEvidence], dict[str, Any]]:
        hostname = parsed.hostname or ""
        domain_info = tldextract.extract(normalized_url)
        base_domain = ".".join(part for part in [domain_info.domain, domain_info.suffix] if part)
        tld = domain_info.suffix.split(".")[-1].lower() if domain_info.suffix else ""
        path = parsed.path or ""
        query = parsed.query or ""

        signals: list[SignalEvidence] = []
        metadata: dict[str, Any] = {
            "base_domain": base_domain,
            "tld": tld,
            "path_length": len(path),
            "query_length": len(query),
        }

        if self._is_ip_host(hostname):
            signals.append(
                self._signal(
                    code="url-ip-host",
                    title="IP-based URL host",
                    description="The URL uses a direct IP address instead of a registered domain.",
                    severity="high",
                    source="url",
                    category="infrastructure",
                    score_impact=24,
                    confidence=0.92,
                )
            )

        if parsed.scheme != "https":
            signals.append(
                self._signal(
                    code="url-non-https",
                    title="Unencrypted HTTP transport",
                    description="The target does not use HTTPS, increasing interception and tampering risk.",
                    severity="medium",
                    source="url",
                    category="transport",
                    score_impact=11,
                    confidence=0.84,
                )
            )

        if "@" in normalized_url:
            signals.append(
                self._signal(
                    code="url-at-symbol",
                    title="Credential separator character in URL",
                    description="The URL contains '@', a pattern commonly used to obscure destination hosts.",
                    severity="high",
                    source="url",
                    category="obfuscation",
                    score_impact=22,
                    confidence=0.93,
                )
            )

        if base_domain.lower() in SHORTENER_DOMAINS or hostname.lower() in SHORTENER_DOMAINS:
            signals.append(
                self._signal(
                    code="url-shortener",
                    title="Known URL shortener usage",
                    description="Shortened links can hide destination context and evade user trust checks.",
                    severity="high",
                    source="url",
                    category="obfuscation",
                    score_impact=18,
                    confidence=0.87,
                )
            )

        subdomain_depth = self._subdomain_depth(domain_info.subdomain)
        metadata["subdomain_depth"] = subdomain_depth
        if subdomain_depth >= 3:
            severity = "high" if subdomain_depth >= 5 else "medium"
            signals.append(
                self._signal(
                    code="url-excessive-subdomains",
                    title="Excessive subdomain depth",
                    description=f"Host includes {subdomain_depth} subdomain levels, which can hide malicious destinations.",
                    severity=severity,
                    source="url",
                    category="structure",
                    score_impact=20 if severity == "high" else 13,
                    confidence=0.8,
                    value=subdomain_depth,
                )
            )

        entropy = self._shannon_entropy(hostname)
        metadata["hostname_entropy"] = round(entropy, 3)
        if entropy >= 4.2:
            signals.append(
                self._signal(
                    code="url-high-entropy-host",
                    title="High-entropy hostname",
                    description="Hostname complexity is unusually high, which is common in generated phishing domains.",
                    severity="high",
                    source="url",
                    category="structure",
                    score_impact=18,
                    confidence=0.79,
                    value=round(entropy, 3),
                )
            )
        elif entropy >= 3.7:
            signals.append(
                self._signal(
                    code="url-medium-entropy-host",
                    title="Unusual hostname randomness",
                    description="Hostname appears random and may indicate disposable infrastructure.",
                    severity="medium",
                    source="url",
                    category="structure",
                    score_impact=11,
                    confidence=0.72,
                    value=round(entropy, 3),
                )
            )

        if tld in SUSPICIOUS_TLDS:
            signals.append(
                self._signal(
                    code="url-suspicious-tld",
                    title="Suspicious or abuse-prone TLD",
                    description=f"The domain uses .{tld}, which appears frequently in abuse telemetry.",
                    severity="medium",
                    source="url",
                    category="infrastructure",
                    score_impact=12,
                    confidence=0.78,
                    value=tld,
                )
            )

        unicode_host = any(ord(ch) > 127 for ch in hostname)
        punycode_host = "xn--" in hostname.lower()
        metadata["unicode_host"] = unicode_host
        metadata["punycode_host"] = punycode_host
        if unicode_host or punycode_host:
            signals.append(
                self._signal(
                    code="url-idn-spoof-risk",
                    title="Internationalized domain spoofing risk",
                    description="The host uses Unicode/Punycode representation that can support lookalike spoofing.",
                    severity="high",
                    source="url",
                    category="spoofing",
                    score_impact=19,
                    confidence=0.82,
                )
            )

        typosquat = self._detect_typosquatting(domain_info.domain.lower())
        metadata["typosquat_candidate"] = typosquat
        if typosquat:
            signals.append(
                self._signal(
                    code="url-typosquat-pattern",
                    title=f"Typosquatting pattern against '{typosquat}'",
                    description="Domain string closely resembles a well-known brand and may be impersonation infrastructure.",
                    severity="high",
                    source="url",
                    category="spoofing",
                    score_impact=23,
                    confidence=0.88,
                    value=typosquat,
                )
            )

        suspicious_params = [
            key
            for key, _ in parse_qsl(query, keep_blank_values=True)
            if key.lower() in SUSPICIOUS_QUERY_KEYS
        ]
        metadata["suspicious_query_params"] = suspicious_params
        if len(suspicious_params) >= 2:
            signals.append(
                self._signal(
                    code="url-suspicious-query-params",
                    title="Suspicious query parameter set",
                    description=(
                        "The URL query contains multiple sensitive control parameters "
                        f"({', '.join(sorted(set(suspicious_params))[:5])})."
                    ),
                    severity="medium",
                    source="url",
                    category="delivery",
                    score_impact=12,
                    confidence=0.76,
                )
            )

        encoded_octets = len(re.findall(r"%[0-9a-fA-F]{2}", normalized_url))
        long_encoded_segment = any(self._looks_like_base64(segment) for segment in path.split("/") if segment)
        metadata["encoded_octets"] = encoded_octets
        metadata["long_encoded_segment"] = long_encoded_segment
        if encoded_octets >= 8 or long_encoded_segment:
            signals.append(
                self._signal(
                    code="url-encoded-payload",
                    title="Encoded payload indicators in URL",
                    description="Path/query includes heavy encoding, often used to hide redirects or payload selectors.",
                    severity="high" if encoded_octets >= 14 else "medium",
                    source="url",
                    category="obfuscation",
                    score_impact=17 if encoded_octets >= 14 else 11,
                    confidence=0.8,
                )
            )

        path_depth = len([segment for segment in path.split("/") if segment])
        metadata["path_depth"] = path_depth
        if path_depth >= 6:
            signals.append(
                self._signal(
                    code="url-deep-path",
                    title="Deep nested path structure",
                    description=f"The URL path depth ({path_depth}) may be used to camouflage phishing endpoints.",
                    severity="medium",
                    source="url",
                    category="structure",
                    score_impact=9,
                    confidence=0.67,
                )
            )

        return signals, metadata

    def _extract_dom_signals(
        self,
        normalized_url: str,
        hostname: str,
        soup: BeautifulSoup | None,
        raw_html: str,
    ) -> list[SignalEvidence]:
        if not soup:
            return []

        signals: list[SignalEvidence] = []
        parsed = urlparse(normalized_url)

        forms = soup.find_all("form")
        credential_forms = 0
        hidden_credential_forms = 0
        hidden_password_fields = 0
        invisible_login_overlays = 0

        for form in forms:
            action = (form.get("action") or "").strip()
            inputs = form.find_all("input")
            credential_inputs = 0
            for input_tag in inputs:
                input_type = (input_tag.get("type") or "").lower()
                input_name = (input_tag.get("name") or "").lower()
                if input_type == "password" or any(token in input_name for token in CREDENTIAL_INPUT_NAMES):
                    credential_inputs += 1
                if input_type == "password" and self._element_hidden(input_tag):
                    hidden_password_fields += 1

            if credential_inputs == 0:
                continue

            credential_forms += 1
            is_hidden = self._element_hidden(form)
            if is_hidden:
                hidden_credential_forms += 1
            style = (form.get("style") or "").lower()
            class_name = " ".join(form.get("class") or []).lower()
            if ("position:fixed" in style or "overlay" in class_name) and credential_inputs >= 2:
                invisible_login_overlays += 1

            if action in {"", "about:blank"} or action.lower().startswith("javascript:"):
                signals.append(
                    self._signal(
                        code="dom-credential-form-blank-action",
                        title="Credential form with blank or script action",
                        description="A credential collection form has no trustworthy submission target.",
                        severity="high",
                        source="dom",
                        category="credential-harvest",
                        score_impact=22,
                        confidence=0.9,
                        reasoning_context="Credential collection form action is empty/script-driven.",
                        analyst_details={
                            "form_action": action or "(empty)",
                            "css_style": (form.get("style") or "")[:400],
                            "form_snippet": str(form)[:420],
                        },
                    )
                )
            elif self._is_external_destination(action, hostname):
                signals.append(
                    self._signal(
                        code="dom-external-credential-post",
                        title="Credential submission to external origin",
                        description=f"Login-like form posts data to a different origin: {action}.",
                        severity="critical",
                        source="dom",
                        category="credential-harvest",
                        score_impact=30,
                        confidence=0.96,
                        reasoning_context=(
                            "Credential form submits to unrelated origin, high-confidence harvest behavior."
                        ),
                        analyst_details={
                            "form_action": action,
                            "source_hostname": hostname,
                            "form_snippet": str(form)[:420],
                        },
                    )
                )
            elif parsed.scheme == "https" and action.lower().startswith("http://"):
                signals.append(
                    self._signal(
                        code="dom-downgraded-form-post",
                        title="Credential submission downgraded to HTTP",
                        description="The page is HTTPS but submits sensitive data over unencrypted HTTP.",
                        severity="high",
                        source="dom",
                        category="credential-harvest",
                        score_impact=24,
                        confidence=0.92,
                        reasoning_context="Sensitive credential flow downgraded from HTTPS page to HTTP endpoint.",
                        analyst_details={
                            "form_action": action,
                            "source_scheme": parsed.scheme,
                            "form_snippet": str(form)[:420],
                        },
                    )
                )

        if hidden_credential_forms > 0:
            signals.append(
                self._signal(
                    code="dom-hidden-credential-form",
                    title="Hidden credential form detected",
                    description="At least one login/credential form is visually hidden, a frequent phishing evasion pattern.",
                    severity="high",
                    source="dom",
                    category="evasion",
                    score_impact=21,
                    confidence=0.88,
                    value=hidden_credential_forms,
                )
            )

        if hidden_password_fields > 0:
            signals.append(
                self._signal(
                    code="dom-hidden-password-field",
                    title="Hidden password input field",
                    description=(
                        "Detected password input elements with CSS/attribute visibility suppression, "
                        "consistent with covert credential capture."
                    ),
                    severity="high",
                    source="dom",
                    category="credential-harvest",
                    score_impact=23,
                    confidence=0.91,
                    value=hidden_password_fields,
                )
            )

        if invisible_login_overlays > 0:
            signals.append(
                self._signal(
                    code="dom-invisible-login-overlay",
                    title="Invisible login overlay pattern",
                    description=(
                        "Detected fixed-position login form structures likely used as deceptive overlay "
                        "elements to intercept credentials."
                    ),
                    severity="high",
                    source="dom",
                    category="credential-harvest",
                    score_impact=22,
                    confidence=0.84,
                    value=invisible_login_overlays,
                )
            )

        if credential_forms >= 2:
            signals.append(
                self._signal(
                    code="dom-multiple-credential-forms",
                    title="Multiple credential capture forms",
                    description="The page exposes several credential-like forms, uncommon for legitimate login workflows.",
                    severity="medium",
                    source="dom",
                    category="credential-harvest",
                    score_impact=13,
                    confidence=0.74,
                    value=credential_forms,
                )
            )

        iframes = soup.find_all("iframe")
        if iframes:
            invisible_iframes = 0
            for frame in iframes:
                width = (frame.get("width") or "").strip()
                height = (frame.get("height") or "").strip()
                style = (frame.get("style") or "").strip()
                if width in {"0", "1"} or height in {"0", "1"} or HIDDEN_STYLE_PATTERN.search(style):
                    invisible_iframes += 1
            if len(iframes) >= 3:
                signals.append(
                    self._signal(
                        code="dom-iframe-abuse",
                        title="Excessive iframe embedding",
                        description=f"Page contains {len(iframes)} iframes, increasing clickjacking and redirection risk.",
                        severity="medium",
                        source="dom",
                        category="delivery",
                        score_impact=14,
                        confidence=0.71,
                        value=len(iframes),
                    )
                )
            if invisible_iframes > 0:
                signals.append(
                    self._signal(
                        code="dom-invisible-iframe",
                        title="Invisible iframe elements",
                        description="One or more hidden iframes were detected, which can support covert redirects or overlays.",
                        severity="high",
                        source="dom",
                        category="evasion",
                        score_impact=20,
                        confidence=0.87,
                        value=invisible_iframes,
                    )
                )

        refresh_tags = soup.find_all(
            "meta",
            attrs={"http-equiv": lambda value: isinstance(value, str) and value.lower() == "refresh"},
        )
        if refresh_tags:
            signals.append(
                self._signal(
                    code="dom-meta-refresh-redirect",
                    title="Client-side meta refresh redirect",
                    description="Meta refresh redirect logic can be used to chain users into credential-harvest pages.",
                    severity="medium",
                    source="dom",
                    category="delivery",
                    score_impact=12,
                    confidence=0.78,
                )
            )

        script_tags = soup.find_all("script")
        external_scripts = 0
        for script in script_tags:
            src = (script.get("src") or "").strip()
            if src and self._is_external_destination(src, hostname):
                external_scripts += 1
        if script_tags and external_scripts / max(1, len(script_tags)) >= 0.7 and external_scripts >= 5:
            signals.append(
                self._signal(
                    code="dom-external-script-load",
                    title="High ratio of external scripts",
                    description=(
                        f"{external_scripts} out of {len(script_tags)} scripts load from external origins, "
                        "raising supply-chain and tampering risk."
                    ),
                    severity="medium",
                    source="dom",
                    category="supply-chain",
                    score_impact=12,
                    confidence=0.7,
                )
            )

        lower_html = raw_html.lower()
        if OBFUSCATION_PATTERN.search(lower_html):
            signals.append(
                    self._signal(
                        code="dom-obfuscated-javascript",
                    title="Obfuscated JavaScript indicators",
                    description="Script content includes common obfuscation patterns (eval/atob/fromCharCode escapes).",
                    severity="high",
                    source="dom",
                        category="evasion",
                        score_impact=18,
                        confidence=0.83,
                        analyst_details={
                            "js_excerpt": raw_html[:480],
                            "pattern": "eval/atob/fromCharCode or escape sequences",
                        },
                    )
                )

        if REDIRECT_SCRIPT_PATTERN.search(lower_html):
            signals.append(
                    self._signal(
                        code="dom-scripted-redirect-logic",
                    title="Scripted redirect behavior",
                    description="Client-side redirect behavior was detected in script or markup.",
                    severity="medium",
                    source="dom",
                        category="delivery",
                        score_impact=11,
                        confidence=0.73,
                        analyst_details={
                            "pattern": "window.location / location.href / meta refresh",
                            "js_excerpt": raw_html[:480],
                        },
                    )
                )

        if SUSPICIOUS_EVENT_LISTENER_PATTERN.search(lower_html):
            signals.append(
                    self._signal(
                        code="dom-suspicious-event-listeners",
                    title="Suspicious event listener hooks",
                    description=(
                        "Detected event listeners tied to submit/contextmenu/copy lifecycle, often used "
                        "for interaction tampering and data interception."
                    ),
                    severity="medium",
                    source="dom",
                        category="behavioral-manipulation",
                        score_impact=14,
                        confidence=0.78,
                        analyst_details={
                            "pattern": "addEventListener(submit/beforeunload/keydown/copy/contextmenu)",
                            "js_excerpt": raw_html[:480],
                        },
                    )
                )

        if CLIPBOARD_PATTERN.search(lower_html):
            signals.append(
                self._signal(
                    code="dom-clipboard-manipulation",
                    title="Clipboard manipulation logic",
                    description=(
                        "JavaScript includes clipboard read/write operations that can redirect pasted "
                        "wallets, credentials, or MFA codes."
                    ),
                    severity="high",
                    source="dom",
                    category="behavioral-manipulation",
                    score_impact=20,
                    confidence=0.86,
                )
            )

        if NOTIFICATION_ABUSE_PATTERN.search(lower_html):
            signals.append(
                self._signal(
                    code="dom-notification-abuse",
                    title="Browser notification abuse pattern",
                    description=(
                        "Detected notification permission/request script paths that are frequently abused "
                        "for persistent phishing prompts."
                    ),
                    severity="medium",
                    source="dom",
                    category="behavioral-manipulation",
                    score_impact=12,
                    confidence=0.74,
                )
            )

        if ANTI_INTERACTION_PATTERN.search(lower_html):
            signals.append(
                self._signal(
                    code="dom-anti-user-interaction",
                    title="Anti-user interaction controls",
                    description=(
                        "Detected script patterns that suppress navigation/interaction controls "
                        "(context-menu blocking, unload traps, forced preventDefault)."
                    ),
                    severity="medium",
                    source="dom",
                    category="behavioral-manipulation",
                    score_impact=14,
                    confidence=0.79,
                )
            )

        if FULLSCREEN_COERCION_PATTERN.search(lower_html):
            signals.append(
                self._signal(
                    code="dom-forced-fullscreen-attempt",
                    title="Forced fullscreen request logic",
                    description=(
                        "Page script attempts fullscreen mode to hide browser security context and "
                        "increase impersonation realism."
                    ),
                    severity="high",
                    source="dom",
                    category="behavioral-manipulation",
                    score_impact=18,
                    confidence=0.82,
                )
            )

        if POPUP_TRICK_PATTERN.search(lower_html):
            signals.append(
                self._signal(
                    code="dom-deceptive-popup-pattern",
                    title="Deceptive popup behavior",
                    description=(
                        "Detected popup/alert invocation patterns commonly used for fake session expiry "
                        "or fake support dialogs."
                    ),
                    severity="medium",
                    source="dom",
                    category="social-engineering",
                    score_impact=12,
                    confidence=0.71,
                )
            )

        page_text = soup.get_text(separator=" ", strip=True)
        suspicious_brand_mentions = self._suspicious_brand_mentions(page_text, hostname)
        if suspicious_brand_mentions:
            signals.append(
                self._signal(
                    code="dom-brand-impersonation-cues",
                    title="Potential brand impersonation cues",
                    description=(
                        "Page content references known brands while hosted on an unrelated domain "
                        f"({', '.join(suspicious_brand_mentions[:4])})."
                    ),
                    severity="high",
                    source="dom",
                    category="spoofing",
                    score_impact=19,
                    confidence=0.81,
                )
            )

        if SUSPENSION_LANGUAGE_PATTERN.search(page_text.lower()):
            signals.append(
                self._signal(
                    code="dom-account-suspension-language",
                    title="Account suspension coercion language",
                    description=(
                        "Page text contains account lock/suspension statements used to pressure rapid "
                        "credential submission."
                    ),
                    severity="high",
                    source="dom",
                    category="social-engineering",
                    score_impact=18,
                    confidence=0.84,
                )
            )

        if URGENCY_BANNER_PATTERN.search(page_text.lower()):
            signals.append(
                self._signal(
                    code="dom-urgency-banner-language",
                    title="Urgency banner phrasing",
                    description=(
                        "Detected urgency-driven banner language indicating deadline pressure tactics."
                    ),
                    severity="medium",
                    source="dom",
                    category="social-engineering",
                    score_impact=11,
                    confidence=0.72,
                )
            )

        hidden_elements = len(
            [
                tag
                for tag in soup.find_all(True)
                if self._element_hidden(tag) and tag.name not in {"script", "style", "meta", "link"}
            ]
        )
        fake_modal_candidates = 0
        for tag in soup.find_all(True):
            class_name = " ".join(tag.get("class") or []).lower()
            style = (tag.get("style") or "").lower()
            has_modal_identity = any(token in class_name for token in ("modal", "popup", "overlay", "dialog"))
            if not has_modal_identity:
                continue
            if "position:fixed" in style and "z-index" in style:
                fake_modal_candidates += 1
        if fake_modal_candidates > 0:
            signals.append(
                self._signal(
                    code="dom-fake-modal-injection",
                    title="Potential fake modal injection",
                    description=(
                        "Detected high-z-index fixed modal/overlay structures that may impersonate "
                        "security prompts or account re-authentication dialogs."
                    ),
                    severity="medium",
                    source="dom",
                    category="social-engineering",
                    score_impact=13,
                    confidence=0.76,
                    value=fake_modal_candidates,
                )
            )

        if hidden_elements >= 12:
            signals.append(
                self._signal(
                    code="dom-excessive-hidden-elements",
                    title="Excessive hidden page elements",
                    description="A large number of hidden elements were found, which can indicate deceptive rendering.",
                    severity="medium",
                    source="dom",
                    category="evasion",
                    score_impact=10,
                    confidence=0.64,
                    value=hidden_elements,
                )
            )

        return signals

    def _extract_content_signals(self, text: str) -> list[SignalEvidence]:
        if not text:
            return []

        lowered = text.lower()
        signals: list[SignalEvidence] = []

        pattern_catalog = [
            (
                "content-urgency-pressure",
                "Urgency pressure language",
                r"\b(urgent|immediately|act now|limited time|final warning|within \d+ (hours?|minutes?))\b",
                "medium",
                "social-engineering",
                12,
            ),
            (
                "content-scare-tactics",
                "Scare or fear-based messaging",
                r"\b(account (suspended|locked|disabled)|security alert|unauthorized login|legal action|permanent suspension)\b",
                "high",
                "social-engineering",
                17,
            ),
            (
                "content-fake-reward",
                "Fake reward or prize lure",
                r"\b(won|winner|gift card|reward|bonus|airdrop|claim your prize)\b",
                "medium",
                "fraud-lure",
                11,
            ),
            (
                "content-credential-request",
                "Direct credential verification request",
                r"\b(verify your account|confirm your password|re-enter your password|validate credentials|security verification)\b",
                "high",
                "credential-harvest",
                20,
            ),
            (
                "content-payment-pressure",
                "Payment or billing pressure wording",
                r"\b(update billing|payment failed|invoice overdue|confirm payment method|bank account verification)\b",
                "medium",
                "financial-fraud",
                13,
            ),
            (
                "content-impersonation-language",
                "Impersonation language",
                r"\b(customer support team|security team|account team|official notice|dear customer)\b",
                "medium",
                "spoofing",
                10,
            ),
        ]

        for code, title, pattern, severity, category, impact in pattern_catalog:
            raw_matches = re.findall(pattern, lowered, flags=re.IGNORECASE)
            if not raw_matches:
                continue
            matches = self._normalize_regex_matches(raw_matches)
            scaled_impact = min(28, impact + max(0, len(matches) - 1) * 2)
            preview = ", ".join(matches[:3]) if matches else "pattern match"
            signals.append(
                self._signal(
                    code=code,
                    title=title,
                    description=(
                        f"Detected {len(matches)} phishing-linked language matches "
                        f"({preview})."
                    ),
                    severity=severity,
                    source="content",
                    category=category,
                    score_impact=scaled_impact,
                    confidence=min(0.95, 0.66 + len(matches) * 0.05),
                    value=len(matches),
                )
            )

        exclamation_count = lowered.count("!")
        uppercase_ratio = self._uppercase_ratio(text)
        if exclamation_count >= 6 or uppercase_ratio >= 0.32:
            signals.append(
                self._signal(
                    code="content-emotional-amplification",
                    title="Emotional amplification patterns",
                    description=(
                        "Detected coercive formatting (uppercase ratio/exclamation density) "
                        "associated with social-engineering pressure."
                    ),
                    severity="low",
                    source="content",
                    category="social-engineering",
                    score_impact=8,
                    confidence=0.62,
                    value={"exclamation_count": exclamation_count, "uppercase_ratio": round(uppercase_ratio, 3)},
                )
            )

        return signals

    def _fetch_page(self, url: str) -> tuple[str, list[str], str | None]:
        try:
            response = requests.get(
                url,
                timeout=self.timeout_seconds,
                allow_redirects=True,
                headers={"User-Agent": "SentinelAI/2.0 (+threat-reasoning)"},
            )
            response.raise_for_status()
            redirects = [item.url for item in response.history]
            return response.text[:250000], redirects, None
        except Exception as exc:
            return "", [], f"page-fetch-failed: {exc}"

    def _normalize_url(self, url: str) -> str:
        if url.startswith(("http://", "https://")):
            return url
        return f"https://{url}"

    def _is_ip_host(self, hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    def _subdomain_depth(self, subdomain: str) -> int:
        if not subdomain:
            return 0
        return len([part for part in subdomain.split(".") if part and part.lower() != "www"])

    def _shannon_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        counts: dict[str, int] = {}
        for char in value:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        length = len(value)
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    def _looks_like_base64(self, segment: str) -> bool:
        if len(segment) < 24:
            return False
        return bool(re.fullmatch(r"[A-Za-z0-9_\-]+=*", segment))

    def _detect_typosquatting(self, domain_token: str) -> str | None:
        if not domain_token:
            return None
        if domain_token in LEGIT_BRAND_DOMAIN_TOKENS:
            return None
        for brand in BRAND_KEYWORDS:
            if domain_token == brand:
                return None
            if brand in domain_token and domain_token != brand:
                return brand
            distance = self._levenshtein(domain_token, brand)
            if distance == 1 and abs(len(domain_token) - len(brand)) <= 1:
                return brand
        return None

    def _levenshtein(self, left: str, right: str) -> int:
        if left == right:
            return 0
        if not left:
            return len(right)
        if not right:
            return len(left)

        prev_row = list(range(len(right) + 1))
        for i, left_char in enumerate(left, start=1):
            current_row = [i]
            for j, right_char in enumerate(right, start=1):
                insert_cost = current_row[j - 1] + 1
                delete_cost = prev_row[j] + 1
                replace_cost = prev_row[j - 1] + (0 if left_char == right_char else 1)
                current_row.append(min(insert_cost, delete_cost, replace_cost))
            prev_row = current_row
        return prev_row[-1]

    def _is_external_destination(self, target: str, hostname: str) -> bool:
        parsed_target = urlparse(target)
        if not parsed_target.netloc:
            return False
        target_host = (parsed_target.hostname or "").lower()
        current_host = hostname.lower()
        if not target_host or not current_host:
            return False
        return not (
            target_host == current_host
            or target_host.endswith(f".{current_host}")
            or current_host.endswith(f".{target_host}")
        )

    def _element_hidden(self, tag: Any) -> bool:
        if tag.has_attr("hidden"):
            return True
        style = (tag.get("style") or "").strip()
        class_name = " ".join(tag.get("class") or [])
        aria_hidden = (tag.get("aria-hidden") or "").lower() == "true"
        return bool(aria_hidden or HIDDEN_STYLE_PATTERN.search(style) or "hidden" in class_name.lower())

    def _suspicious_brand_mentions(self, text: str, hostname: str) -> list[str]:
        lowered_text = text.lower()
        lowered_host = hostname.lower()
        hits: list[str] = []
        for brand in BRAND_KEYWORDS:
            if brand in lowered_text and brand not in lowered_host:
                hits.append(brand)
        return hits

    def _uppercase_ratio(self, text: str) -> float:
        letters = [char for char in text if char.isalpha()]
        if not letters:
            return 0.0
        uppercase = [char for char in letters if char.isupper()]
        return len(uppercase) / len(letters)

    def _normalize_regex_matches(self, matches: list[Any]) -> list[str]:
        normalized: list[str] = []
        for match in matches:
            if isinstance(match, tuple):
                parts = [str(item).strip() for item in match if item]
                if parts:
                    normalized.append(" ".join(parts))
            else:
                token = str(match).strip()
                if token:
                    normalized.append(token)
        return normalized

    def _apply_contextual_suppression(
        self,
        *,
        normalized_url: str,
        hostname: str,
        soup: BeautifulSoup | None,
        page_text: str,
        url_signals: list[SignalEvidence],
        dom_signals: list[SignalEvidence],
        content_signals: list[SignalEvidence],
        trust_profile: dict[str, Any],
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        lowered_text = page_text.lower()
        lower_html = str(soup).lower() if soup else ""

        oauth_context = any(token in normalized_url.lower() for token in TRUSTED_OAUTH_HINTS) or any(
            token in lowered_text for token in ("single sign-on", "sso", "oauth consent", "sign in with")
        )
        mfa_context = any(token in lowered_text for token in BENIGN_MFA_HINTS)
        benign_notification_context = any(token in lowered_text for token in BENIGN_NOTIFICATION_HINTS)
        analytics_context = any(
            token in lower_html
            for token in ("googletagmanager", "google-analytics", "segment.com", "hotjar", "mixpanel")
        )

        for signal in dom_signals:
            if oauth_context and signal.code in {
                "dom-scripted-redirect-logic",
                "dom-meta-refresh-redirect",
                "dom-suspicious-event-listeners",
            }:
                records.append(
                    self._downgrade_signal(
                        signal=signal,
                        reason=(
                            "Downgraded due to trusted OAuth/SSO context and absence of direct "
                            "credential-harvest evidence."
                        ),
                        score_penalty=5,
                        confidence_penalty=0.12,
                    )
                )
            if mfa_context and signal.code in {"dom-account-suspension-language", "dom-urgency-banner-language"}:
                records.append(
                    self._downgrade_signal(
                        signal=signal,
                        reason=(
                            "Downgraded because page language aligns with common MFA verification wording."
                        ),
                        score_penalty=6,
                        confidence_penalty=0.16,
                    )
                )
            if benign_notification_context and signal.code == "dom-notification-abuse":
                records.append(
                    self._downgrade_signal(
                        signal=signal,
                        reason=(
                            "Notification request present but context matches benign update prompt language."
                        ),
                        score_penalty=7,
                        confidence_penalty=0.18,
                    )
                )
            if analytics_context and signal.code == "dom-suspicious-event-listeners":
                records.append(
                    self._downgrade_signal(
                        signal=signal,
                        reason=(
                            "Event-listener pattern overlaps with common analytics instrumentation."
                        ),
                        score_penalty=4,
                        confidence_penalty=0.1,
                    )
                )

        has_high_signal = any(signal.severity in {"high", "critical"} for signal in dom_signals + content_signals)
        if not has_high_signal:
            for signal in content_signals:
                if signal.code in {
                    "content-urgency-pressure",
                    "content-emotional-amplification",
                    "content-impersonation-language",
                }:
                    records.append(
                        self._downgrade_signal(
                            signal=signal,
                            reason=(
                                "Downgraded low-context social-engineering cue without corroborating "
                                "technical phishing indicators."
                            ),
                            score_penalty=3,
                            confidence_penalty=0.1,
                        )
                    )

        trusted_context = bool(trust_profile.get("is_trusted"))
        if trusted_context:
            for signal in url_signals + dom_signals + content_signals:
                if self._is_weak_context_signal(signal):
                    records.append(
                        self._downgrade_signal(
                            signal=signal,
                            reason=(
                                "Weak contextual signal suppressed in trusted-domain context. "
                                "No direct phishing behavior corroboration detected."
                            ),
                            score_penalty=6,
                            confidence_penalty=0.14,
                        )
                    )

        return records

    def _build_domain_trust_profile(
        self,
        *,
        normalized_url: str,
        hostname: str,
        url_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        host = hostname.lower()
        base_domain = str(url_metadata.get("base_domain") or "").lower()
        suffix = str(url_metadata.get("tld") or "").lower()
        full_suffix = ""
        domain_parts = [part for part in base_domain.split(".") if part]
        if len(domain_parts) >= 2:
            full_suffix = ".".join(domain_parts[1:])

        trust_score = 0
        reasons: list[str] = []
        category = "untrusted"

        suffix_candidates = {suffix, full_suffix}
        if any(candidate in TRUSTED_SUFFIXES for candidate in suffix_candidates if candidate):
            trust_score += 55
            category = "public-sector"
            reasons.append("Public-sector/education suffix match.")

        if any(host.endswith(domain) or base_domain.endswith(domain) for domain in TRUSTED_ENTERPRISE_DOMAINS):
            trust_score += 42
            category = "trusted-provider"
            reasons.append("Known trusted enterprise/provider domain match.")

        if any(keyword in host for keyword in TRUSTED_TRANSPORT_KEYWORDS):
            trust_score += 18
            if category == "untrusted":
                category = "transport-portal"
            reasons.append("Transportation portal keyword context.")

        if any(token in normalized_url.lower() for token in TRUSTED_OAUTH_HINTS):
            trust_score += 22
            if category == "untrusted":
                category = "trusted-auth"
            reasons.append("Trusted OAuth/SSO authentication endpoint context.")

        trust_score = max(0, min(100, trust_score))
        is_trusted = trust_score >= 45
        if not reasons:
            reasons.append("No explicit trusted-domain indicators.")
        return {
            "is_trusted": is_trusted,
            "trust_score": trust_score,
            "trust_category": category,
            "reasons": reasons,
        }

    def _is_weak_context_signal(self, signal: SignalEvidence) -> bool:
        text_blob = " ".join(
            [
                signal.code.lower(),
                signal.title.lower(),
                signal.description.lower(),
                signal.category.lower(),
            ]
        )
        if any(token in text_blob for token in WEAK_CONTEXT_TERMS):
            return True
        return signal.code in {
            "content-urgency-pressure",
            "content-emotional-amplification",
            "content-impersonation-language",
            "dom-urgency-banner-language",
            "dom-fake-modal-injection",
            "dom-excessive-hidden-elements",
            "dom-suspicious-event-listeners",
            "url-deep-path",
            "url-medium-entropy-host",
            "url-suspicious-query-params",
        }

    def _downgrade_signal(
        self,
        *,
        signal: SignalEvidence,
        reason: str,
        score_penalty: int,
        confidence_penalty: float,
    ) -> dict[str, Any]:
        original = {
            "severity": signal.severity,
            "score_impact": signal.score_impact,
            "confidence": signal.confidence,
        }
        signal.score_impact = max(1, signal.score_impact - score_penalty)
        signal.confidence = max(0.2, round(signal.confidence - confidence_penalty, 2))
        signal.reliability = max(0.35, round(signal.reliability - 0.08, 2))
        signal.reasoning_context = reason
        severity_order = ["info", "low", "medium", "high", "critical"]
        current_index = severity_order.index(signal.severity) if signal.severity in severity_order else 2
        signal.severity = severity_order[max(0, current_index - 1)]
        signal.analyst_details = {
            **signal.analyst_details,
            "calibration_note": reason,
            "original_signal_state": original,
        }
        return {
            "code": signal.code,
            "reason": reason,
            "original": original,
            "updated": {
                "severity": signal.severity,
                "score_impact": signal.score_impact,
                "confidence": signal.confidence,
            },
        }

    def _signal(
        self,
        code: str,
        title: str,
        description: str,
        severity: str,
        source: str,
        category: str,
        score_impact: int | None = None,
        confidence: float = 0.7,
        reliability: float = 0.74,
        reasoning_context: str | None = None,
        source_module: str | None = "signal_extractor",
        analyst_details: dict[str, Any] | None = None,
        value: Any | None = None,
    ) -> SignalEvidence:
        impact = score_impact if score_impact is not None else SEVERITY_DEFAULT_IMPACT.get(severity, 8)
        return SignalEvidence(
            code=code,
            title=title,
            description=description,
            severity=severity,
            source=source,
            category=category,
            score_impact=max(1, min(35, impact)),
            confidence=max(0.0, min(0.99, confidence)),
            reliability=max(0.2, min(0.99, reliability)),
            reasoning_context=reasoning_context,
            escalation_contribution=max(1, min(35, impact)),
            source_module=source_module,
            analyst_details=analyst_details or {},
            value=value,
        )
