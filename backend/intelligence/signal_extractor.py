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
        dom_signals = self._extract_dom_signals(
            normalized_url=normalized_url,
            hostname=hostname,
            soup=soup,
            raw_html=html,
        )
        content_signals = self._extract_content_signals(text_for_analysis)

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
        external_credential_posts = 0
        http_credential_posts = 0

        for form in forms:
            action = (form.get("action") or "").strip()
            inputs = form.find_all("input")
            credential_inputs = 0
            for input_tag in inputs:
                input_type = (input_tag.get("type") or "").lower()
                input_name = (input_tag.get("name") or "").lower()
                if input_type == "password" or any(token in input_name for token in CREDENTIAL_INPUT_NAMES):
                    credential_inputs += 1

            if credential_inputs == 0:
                continue

            credential_forms += 1
            is_hidden = self._element_hidden(form)
            if is_hidden:
                hidden_credential_forms += 1

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
                    )
                )
            elif self._is_external_destination(action, hostname):
                external_credential_posts += 1
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
                    )
                )
            elif parsed.scheme == "https" and action.lower().startswith("http://"):
                http_credential_posts += 1
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
                )
            )

        suspicious_brand_mentions = self._suspicious_brand_mentions(soup.get_text(separator=" ", strip=True), hostname)
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

        hidden_elements = len(
            [
                tag
                for tag in soup.find_all(True)
                if self._element_hidden(tag) and tag.name not in {"script", "style", "meta", "link"}
            ]
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
            matches = re.findall(pattern, lowered, flags=re.IGNORECASE)
            if not matches:
                continue
            scaled_impact = min(28, impact + max(0, len(matches) - 1) * 2)
            signals.append(
                self._signal(
                    code=code,
                    title=title,
                    description=f"Detected {len(matches)} matching language cues linked to phishing/scam campaigns.",
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
                    description="Message uses excessive uppercase punctuation or intensity markers to coerce fast action.",
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
            value=value,
        )
