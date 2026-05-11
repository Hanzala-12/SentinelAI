from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import numpy as np
import requests
import tldextract
import whois
from bs4 import BeautifulSoup

from backend.api.schemas.scans import DetectedIssue

logger = logging.getLogger(__name__)

SHORT_URL_PATTERNS = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|"
    r"rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|"
    r"ut\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|"
    r"filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net",
    re.IGNORECASE,
)

SUSPICIOUS_TLDS = (
    "zip",
    "mov",
    "xyz",
    "top",
    "click",
    "link",
    "support",
    "work",
)


@dataclass(slots=True)
class UrlModelInference:
    prediction: Any | None
    phishing_probability: float
    raw_probability: float | None
    model_loaded: bool
    model_path: str | None
    issue: str | None = None


@dataclass(slots=True)
class UrlFeaturePack:
    features: list[Any]
    issues: list[DetectedIssue]
    privacy_score: int
    confidence_hint: float


class PhishingUrlFeatureExtractor:
    def __init__(self, timeout: float = 5.0, whois_timeout: float = 2.0) -> None:
        self.timeout = timeout
        self.whois_timeout = whois_timeout

    def extract(self, url: str) -> UrlFeaturePack:
        normalized_url = self._normalize(url)
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        domain_parts = tldextract.extract(normalized_url)
        registered_domain = ".".join(part for part in [domain_parts.domain, domain_parts.suffix] if part)

        page_html, history = self._fetch_page(normalized_url)
        soup = BeautifulSoup(page_html, "html.parser") if page_html else None
        whois_response = self._safe_whois(hostname)

        features: list[Any] = []
        issues: list[DetectedIssue] = []
        privacy_score = 10
        confidence_hint = 0.35

        def add_issue(code: str, title: str, description: str, severity: str) -> None:
            issues.append(
                DetectedIssue(
                    code=code,
                    title=title,
                    description=description,
                    severity=severity,
                )
            )

        # 1 UsingIp
        if self._is_ip_address(hostname):
            features.append(-1)
            add_issue("ip-host", "IP address used as host", "The URL is an IP address instead of a domain name.", "high")
            confidence_hint += 0.1
        else:
            features.append(1)

        # 2 longUrl
        features.append(self._long_url(normalized_url))

        # 3 shortUrl
        if SHORT_URL_PATTERNS.search(normalized_url):
            features.append(-1)
            add_issue("shortener", "Shortened URL pattern", "The URL matches a known URL shortener or cloaking domain.", "medium")
            confidence_hint += 0.08
        else:
            features.append(1)

        # 4 symbol
        features.append(-1 if "@" in normalized_url else 1)
        if "@" in normalized_url:
            add_issue("at-symbol", "Embedded @ symbol", "The @ symbol can hide the real destination domain.", "high")
            confidence_hint += 0.08

        # 5 redirecting
        features.append(-1 if normalized_url.rfind("//") > 6 else 1)
        if normalized_url.rfind("//") > 6:
            add_issue("double-slash", "Redirect-like path", "The URL contains a suspicious double-slash pattern after the scheme.", "medium")

        # 6 prefixSuffix
        features.append(-1 if "-" in hostname else 1)
        if "-" in hostname:
            add_issue("hyphenated-host", "Hyphenated domain", "Hyphens are often used in lookalike phishing domains.", "medium")

        # 7 SubDomains
        subdomain_count = self._subdomain_count(domain_parts.subdomain)
        if subdomain_count <= 1:
            features.append(1)
        elif subdomain_count == 2:
            features.append(0)
        else:
            features.append(-1)
            add_issue("many-subdomains", "Excessive subdomains", "Multiple subdomains are often used to obscure the true destination.", "medium")

        # 8 Hppts
        features.append(1 if parsed.scheme == "https" else -1)
        if parsed.scheme != "https":
            privacy_score += 18
            add_issue("non-https", "Non-HTTPS page", "Traffic is not protected by HTTPS.", "medium")

        # 9 DomainRegLen
        domain_age = self._domain_age_months(whois_response)
        if domain_age is None:
            features.append(-1)
        elif domain_age >= 12:
            features.append(1)
        else:
            features.append(-1)
            add_issue("new-domain", "Newly registered domain", "The domain appears to be recently registered.", "medium")

        # 10 Favicon
        features.append(self._favicon_feature(normalized_url, hostname, soup))

        # 11 NonStdPort
        features.append(-1 if parsed.port else 1)
        if parsed.port:
            add_issue("non-standard-port", "Non-standard port", "The URL uses a non-standard port.", "low")

        # 12 HTTPSDomainURL
        features.append(-1 if "https" in hostname.lower() else 1)

        # 13 RequestURL
        request_url_feature = self._request_url_feature(normalized_url, hostname, soup)
        features.append(request_url_feature)

        # 14 AnchorURL
        anchor_feature = self._anchor_feature(normalized_url, hostname, soup)
        features.append(anchor_feature)

        # 15 LinksInScriptTags
        features.append(self._script_link_feature(normalized_url, hostname, soup))

        # 16 ServerFormHandler
        features.append(self._form_handler_feature(normalized_url, hostname, soup))

        # 17 InfoEmail
        info_email_feature = self._info_email_feature(page_html)
        features.append(info_email_feature)
        if info_email_feature == -1:
            add_issue("mailto", "Email harvesting markers", "The page contains mailto/email harvesting patterns.", "medium")

        # 18 AbnormalURL
        features.append(self._abnormal_url_feature(page_html, hostname, whois_response))

        # 19 WebsiteForwarding
        forwarding_feature = self._forwarding_feature(history)
        features.append(forwarding_feature)
        if forwarding_feature != 1:
            add_issue("redirect-chain", "Redirect chain", "The URL follows one or more redirects.", "medium")

        # 20 StatusBarCust
        features.append(self._status_bar_feature(page_html))

        # 21 DisableRightClick
        features.append(self._right_click_feature(page_html))

        # 22 UsingPopupWindow
        features.append(self._popup_feature(page_html))

        # 23 IframeRedirection
        features.append(self._iframe_feature(page_html))

        # 24 AgeofDomain
        features.append(1 if domain_age is not None and domain_age >= 6 else -1)

        # 25 DNSRecording
        features.append(1 if domain_age is not None and domain_age >= 6 else -1)

        # 26 WebsiteTraffic
        features.append(self._traffic_feature(hostname))

        # 27 PageRank
        features.append(self._pagerank_feature(hostname))

        # 28 GoogleIndex
        features.append(self._google_index_feature(registered_domain))

        # 29 LinksPointingToPage
        features.append(self._links_pointing_feature(page_html))

        # 30 StatsReport
        stats_feature = self._stats_report_feature(hostname)
        features.append(stats_feature)
        if stats_feature == -1:
            add_issue("known-risk-signals", "Suspicious host patterns", "The host matches patterns that are common in risky domains.", "medium")

        return UrlFeaturePack(
            features=features,
            issues=issues,
            privacy_score=min(100, privacy_score),
            confidence_hint=min(0.95, confidence_hint),
        )

    def _normalize(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    def _is_ip_address(self, hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    def _long_url(self, url: str) -> int:
        if len(url) < 54:
            return 1
        if 54 <= len(url) <= 75:
            return 0
        return -1

    def _subdomain_count(self, subdomain: str) -> int:
        if not subdomain:
            return 0
        cleaned = [part for part in subdomain.split(".") if part and part != "www"]
        return len(cleaned)

    def _safe_whois(self, hostname: str) -> Any | None:
        if not hostname:
            return None
        if os.getenv("PHISHLENS_OFFLINE_EVAL", "0") == "1":
            return None
        result: dict[str, Any] = {"value": None}
        error: dict[str, Exception] = {}

        def _lookup() -> None:
            try:
                result["value"] = whois.whois(hostname)
            except Exception as exc:  # pragma: no cover - defensive fallback
                error["exc"] = exc

        worker = threading.Thread(target=_lookup, daemon=True)
        worker.start()
        worker.join(self.whois_timeout)
        if worker.is_alive():
            logger.debug("WHOIS lookup timed out for host '%s' after %.2fs", hostname, self.whois_timeout)
            return None
        try:
            if "exc" in error:
                raise error["exc"]
            return result["value"]
        except Exception:
            return None

    def _domain_age_months(self, whois_response: Any | None) -> int | None:
        if not whois_response:
            return None
        creation_date = getattr(whois_response, "creation_date", None)
        expiration_date = getattr(whois_response, "expiration_date", None)
        try:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, datetime) and isinstance(expiration_date, datetime):
                return (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            if isinstance(creation_date, datetime):
                today = date.today()
                return (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
        except Exception:
            return None
        return None

    def _fetch_page(self, url: str) -> tuple[str, list[str]]:
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                headers={"User-Agent": "PhishLens/1.0"},
                allow_redirects=True,
            )
            response.raise_for_status()
            return response.text, [item.url for item in response.history]
        except Exception:
            return "", []

    def _page_soup(self, soup: BeautifulSoup | None) -> BeautifulSoup | None:
        return soup

    def _favicon_feature(self, url: str, hostname: str, soup: BeautifulSoup | None) -> int:
        if not soup:
            return 0
        try:
            for head_link in soup.find_all("link", href=True):
                href = head_link["href"]
                dots = [x.start(0) for x in re.finditer(r"\.", href)]
                if url in href or len(dots) == 1 or hostname in href:
                    return 1
            return -1
        except Exception:
            return -1

    def _request_url_feature(self, url: str, hostname: str, soup: BeautifulSoup | None) -> int:
        if not soup:
            return 0
        try:
            i = 0
            success = 0
            for tag_name in ("img", "audio", "embed", "iframe"):
                for element in soup.find_all(tag_name, src=True):
                    src = element["src"]
                    dots = [x.start(0) for x in re.finditer(r"\.", src)]
                    if url in src or hostname in src or len(dots) == 1:
                        success += 1
                    i += 1
            if i == 0:
                return 1
            percentage = success / float(i) * 100
            if percentage < 22.0:
                return 1
            if percentage < 61.0:
                return 0
            return -1
        except Exception:
            return 0

    def _anchor_feature(self, url: str, hostname: str, soup: BeautifulSoup | None) -> int:
        if not soup:
            return 0
        try:
            unsafe = 0
            total = 0
            for anchor in soup.find_all("a", href=True):
                href = anchor["href"]
                if "#" in href or "javascript" in href.lower() or "mailto" in href.lower() or not (url in href or hostname in href):
                    unsafe += 1
                total += 1
            if total == 0:
                return -1
            percentage = unsafe / float(total) * 100
            if percentage < 31.0:
                return 1
            if percentage < 67.0:
                return 0
            return -1
        except Exception:
            return -1

    def _script_link_feature(self, url: str, hostname: str, soup: BeautifulSoup | None) -> int:
        if not soup:
            return 0
        try:
            total = 0
            success = 0
            for link in soup.find_all("link", href=True):
                dots = [x.start(0) for x in re.finditer(r"\.", link["href"])]
                if url in link["href"] or hostname in link["href"] or len(dots) == 1:
                    success += 1
                total += 1
            for script in soup.find_all("script", src=True):
                dots = [x.start(0) for x in re.finditer(r"\.", script["src"])]
                if url in script["src"] or hostname in script["src"] or len(dots) == 1:
                    success += 1
                total += 1
            if total == 0:
                return -1
            percentage = success / float(total) * 100
            if percentage < 17.0:
                return 1
            if percentage < 81.0:
                return 0
            return -1
        except Exception:
            return -1

    def _form_handler_feature(self, url: str, hostname: str, soup: BeautifulSoup | None) -> int:
        if not soup:
            return 0
        try:
            forms = soup.find_all("form", action=True)
            if len(forms) == 0:
                return 1
            for form in forms:
                action = form.get("action", "")
                if action in {"", "about:blank"}:
                    return -1
                if url not in action and hostname not in action:
                    return 0
            return 1
        except Exception:
            return -1

    def _info_email_feature(self, page_html: str) -> int:
        try:
            if re.findall(r"[mail\(\)|mailto:?]", page_html):
                return -1
            return 1
        except Exception:
            return -1

    def _abnormal_url_feature(self, page_html: str, hostname: str, whois_response: Any | None) -> int:
        try:
            if not page_html or not hostname:
                return -1
            if whois_response is None:
                return -1
            if hostname.lower() in page_html.lower():
                return 1
            return -1
        except Exception:
            return -1

    def _forwarding_feature(self, history: list[str]) -> int:
        try:
            if len(history) <= 1:
                return 1
            if len(history) <= 4:
                return 0
            return -1
        except Exception:
            return -1

    def _status_bar_feature(self, page_html: str) -> int:
        try:
            if re.findall(r"<script>.+onmouseover.+</script>", page_html):
                return 1
            return -1
        except Exception:
            return -1

    def _right_click_feature(self, page_html: str) -> int:
        try:
            if re.findall(r"event.button ?== ?2|contextmenu", page_html):
                return 1
            return -1
        except Exception:
            return -1

    def _popup_feature(self, page_html: str) -> int:
        try:
            if re.findall(r"alert\(", page_html):
                return 1
            return -1
        except Exception:
            return -1

    def _iframe_feature(self, page_html: str) -> int:
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", page_html):
                return 1
            return -1
        except Exception:
            return -1

    def _traffic_feature(self, hostname: str) -> int:
        if not hostname:
            return -1
        # Avoid hard dependency on public ranking services during runtime; return unknown.
        return 0

    def _pagerank_feature(self, hostname: str) -> int:
        if not hostname:
            return -1
        return 0

    def _google_index_feature(self, registered_domain: str) -> int:
        if not registered_domain:
            return -1
        return 0

    def _links_pointing_feature(self, page_html: str) -> int:
        try:
            number_of_links = len(re.findall(r"<a href=", page_html, re.IGNORECASE))
            if number_of_links == 0:
                return 1
            if number_of_links <= 2:
                return 0
            return -1
        except Exception:
            return -1

    def _stats_report_feature(self, hostname: str) -> int:
        try:
            if not hostname:
                return -1
            if hostname.replace(".", "").isdigit():
                return -1
            if any(hostname.lower().endswith(f".{tld}") for tld in SUSPICIOUS_TLDS):
                return -1
            return 1
        except Exception:
            return 1


class PretrainedPhishingUrlModel:
    def __init__(
        self,
        model_path: str | None = None,
        metadata_path: str | None = None,
    ) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        default_model_root = Path(__file__).resolve().parents[1] / "models" / "url"
        configured_model_path = Path(
            model_path
            or os.getenv("PHISHLENS_URL_MODEL_PATH")
            or (default_model_root / "phishing_url_model_v1.pkl")
        )
        configured_metadata_path = Path(
            metadata_path
            or os.getenv("PHISHLENS_URL_MODEL_METADATA_PATH")
            or (default_model_root / "phishing_url_model_v1.json")
        )
        self.model_path = (
            configured_model_path if configured_model_path.is_absolute() else repo_root / configured_model_path
        )
        self.metadata_path = (
            configured_metadata_path
            if configured_metadata_path.is_absolute()
            else repo_root / configured_metadata_path
        )
        self._model = None
        self._model_error: str | None = None
        self._fallback_logged = False
        self._extractor = PhishingUrlFeatureExtractor()
        self._metadata: dict[str, Any] = {}

    @property
    def model_loaded(self) -> bool:
        return self._model is not None

    def predict(self, url: str) -> tuple[UrlModelInference, UrlFeaturePack]:
        features = self._extractor.extract(url)
        try:
            model = self._load_model()
            prediction, phishing_probability, raw_probability = self._predict_with_model(model, features.features)
            return (
                UrlModelInference(
                    prediction=prediction,
                    phishing_probability=phishing_probability,
                    raw_probability=raw_probability,
                    model_loaded=True,
                    model_path=str(self.model_path),
                ),
                features,
            )
        except Exception as exc:
            if not self._fallback_logged:
                logger.warning("Falling back to heuristic URL scoring: %s", exc)
                self._fallback_logged = True
            fallback_probability = self._heuristic_probability(features)
            return (
                UrlModelInference(
                    prediction=None,
                    phishing_probability=fallback_probability,
                    raw_probability=None,
                    model_loaded=False,
                    model_path=str(self.model_path) if self.model_path.exists() else None,
                    issue=str(exc),
                ),
                features,
            )

    def _load_model(self) -> Any:
        if self._model is not None:
            return self._model
        if self._model_error and not self.model_path.exists():
            raise RuntimeError(self._model_error)
        if not self.model_path.exists():
            self._model_error = f"local-url-model-missing: {self.model_path}"
            raise RuntimeError(self._model_error)
        self._metadata = self._load_metadata()
        self._model = joblib.load(self.model_path)
        self._validate_model(self._model)
        self._model_error = None
        self._fallback_logged = False
        return self._model

    def _predict_with_model(self, model: Any, features: list[Any]) -> tuple[Any, float, float | None]:
        data = np.array([features], dtype=object)
        prediction = model.predict(data)[0]
        raw_probability = None
        phishing_probability = 0.5

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(data)[0]
            raw_probability = float(np.max(probabilities))
            phishing_probability = self._resolve_phishing_probability(model, prediction, probabilities)
        elif hasattr(model, "decision_function"):
            decision = model.decision_function(data)
            decision_value = float(np.ravel(decision)[0])
            phishing_probability = 1.0 / (1.0 + np.exp(-decision_value))
            raw_probability = phishing_probability
        else:
            phishing_probability = 0.5 if prediction in {1, "safe", "benign", "not_phishy", "NotPhishy"} else 0.85
            raw_probability = phishing_probability

        return prediction, float(np.clip(phishing_probability, 0.0, 1.0)), raw_probability

    def _resolve_phishing_probability(self, model: Any, prediction: Any, probabilities: np.ndarray) -> float:
        classes = list(getattr(model, "classes_", []))
        class_probability = {cls: float(prob) for cls, prob in zip(classes, probabilities)}

        phishing_labels = (-1, "-1", "Phishy", "phishy", "malicious", "unsafe", "unsafe ")
        safe_labels = (1, "1", "NotPhishy", "Not Phishy", "safe", "benign", "legitimate")

        for label in phishing_labels:
            if label in class_probability:
                return class_probability[label]
        for label in safe_labels:
            if label in class_probability:
                return 1.0 - class_probability[label]

        if isinstance(prediction, (int, float)):
            return 0.85 if prediction < 0 else 0.15
        if isinstance(prediction, str):
            lowered = prediction.lower()
            if any(token in lowered for token in ("phish", "mal", "unsafe", "bad")):
                return 0.85
            if any(token in lowered for token in ("safe", "legit", "good", "benign")):
                return 0.15
        return float(np.max(probabilities))

    def _heuristic_probability(self, features: UrlFeaturePack) -> float:
        risky = 0
        for value in features.features:
            if value in (-1, "-1", "Phishy", "BadHREFs", "ErrorSE", "ErrorHREFs", "N/AHREFs"):
                risky += 1
        return min(0.95, 0.25 + risky * 0.02)

    def _load_metadata(self) -> dict[str, Any]:
        if not self.metadata_path.exists():
            return {}
        try:
            payload = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                return payload
            return {}
        except Exception as exc:
            logger.warning("URL model metadata parsing failed (%s): %s", self.metadata_path, exc)
            return {}

    def _validate_model(self, model: Any) -> None:
        if not hasattr(model, "predict"):
            raise RuntimeError("local-url-model-invalid: model missing predict()")
        expected_feature_count = self._metadata.get("feature_count")
        if expected_feature_count is not None:
            try:
                expected = int(expected_feature_count)
            except (TypeError, ValueError):
                expected = None
            if expected is not None and expected != 30:
                raise RuntimeError(
                    "local-url-model-invalid: unsupported feature_count in metadata "
                    f"({expected}); expected 30"
                )
