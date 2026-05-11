"""
ML-based feature extraction for phishing detection.

This module extracts real, statistically meaningful features from URLs
that work completely offline and can be fed into sklearn models.

Features are organized into categories:
- URL Structural Features (length, entropy, special characters)
- Domain Features (TLD, hyphens, numeric ratio)
- Lexical Features (keyword presence, tokenization)
- Path Features (depth, parameters, suspicious patterns)
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import tldextract


class MLFeatureExtractor:
    """Extract ML-ready features from URLs for offline phishing detection."""

    # Suspicious keywords commonly found in phishing URLs
    PHISHING_KEYWORDS = {
        "login", "signin", "sign-in", "signin-",
        "verify", "confirm", "validate", "authenticate",
        "update", "upgrade", "renew", "activate",
        "secure", "security", "protect",
        "account", "password", "credential",
        "payment", "billing", "card",
        "bank", "paypal", "amazon", "apple", "microsoft", "google",
        "urgent", "alert", "warning", "expired",
    }

    # Suspicious TLDs (commonly used in phishing)
    SUSPICIOUS_TLDS = {
        "tk", "ml", "ga", "cf",  # Free TLDs
        "top", "win", "download", "space",
        "club", "stream", "party",
    }

    # Legitimate TLDs (highly trusted)
    LEGITIMATE_TLDS = {
        "gov", "edu", "mil",  # Government/education
        "com", "org", "net",  # Established
    }

    def __init__(self) -> None:
        """Initialize feature extractor."""
        pass

    def extract_features(self, url: str) -> dict[str, float]:
        """
        Extract all features from a single URL.

        Returns dict with 40+ feature keys ready for sklearn.
        """
        features: dict[str, float] = {}

        # Parse URL
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            path = parsed.path or ""
            query = parsed.query or ""
        except Exception:
            return self._get_default_features()

        # URL-level features
        features.update(self._extract_url_features(url))

        # Domain features
        features.update(self._extract_domain_features(hostname))

        # Path features
        features.update(self._extract_path_features(path, query))

        # Structural features
        features.update(self._extract_structural_features(url, hostname, path, query))

        return features

    def _extract_url_features(self, url: str) -> dict[str, float]:
        """URL-level statistical features."""
        features: dict[str, float] = {}

        # Length features
        features["url_length"] = float(len(url))
        features["url_length_normalized"] = float(len(url)) / 255.0  # Normalized to 0-1

        # Character composition
        features["url_digit_ratio"] = float(sum(c.isdigit() for c in url)) / max(len(url), 1)
        features["url_special_char_count"] = float(sum(c in "!@#$%^&*-_+=" for c in url))
        features["url_dot_count"] = float(url.count("."))
        features["url_hyphen_count"] = float(url.count("-"))
        features["url_slash_count"] = float(url.count("/"))
        features["url_underscore_count"] = float(url.count("_"))

        # Entropy (measure of randomness/obfuscation)
        features["url_entropy"] = self._calculate_entropy(url)
        features["url_entropy_normalized"] = features["url_entropy"] / 5.0  # Normalized to 0-1

        # Suspicious patterns
        features["has_ip_like"] = 1.0 if self._looks_like_ip(url) else 0.0
        features["has_base64_like"] = 1.0 if self._looks_like_base64(url) else 0.0
        features["has_hex_encoded"] = 1.0 if self._has_hex_encoding(url) else 0.0

        # Protocol
        features["uses_https"] = 1.0 if url.startswith("https") else 0.0

        return features

    def _extract_domain_features(self, hostname: str) -> dict[str, float]:
        """Domain-specific features."""
        features: dict[str, float] = {}

        if not hostname:
            return {
                "domain_length": 0.0,
                "domain_length_normalized": 0.0,
                "domain_digit_ratio": 0.0,
                "domain_hyphen_count": 0.0,
                "subdomain_count": 0.0,
                "tld_length": 0.0,
                "tld_suspicious": 0.0,
                "tld_legitimate": 0.0,
                "domain_entropy": 0.0,
            }

        # Parse domain
        extracted = tldextract.extract(hostname)
        domain = extracted.domain
        tld = extracted.suffix
        subdomains = extracted.subdomain

        # Length features
        features["domain_length"] = float(len(domain))
        features["domain_length_normalized"] = float(len(domain)) / 63.0  # Max domain length

        # Domain composition
        features["domain_digit_ratio"] = float(sum(c.isdigit() for c in domain)) / max(len(domain), 1)
        features["domain_hyphen_count"] = float(domain.count("-"))

        # Subdomain analysis
        subdomain_parts = subdomains.split(".") if subdomains else []
        features["subdomain_count"] = float(len([p for p in subdomain_parts if p]))

        # TLD features
        features["tld_length"] = float(len(tld))
        features["tld_suspicious"] = 1.0 if tld.lower() in self.SUSPICIOUS_TLDS else 0.0
        features["tld_legitimate"] = 1.0 if tld.lower() in self.LEGITIMATE_TLDS else 0.0

        # Domain entropy
        features["domain_entropy"] = self._calculate_entropy(domain)

        # Full hostname (including subdomains)
        full_host_dots = hostname.count(".")
        features["host_dot_count"] = float(full_host_dots)

        return features

    def _extract_path_features(self, path: str, query: str) -> dict[str, float]:
        """Path and query string features."""
        features: dict[str, float] = {}

        # Path features
        features["path_length"] = float(len(path))
        features["path_depth"] = float(max(1, path.count("/")))
        features["path_entropy"] = self._calculate_entropy(path)

        # Query string features
        features["has_query"] = 1.0 if query else 0.0
        features["query_length"] = float(len(query))
        features["query_param_count"] = float(max(1, query.count("&")) + (1.0 if query else 0.0))

        # Suspicious query patterns
        features["query_has_redirect"] = 1.0 if self._has_redirect_param(query) else 0.0
        features["query_has_url_param"] = 1.0 if self._has_url_parameter(query) else 0.0

        return features

    def _extract_structural_features(
        self, url: str, hostname: str, path: str, query: str
    ) -> dict[str, float]:
        """Higher-level structural features combining multiple components."""
        features: dict[str, float] = {}

        # Keyword presence
        url_lower = url.lower()
        keyword_matches = sum(1 for kw in self.PHISHING_KEYWORDS if kw in url_lower)
        features["phishing_keyword_count"] = float(keyword_matches)
        features["has_phishing_keyword"] = 1.0 if keyword_matches > 0 else 0.0

        # Brand impersonation patterns
        features["impersonates_known_brand"] = 1.0 if self._impersonates_brand(url) else 0.0

        # Obfuscation patterns
        features["uses_url_shortener"] = 1.0 if self._is_url_shortener(hostname) else 0.0
        features["looks_obfuscated"] = 1.0 if self._looks_obfuscated(url) else 0.0

        # Port in URL
        features["has_uncommon_port"] = 1.0 if self._has_uncommon_port(url) else 0.0

        # Character mixing (mix of uppercase/lowercase/digits suggests obfuscation)
        has_upper = any(c.isupper() for c in hostname)
        has_lower = any(c.islower() for c in hostname)
        has_digit = any(c.isdigit() for c in hostname)
        features["hostname_mixed_case"] = 1.0 if (has_upper and has_lower) else 0.0
        features["hostname_has_digit"] = 1.0 if has_digit else 0.0

        return features

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text (measure of randomness)."""
        if not text:
            return 0.0
        char_counts = Counter(text)
        total = len(text)
        entropy = 0.0
        for count in char_counts.values():
            p = count / total
            entropy -= p * np.log2(p) if p > 0 else 0
        return entropy

    def _looks_like_ip(self, url: str) -> bool:
        """Check if URL contains an IP address."""
        # Simple regex: match patterns like 192.168.1.1
        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        return bool(re.search(ip_pattern, url))

    def _looks_like_base64(self, url: str) -> bool:
        """Check if URL contains base64-like encoding."""
        base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        # Look for sequences of 20+ base64 chars
        for i in range(len(url) - 20):
            segment = url[i : i + 20]
            if all(c in base64_chars for c in segment.replace("-", "").replace("_", "")):
                return True
        return False

    def _has_hex_encoding(self, url: str) -> bool:
        """Check if URL contains hex-encoded characters."""
        return bool(re.search(r"%[0-9A-Fa-f]{2}", url))

    def _has_redirect_param(self, query: str) -> bool:
        """Check for suspicious redirect parameters."""
        redirect_patterns = ["redirect", "url", "continue", "return", "goto", "next"]
        return any(pattern in query.lower() for pattern in redirect_patterns)

    def _has_url_parameter(self, query: str) -> bool:
        """Check if query contains another URL as parameter."""
        return "http" in query.lower() or "www" in query.lower()

    def _impersonates_brand(self, url: str) -> bool:
        """Check if URL impersonates known brands."""
        brands = [
            "paypal", "ebay", "amazon", "apple", "microsoft", "google",
            "facebook", "twitter", "instagram", "linkedin", "bank"
        ]
        url_lower = url.lower()
        # Check if multiple brand keywords appear (e.g., "paypal-amazon-update")
        brand_matches = sum(1 for brand in brands if brand in url_lower)
        return brand_matches >= 1

    def _is_url_shortener(self, hostname: str) -> bool:
        """Identify known URL shorteners."""
        shorteners = {"bit.ly", "goo.gl", "tinyurl.com", "short.link", "rebrand.ly"}
        return any(shortener in hostname.lower() for shortener in shorteners)

    def _looks_obfuscated(self, url: str) -> bool:
        """Check for obfuscation patterns."""
        # High entropy + lots of special characters
        return (
            self._calculate_entropy(url) > 4.0
            and sum(c in "!@#$%^&*-_+=" for c in url) > 3
        )

    def _has_uncommon_port(self, url: str) -> bool:
        """Check for uncommon ports (ports other than 80, 443)."""
        port_pattern = r":(\d+)"
        match = re.search(port_pattern, url)
        if match:
            port = int(match.group(1))
            return port not in {80, 443}
        return False

    def _get_default_features(self) -> dict[str, float]:
        """Return default (all-zero) features for malformed URLs."""
        return {
            "url_length": 0.0,
            "url_length_normalized": 0.0,
            "url_digit_ratio": 0.0,
            "url_special_char_count": 0.0,
            "url_dot_count": 0.0,
            "url_hyphen_count": 0.0,
            "url_slash_count": 0.0,
            "url_underscore_count": 0.0,
            "url_entropy": 0.0,
            "url_entropy_normalized": 0.0,
            "has_ip_like": 0.0,
            "has_base64_like": 0.0,
            "has_hex_encoded": 0.0,
            "uses_https": 0.0,
            "domain_length": 0.0,
            "domain_length_normalized": 0.0,
            "domain_digit_ratio": 0.0,
            "domain_hyphen_count": 0.0,
            "subdomain_count": 0.0,
            "tld_length": 0.0,
            "tld_suspicious": 0.0,
            "tld_legitimate": 0.0,
            "domain_entropy": 0.0,
            "path_length": 0.0,
            "path_depth": 0.0,
            "path_entropy": 0.0,
            "has_query": 0.0,
            "query_length": 0.0,
            "query_param_count": 0.0,
            "query_has_redirect": 0.0,
            "query_has_url_param": 0.0,
            "phishing_keyword_count": 0.0,
            "has_phishing_keyword": 0.0,
            "impersonates_known_brand": 0.0,
            "uses_url_shortener": 0.0,
            "looks_obfuscated": 0.0,
            "has_uncommon_port": 0.0,
            "hostname_mixed_case": 0.0,
            "hostname_has_digit": 0.0,
            "host_dot_count": 0.0,
        }

    def extract_features_batch(self, urls: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features for a batch of URLs.

        Args:
            urls: DataFrame with 'url' column

        Returns:
            DataFrame with URL and all feature columns
        """
        features_list = []
        for url in urls["url"]:
            features = self.extract_features(url)
            features_list.append(features)

        features_df = pd.DataFrame(features_list)
        # Add original URL and label if present
        features_df["url"] = urls["url"].values
        if "label" in urls.columns:
            features_df["label"] = urls["label"].values

        return features_df

    def get_feature_names(self) -> list[str]:
        """Get list of all feature names (for sklearn pipeline)."""
        return list(self._get_default_features().keys())
