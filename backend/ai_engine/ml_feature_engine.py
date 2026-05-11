"""
ML Feature Engine for offline-safe URL feature extraction.

This module implements the Feature_Engine component that extracts 16 offline-safe
features from URL strings without requiring network access. Features are designed
to be leakage-free (no brand dictionaries or phishing keywords) and work purely
through character-level and structural analysis.

**Validates: Requirements 2.1-2.9, 10.1-10.16**
"""

import math
import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse

import tldextract

from backend.ai_engine.ml_models import MLFeaturePack


class MLFeatureEngine:
    """Extract offline-safe features from URL strings.
    
    This class implements 16 feature extraction functions that operate purely on
    URL string analysis without network dependencies. Features include lexical
    characteristics (length, entropy, character ratios), structural properties
    (subdomain count, path depth), and domain heuristics (TLD category, homoglyphs).
    
    **Validates: Requirements 2.1-2.9, 10.1-10.16**
    """
    
    # TLD categories for classification
    GENERIC_TLDS = {
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
        'info', 'biz', 'name', 'pro', 'aero', 'coop', 'museum'
    }
    
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs often abused
        'xyz', 'top', 'work', 'click', 'link',  # Commonly used in phishing
        'zip', 'mov', 'icu'  # Confusing or suspicious
    }
    
    # Homoglyph characters (visually similar)
    HOMOGLYPH_CHARS = set('0Ool1I|')
    
    # Special characters for counting
    SPECIAL_CHARS = set('!@#$%^&*-_+=')
    
    # Vowels and consonants for ratio calculation
    VOWELS = set('aeiouAEIOU')
    CONSONANTS = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
    
    def extract(self, url: str) -> MLFeaturePack:
        """Extract features from URL string.
        
        Args:
            url: Raw URL string
            
        Returns:
            MLFeaturePack containing:
                - features: list[float] (16 elements)
                - feature_names: list[str] (16 elements)
                - extraction_metadata: dict with extraction details
                
        **Validates: Requirements 2.1-2.9, 10.1-10.16**
        """
        import time
        start_time = time.time()
        
        metadata: dict[str, Any] = {
            'url': url,
            'errors': [],
            'warnings': []
        }
        
        try:
            # Parse URL components
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            # Extract all 16 features
            features = [
                self._extract_url_length(url),                          # f1
                self._extract_character_entropy(url),                   # f2
                self._extract_digit_ratio(url),                         # f3
                self._extract_special_char_count(url),                  # f4
                self._extract_subdomain_count(extracted),               # f5
                self._extract_path_depth(parsed),                       # f6
                self._extract_query_param_count(parsed),                # f7
                self._extract_tld_category(extracted),                  # f8
                self._extract_domain_token_count(extracted),            # f9
                self._extract_longest_token_length(extracted),          # f10
                self._extract_vowel_consonant_ratio(extracted),         # f11
                self._extract_homoglyph_risk_score(extracted),          # f12
                self._extract_https_usage(parsed),                      # f13
                self._extract_ip_address_usage(parsed),                 # f14
                self._extract_port_specification(parsed),               # f15
                self._extract_url_entropy_normalized(url)               # f16
            ]
            
            feature_names = [
                'url_length',
                'character_entropy',
                'digit_ratio',
                'special_char_count',
                'subdomain_count',
                'path_depth',
                'query_param_count',
                'tld_category',
                'domain_token_count',
                'longest_token_length',
                'vowel_consonant_ratio',
                'homoglyph_risk_score',
                'https_usage',
                'ip_address_usage',
                'port_specification',
                'url_entropy_normalized'
            ]
            
        except Exception as e:
            # Return default feature vector on error
            metadata['errors'].append(f"Feature extraction failed: {str(e)}")
            features = self._get_default_features()
            feature_names = self._get_feature_names()
        
        extraction_time_ms = (time.time() - start_time) * 1000
        
        return MLFeaturePack(
            features=features,
            feature_names=feature_names,
            extraction_metadata=metadata,
            extraction_time_ms=extraction_time_ms
        )
    
    def _extract_url_length(self, url: str) -> float:
        """Extract URL length feature (f1).
        
        Args:
            url: Raw URL string
            
        Returns:
            Length of the URL as a float
            
        **Validates: Requirement 10.1**
        """
        return float(len(url))
    
    def _extract_character_entropy(self, url: str) -> float:
        """Extract character entropy feature (f2) using Shannon entropy.
        
        Shannon entropy measures the randomness/unpredictability of characters
        in the URL. Higher entropy suggests more random character distribution.
        
        Args:
            url: Raw URL string
            
        Returns:
            Shannon entropy of the URL string
            
        **Validates: Requirement 10.2**
        """
        if not url:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(url)
        url_len = len(url)
        
        # Calculate Shannon entropy: -sum(p(x) * log2(p(x)))
        entropy = 0.0
        for count in char_counts.values():
            probability = count / url_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _extract_digit_ratio(self, url: str) -> float:
        """Extract digit ratio feature (f3).
        
        Args:
            url: Raw URL string
            
        Returns:
            Ratio of digits to total URL length
            
        **Validates: Requirement 10.3**
        """
        if not url:
            return 0.0
        
        digit_count = sum(1 for char in url if char.isdigit())
        return digit_count / len(url)
    
    def _extract_special_char_count(self, url: str) -> float:
        """Extract special character count feature (f4).
        
        Counts occurrences of special characters: !@#$%^&*-_+=
        
        Args:
            url: Raw URL string
            
        Returns:
            Count of special characters
            
        **Validates: Requirement 10.4**
        """
        return float(sum(1 for char in url if char in self.SPECIAL_CHARS))
    
    def _extract_subdomain_count(self, extracted: Any) -> float:
        """Extract subdomain count feature (f5).
        
        Args:
            extracted: tldextract.ExtractResult object
            
        Returns:
            Number of subdomain levels
            
        **Validates: Requirement 10.5**
        """
        subdomain = extracted.subdomain
        if not subdomain:
            return 0.0
        
        # Count subdomain levels by splitting on '.'
        return float(len(subdomain.split('.')))
    
    def _extract_path_depth(self, parsed: Any) -> float:
        """Extract path depth feature (f6).
        
        Args:
            parsed: urllib.parse.ParseResult object
            
        Returns:
            Number of '/' in the path
            
        **Validates: Requirement 10.6**
        """
        path = parsed.path
        if not path or path == '/':
            return 0.0
        
        # Count forward slashes in path
        return float(path.count('/'))
    
    def _extract_query_param_count(self, parsed: Any) -> float:
        """Extract query parameter count feature (f7).
        
        Args:
            parsed: urllib.parse.ParseResult object
            
        Returns:
            Number of query parameters (count of '&' + 1 if query exists)
            
        **Validates: Requirement 10.7**
        """
        query = parsed.query
        if not query:
            return 0.0
        
        # Count parameters: number of '&' + 1
        return float(query.count('&') + 1)
    
    def _extract_tld_category(self, extracted: Any) -> float:
        """Extract TLD category feature (f8).
        
        Categories:
        - 0: Generic TLD (com, org, net, etc.)
        - 1: Country-code TLD
        - 2: Suspicious TLD (free or commonly abused)
        
        Args:
            extracted: tldextract.ExtractResult object
            
        Returns:
            TLD category code (0, 1, or 2)
            
        **Validates: Requirement 10.8**
        """
        tld = extracted.suffix.lower()
        
        if not tld:
            return 0.0
        
        # Check suspicious TLDs first
        if tld in self.SUSPICIOUS_TLDS:
            return 2.0
        
        # Check generic TLDs
        if tld in self.GENERIC_TLDS:
            return 0.0
        
        # Assume country-code TLD (2-letter TLDs like 'uk', 'de', etc.)
        if len(tld) == 2:
            return 1.0
        
        # Default to generic for unknown TLDs
        return 0.0
    
    def _extract_domain_token_count(self, extracted: Any) -> float:
        """Extract domain token count feature (f9).
        
        Counts tokens in the domain by splitting on '-' and '.'.
        
        Args:
            extracted: tldextract.ExtractResult object
            
        Returns:
            Number of tokens in the domain
            
        **Validates: Requirement 10.9**
        """
        domain = extracted.domain
        if not domain:
            return 0.0
        
        # Split by both '-' and '.'
        tokens = re.split(r'[-.]', domain)
        # Filter out empty tokens
        tokens = [t for t in tokens if t]
        
        return float(len(tokens))
    
    def _extract_longest_token_length(self, extracted: Any) -> float:
        """Extract longest token length feature (f10).
        
        Finds the maximum length of domain tokens (split by '-' and '.').
        
        Args:
            extracted: tldextract.ExtractResult object
            
        Returns:
            Length of the longest token in the domain
            
        **Validates: Requirement 10.10**
        """
        domain = extracted.domain
        if not domain:
            return 0.0
        
        # Split by both '-' and '.'
        tokens = re.split(r'[-.]', domain)
        # Filter out empty tokens
        tokens = [t for t in tokens if t]
        
        if not tokens:
            return 0.0
        
        return float(max(len(token) for token in tokens))
    
    def _extract_vowel_consonant_ratio(self, extracted: Any) -> float:
        """Extract vowel-consonant ratio feature (f11).
        
        Args:
            extracted: tldextract.ExtractResult object
            
        Returns:
            Ratio of vowels to consonants in the domain
            
        **Validates: Requirement 10.11**
        """
        domain = extracted.domain
        if not domain:
            return 0.0
        
        vowel_count = sum(1 for char in domain if char in self.VOWELS)
        consonant_count = sum(1 for char in domain if char in self.CONSONANTS)
        
        if consonant_count == 0:
            return 0.0
        
        return vowel_count / consonant_count
    
    def _extract_homoglyph_risk_score(self, extracted: Any) -> float:
        """Extract homoglyph risk score feature (f12).
        
        Counts visually similar characters (0, O, o, l, 1, I, |) that could
        be used for domain spoofing.
        
        Args:
            extracted: tldextract.ExtractResult object
            
        Returns:
            Count of homoglyph characters in the domain
            
        **Validates: Requirement 10.12**
        """
        domain = extracted.domain
        if not domain:
            return 0.0
        
        return float(sum(1 for char in domain if char in self.HOMOGLYPH_CHARS))
    
    def _extract_https_usage(self, parsed: Any) -> float:
        """Extract HTTPS usage feature (f13).
        
        Args:
            parsed: urllib.parse.ParseResult object
            
        Returns:
            1.0 if HTTPS, 0.0 otherwise
            
        **Validates: Requirement 10.13**
        """
        return 1.0 if parsed.scheme == 'https' else 0.0
    
    def _extract_ip_address_usage(self, parsed: Any) -> float:
        """Extract IP address usage feature (f14).
        
        Detects if the hostname is an IP address (IPv4 or IPv6).
        
        Args:
            parsed: urllib.parse.ParseResult object
            
        Returns:
            1.0 if hostname is an IP address, 0.0 otherwise
            
        **Validates: Requirement 10.14**
        """
        hostname = parsed.hostname
        if not hostname:
            return 0.0
        
        # Check for IPv4 pattern
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ipv4_pattern, hostname):
            return 1.0
        
        # Check for IPv6 pattern (contains colons and hex characters)
        # IPv6 addresses contain colons and may contain hex digits (0-9, a-f)
        if ':' in hostname:
            # Simple check: if it has multiple colons, likely IPv6
            if hostname.count(':') >= 2:
                return 1.0
        
        return 0.0
    
    def _extract_port_specification(self, parsed: Any) -> float:
        """Extract port specification feature (f15).
        
        Detects if a non-standard port is specified in the URL.
        Standard ports: 80 (HTTP), 443 (HTTPS)
        
        Args:
            parsed: urllib.parse.ParseResult object
            
        Returns:
            1.0 if non-standard port is specified, 0.0 otherwise
            
        **Validates: Requirement 10.15**
        """
        port = parsed.port
        if port is None:
            return 0.0
        
        # Standard ports
        standard_ports = {80, 443}
        
        return 0.0 if port in standard_ports else 1.0
    
    def _extract_url_entropy_normalized(self, url: str) -> float:
        """Extract normalized URL entropy feature (f16).
        
        Normalizes entropy to [0, 1] range by dividing by 5.0.
        
        Args:
            url: Raw URL string
            
        Returns:
            Normalized entropy (entropy / 5.0)
            
        **Validates: Requirement 10.16**
        """
        entropy = self._extract_character_entropy(url)
        return entropy / 5.0
    
    def _get_default_features(self) -> list[float]:
        """Get default feature vector for error cases.
        
        Returns all zeros except f13 (HTTPS usage) = 1.0 for conservative assumption.
        
        Returns:
            List of 16 default feature values
        """
        features = [0.0] * 16
        features[12] = 1.0  # f13: HTTPS usage (conservative default)
        return features
    
    def _get_feature_names(self) -> list[str]:
        """Get feature names in order.
        
        Returns:
            List of 16 feature names
        """
        return [
            'url_length',
            'character_entropy',
            'digit_ratio',
            'special_char_count',
            'subdomain_count',
            'path_depth',
            'query_param_count',
            'tld_category',
            'domain_token_count',
            'longest_token_length',
            'vowel_consonant_ratio',
            'homoglyph_risk_score',
            'https_usage',
            'ip_address_usage',
            'port_specification',
            'url_entropy_normalized'
        ]
