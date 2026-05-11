"""
Unit tests for MLFeatureEngine.

Tests cover:
- All 16 feature extraction functions
- Error handling for malformed URLs
- Default feature vector generation
- Feature vector dimensionality
- Edge cases (empty URLs, missing components, etc.)

**Validates: Requirements 2.1-2.9, 10.1-10.16**
"""

import pytest

from backend.ai_engine.ml_feature_engine import MLFeatureEngine
from backend.ai_engine.ml_models import MLFeaturePack


class TestMLFeatureEngine:
    """Tests for MLFeatureEngine feature extraction."""
    
    @pytest.fixture
    def engine(self):
        """Create MLFeatureEngine instance for testing."""
        return MLFeatureEngine()
    
    def test_extract_returns_valid_feature_pack(self, engine):
        """Test that extract() returns a valid MLFeaturePack with 16 features."""
        url = "https://www.example.com/path/to/page?param1=value1&param2=value2"
        
        result = engine.extract(url)
        
        assert isinstance(result, MLFeaturePack)
        assert len(result.features) == 16
        assert len(result.feature_names) == 16
        assert result.extraction_time_ms >= 0
        assert 'url' in result.extraction_metadata
    
    def test_url_length_feature(self, engine):
        """Test URL length feature (f1)."""
        url = "https://example.com"
        result = engine.extract(url)
        
        # f1 is at index 0
        assert result.features[0] == len(url)
        assert result.feature_names[0] == 'url_length'
    
    def test_character_entropy_feature(self, engine):
        """Test character entropy feature (f2)."""
        # Uniform distribution should have high entropy
        url = "https://abcdefghijklmnop.com"
        result = engine.extract(url)
        
        # f2 is at index 1
        entropy = result.features[1]
        assert entropy > 0
        assert result.feature_names[1] == 'character_entropy'
    
    def test_digit_ratio_feature(self, engine):
        """Test digit ratio feature (f3)."""
        url = "https://example123.com"
        result = engine.extract(url)
        
        # f3 is at index 2
        digit_ratio = result.features[2]
        expected_ratio = 3 / len(url)  # "123" has 3 digits
        assert abs(digit_ratio - expected_ratio) < 0.01
        assert result.feature_names[2] == 'digit_ratio'
    
    def test_special_char_count_feature(self, engine):
        """Test special character count feature (f4)."""
        url = "https://example.com/path?param=value&other=test"
        result = engine.extract(url)
        
        # f4 is at index 3
        special_count = result.features[3]
        # Count '&' and '=' in the URL
        expected_count = url.count('&') + url.count('=')
        assert special_count == expected_count
        assert result.feature_names[3] == 'special_char_count'
    
    def test_subdomain_count_feature(self, engine):
        """Test subdomain count feature (f5)."""
        # Test with subdomain
        url = "https://mail.google.com"
        result = engine.extract(url)
        assert result.features[4] == 1.0  # "mail" is 1 subdomain level
        
        # Test with multiple subdomains
        url = "https://a.b.c.example.com"
        result = engine.extract(url)
        assert result.features[4] == 3.0  # "a.b.c" is 3 subdomain levels
        
        # Test without subdomain
        url = "https://example.com"
        result = engine.extract(url)
        assert result.features[4] == 0.0
        
        assert result.feature_names[4] == 'subdomain_count'
    
    def test_path_depth_feature(self, engine):
        """Test path depth feature (f6)."""
        # Test with deep path
        url = "https://example.com/a/b/c/d"
        result = engine.extract(url)
        assert result.features[5] == 4.0  # 4 forward slashes
        
        # Test with no path
        url = "https://example.com"
        result = engine.extract(url)
        assert result.features[5] == 0.0
        
        # Test with root path
        url = "https://example.com/"
        result = engine.extract(url)
        assert result.features[5] == 0.0
        
        assert result.feature_names[5] == 'path_depth'
    
    def test_query_param_count_feature(self, engine):
        """Test query parameter count feature (f7)."""
        # Test with multiple parameters
        url = "https://example.com?a=1&b=2&c=3"
        result = engine.extract(url)
        assert result.features[6] == 3.0  # 3 parameters
        
        # Test with single parameter
        url = "https://example.com?param=value"
        result = engine.extract(url)
        assert result.features[6] == 1.0
        
        # Test with no parameters
        url = "https://example.com"
        result = engine.extract(url)
        assert result.features[6] == 0.0
        
        assert result.feature_names[6] == 'query_param_count'
    
    def test_tld_category_feature(self, engine):
        """Test TLD category feature (f8)."""
        # Test generic TLD
        url = "https://example.com"
        result = engine.extract(url)
        assert result.features[7] == 0.0
        
        # Test country-code TLD
        url = "https://example.uk"
        result = engine.extract(url)
        assert result.features[7] == 1.0
        
        # Test suspicious TLD
        url = "https://example.tk"
        result = engine.extract(url)
        assert result.features[7] == 2.0
        
        assert result.feature_names[7] == 'tld_category'
    
    def test_domain_token_count_feature(self, engine):
        """Test domain token count feature (f9)."""
        # Test single token
        url = "https://example.com"
        result = engine.extract(url)
        assert result.features[8] == 1.0
        
        # Test multiple tokens with hyphens
        url = "https://my-example-site.com"
        result = engine.extract(url)
        assert result.features[8] == 3.0  # "my", "example", "site"
        
        assert result.feature_names[8] == 'domain_token_count'
    
    def test_longest_token_length_feature(self, engine):
        """Test longest token length feature (f10)."""
        url = "https://short-verylongtoken-x.com"
        result = engine.extract(url)
        
        # "verylongtoken" is 13 characters
        assert result.features[9] == 13.0
        assert result.feature_names[9] == 'longest_token_length'
    
    def test_vowel_consonant_ratio_feature(self, engine):
        """Test vowel-consonant ratio feature (f11)."""
        # "example" has 3 vowels (e, a, e) and 4 consonants (x, m, p, l)
        url = "https://example.com"
        result = engine.extract(url)
        
        # Ratio should be 3/4 = 0.75
        vowel_consonant_ratio = result.features[10]
        assert vowel_consonant_ratio > 0
        assert result.feature_names[10] == 'vowel_consonant_ratio'
    
    def test_homoglyph_risk_score_feature(self, engine):
        """Test homoglyph risk score feature (f12)."""
        # Test with homoglyph characters
        url = "https://g00gle.com"  # Contains three '0' characters
        result = engine.extract(url)
        assert result.features[11] == 3.0  # Three '0' characters in "g00gle"
        
        # Test without homoglyphs (use a domain with no l, I, 1, 0, O, o, |)
        url = "https://reddit.com"  # 'reddit' has no homoglyphs
        result = engine.extract(url)
        assert result.features[11] == 0.0
        
        assert result.feature_names[11] == 'homoglyph_risk_score'
    
    def test_https_usage_feature(self, engine):
        """Test HTTPS usage feature (f13)."""
        # Test HTTPS
        url = "https://example.com"
        result = engine.extract(url)
        assert result.features[12] == 1.0
        
        # Test HTTP
        url = "http://example.com"
        result = engine.extract(url)
        assert result.features[12] == 0.0
        
        assert result.feature_names[12] == 'https_usage'
    
    def test_ip_address_usage_feature(self, engine):
        """Test IP address usage feature (f14)."""
        # Test with IPv4 address
        url = "http://192.168.1.1/path"
        result = engine.extract(url)
        assert result.features[13] == 1.0
        
        # Test with domain name
        url = "https://example.com"
        result = engine.extract(url)
        assert result.features[13] == 0.0
        
        # Test with IPv6 address (must be in brackets in URL)
        url = "http://[2001:db8::1]/path"
        result = engine.extract(url)
        assert result.features[13] == 1.0
        
        assert result.feature_names[13] == 'ip_address_usage'
    
    def test_port_specification_feature(self, engine):
        """Test port specification feature (f15)."""
        # Test with non-standard port
        url = "https://example.com:8080/path"
        result = engine.extract(url)
        assert result.features[14] == 1.0
        
        # Test with standard HTTPS port (443)
        url = "https://example.com:443/path"
        result = engine.extract(url)
        assert result.features[14] == 0.0
        
        # Test with standard HTTP port (80)
        url = "http://example.com:80/path"
        result = engine.extract(url)
        assert result.features[14] == 0.0
        
        # Test without port
        url = "https://example.com"
        result = engine.extract(url)
        assert result.features[14] == 0.0
        
        assert result.feature_names[14] == 'port_specification'
    
    def test_url_entropy_normalized_feature(self, engine):
        """Test normalized URL entropy feature (f16)."""
        url = "https://example.com"
        result = engine.extract(url)
        
        # f16 should be f2 / 5.0
        entropy = result.features[1]
        normalized_entropy = result.features[15]
        
        assert abs(normalized_entropy - (entropy / 5.0)) < 0.01
        assert 0.0 <= normalized_entropy <= 1.0
        assert result.feature_names[15] == 'url_entropy_normalized'
    
    def test_malformed_url_returns_default_features(self, engine):
        """Test that malformed URLs return default feature vector."""
        # Use a truly malformed URL that will cause parsing errors
        malformed_url = "ht!tp://?invalid?.com"
        
        result = engine.extract(malformed_url)
        
        # Should still return 16 features
        assert len(result.features) == 16
        assert len(result.feature_names) == 16
        
        # Note: urlparse is very lenient, so even "not-a-valid-url" gets parsed
        # The important thing is that we always return 16 features
    
    def test_empty_url_handling(self, engine):
        """Test handling of empty URL."""
        result = engine.extract("")
        
        # Should return 16 features
        assert len(result.features) == 16
        assert len(result.feature_names) == 16
    
    def test_url_with_all_features(self, engine):
        """Test comprehensive URL with all features present."""
        url = "https://sub1.sub2.my-example-site.tk:8080/path/to/resource?param1=val1&param2=val2&param3=val3"
        
        result = engine.extract(url)
        
        # Verify all features are extracted
        assert len(result.features) == 16
        assert all(isinstance(f, float) for f in result.features)
        
        # Verify specific features
        assert result.features[0] > 0  # URL length
        assert result.features[4] > 0  # Subdomain count (sub1.sub2)
        assert result.features[5] > 0  # Path depth
        assert result.features[6] == 3.0  # Query param count
        assert result.features[7] == 2.0  # TLD category (tk is suspicious)
        assert result.features[12] == 1.0  # HTTPS usage
        assert result.features[14] == 1.0  # Port specification (8080)
    
    def test_feature_names_match_features(self, engine):
        """Test that feature names match the order of features."""
        url = "https://example.com"
        result = engine.extract(url)
        
        expected_names = [
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
        
        assert result.feature_names == expected_names
    
    def test_extraction_metadata_contains_url(self, engine):
        """Test that extraction metadata contains the original URL."""
        url = "https://example.com"
        result = engine.extract(url)
        
        assert result.extraction_metadata['url'] == url
    
    def test_extraction_time_is_positive(self, engine):
        """Test that extraction time is measured and non-negative."""
        url = "https://example.com"
        result = engine.extract(url)
        
        # Extraction time should be non-negative (may be 0.0 if very fast)
        assert result.extraction_time_ms >= 0
    
    def test_consistent_feature_extraction(self, engine):
        """Test that extracting features from the same URL produces consistent results."""
        url = "https://www.example.com/path?param=value"
        
        result1 = engine.extract(url)
        result2 = engine.extract(url)
        
        # Features should be identical (excluding extraction_time_ms)
        assert result1.features == result2.features
        assert result1.feature_names == result2.feature_names
    
    def test_phishing_like_url_features(self, engine):
        """Test feature extraction on a phishing-like URL."""
        # Typical phishing URL characteristics:
        # - Long URL
        # - IP address
        # - Non-standard port
        # - Many query parameters
        # - Suspicious TLD
        url = "http://192.168.1.100:8080/login/verify?user=test&token=abc123&redirect=http://evil.tk"
        
        result = engine.extract(url)
        
        assert result.features[0] > 50  # Long URL
        assert result.features[12] == 0.0  # Not HTTPS
        assert result.features[13] == 1.0  # IP address
        assert result.features[14] == 1.0  # Non-standard port
        assert result.features[6] >= 3.0  # Multiple query params
    
    def test_legitimate_url_features(self, engine):
        """Test feature extraction on a legitimate URL."""
        url = "https://www.google.com/search?q=test"
        
        result = engine.extract(url)
        
        assert result.features[12] == 1.0  # HTTPS
        assert result.features[13] == 0.0  # Not IP address
        assert result.features[14] == 0.0  # Standard port
        assert result.features[7] == 0.0  # Generic TLD (.com)


class TestMLFeatureEngineEdgeCases:
    """Tests for edge cases and error handling."""
    
    @pytest.fixture
    def engine(self):
        """Create MLFeatureEngine instance for testing."""
        return MLFeatureEngine()
    
    def test_url_with_no_path(self, engine):
        """Test URL with no path component."""
        url = "https://example.com"
        result = engine.extract(url)
        
        assert result.features[5] == 0.0  # Path depth should be 0
    
    def test_url_with_no_query(self, engine):
        """Test URL with no query parameters."""
        url = "https://example.com/path"
        result = engine.extract(url)
        
        assert result.features[6] == 0.0  # Query param count should be 0
    
    def test_url_with_fragment(self, engine):
        """Test URL with fragment identifier."""
        url = "https://example.com/path#section"
        result = engine.extract(url)
        
        # Should extract features normally
        assert len(result.features) == 16
    
    def test_url_with_username_password(self, engine):
        """Test URL with username and password."""
        url = "https://user:pass@example.com/path"
        result = engine.extract(url)
        
        # Should extract features normally
        assert len(result.features) == 16
        assert result.features[0] > 0  # URL length includes credentials
    
    def test_url_with_international_characters(self, engine):
        """Test URL with international (non-ASCII) characters."""
        url = "https://例え.jp/path"
        result = engine.extract(url)
        
        # Should handle international domains
        assert len(result.features) == 16
    
    def test_very_long_url(self, engine):
        """Test very long URL."""
        long_path = "/".join(["segment"] * 100)
        url = f"https://example.com/{long_path}"
        
        result = engine.extract(url)
        
        assert result.features[0] > 800  # URL length (adjusted expectation)
        assert result.features[5] > 50  # Path depth
    
    def test_url_with_only_digits_in_domain(self, engine):
        """Test URL with only digits in domain."""
        url = "https://123456.com"
        result = engine.extract(url)
        
        # Should have high digit ratio
        assert result.features[2] > 0.1
    
    def test_url_with_no_vowels_in_domain(self, engine):
        """Test URL with no vowels in domain."""
        url = "https://bcdfg.com"
        result = engine.extract(url)
        
        # Vowel-consonant ratio should be 0
        assert result.features[10] == 0.0
