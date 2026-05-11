"""
Unit tests for data pipeline.

**Validates: Requirements 19.1**
"""

import tempfile
from pathlib import Path

import pandas as pd
import pytest

from training.data_pipeline import DataPipeline, DatasetStatistics, PreparedDataset


class TestDataPipeline:
    """Test suite for DataPipeline class."""
    
    @pytest.fixture
    def temp_datasets(self):
        """Create temporary dataset files for testing."""
        temp_dir = tempfile.mkdtemp()
        temp_path = Path(temp_dir)
        
        # Create sample phishing URLs (OpenPhish format)
        openphish_path = temp_path / "openphish.txt"
        with open(openphish_path, 'w') as f:
            f.write("http://phishing1.com/login\n")
            f.write("https://phishing2.com/verify\n")
            f.write("http://phishing3.net/account\n")
            f.write("https://phishing4.org/secure\n")
            f.write("http://phishing5.com/update\n")
            f.write("http://phishing6.com/confirm\n")
            f.write("https://phishing7.net/validate\n")
            f.write("http://phishing8.org/signin\n")
            f.write("https://phishing9.com/auth\n")
            f.write("http://phishing10.net/portal\n")
        
        # Create sample phishing domains (PhishTank format)
        phishtank_path = temp_path / "phishing_domains.txt"
        with open(phishtank_path, 'w') as f:
            f.write("phishing11.com\n")
            f.write("phishing12.net\n")
            f.write("phishing13.org\n")
            f.write("phishing14.com\n")
            f.write("phishing15.net\n")
        
        # Create sample benign URLs (Alexa/Tranco format)
        benign_path = temp_path / "top-sites.csv"
        with open(benign_path, 'w') as f:
            f.write("1,google.com\n")
            f.write("2,facebook.com\n")
            f.write("3,youtube.com\n")
            f.write("4,amazon.com\n")
            f.write("5,twitter.com\n")
            f.write("6,wikipedia.org\n")
            f.write("7,reddit.com\n")
            f.write("8,linkedin.com\n")
            f.write("9,instagram.com\n")
            f.write("10,netflix.com\n")
            f.write("11,microsoft.com\n")
            f.write("12,apple.com\n")
            f.write("13,github.com\n")
            f.write("14,stackoverflow.com\n")
            f.write("15,medium.com\n")
        
        yield {
            'openphish_path': str(openphish_path),
            'phishtank_path': str(phishtank_path),
            'benign_path': str(benign_path)
        }
    
    def test_initialization(self, temp_datasets):
        """Test DataPipeline initialization."""
        pipeline = DataPipeline(
            openphish_path=temp_datasets['openphish_path'],
            phishtank_path=temp_datasets['phishtank_path'],
            benign_path=temp_datasets['benign_path']
        )
        
        assert pipeline.train_ratio == 0.70
        assert pipeline.validation_ratio == 0.15
        assert pipeline.test_ratio == 0.15
        assert pipeline.train_balance_ratio == 0.60
        assert pipeline.random_state == 42
    
    def test_invalid_split_ratios(self, temp_datasets):
        """Test that invalid split ratios raise ValueError."""
        with pytest.raises(ValueError, match="Split ratios must sum to 1.0"):
            DataPipeline(
                openphish_path=temp_datasets['openphish_path'],
                phishtank_path=temp_datasets['phishtank_path'],
                benign_path=temp_datasets['benign_path'],
                train_ratio=0.6,
                validation_ratio=0.2,
                test_ratio=0.3  # Sum = 1.1, invalid
            )
    
    def test_load_phishing_urls(self, temp_datasets):
        """Test loading phishing URLs from OpenPhish and PhishTank."""
        pipeline = DataPipeline(
            openphish_path=temp_datasets['openphish_path'],
            phishtank_path=temp_datasets['phishtank_path'],
            benign_path=temp_datasets['benign_path']
        )
        
        phishing_urls = pipeline._load_phishing_urls()
        
        # Should have 10 from OpenPhish + 5 from PhishTank = 15 total
        assert len(phishing_urls) == 15
        
        # Check that OpenPhish URLs are preserved as-is
        assert "http://phishing1.com/login" in phishing_urls
        assert "https://phishing2.com/verify" in phishing_urls
        
        # Check that PhishTank domains have http:// added
        assert "http://phishing11.com" in phishing_urls
        assert "http://phishing12.net" in phishing_urls
    
    def test_load_benign_urls(self, temp_datasets):
        """Test loading benign URLs from Alexa/Tranco."""
        pipeline = DataPipeline(
            openphish_path=temp_datasets['openphish_path'],
            phishtank_path=temp_datasets['phishtank_path'],
            benign_path=temp_datasets['benign_path']
        )
        
        benign_urls = pipeline._load_benign_urls()
        
        # Should have 15 benign URLs
        assert len(benign_urls) == 15
        
        # Check that https:// is added
        assert "https://google.com" in benign_urls
        assert "https://facebook.com" in benign_urls
    
    def test_normalize_domain(self, temp_datasets):
        """Test domain normalization for deduplication."""
        pipeline = DataPipeline(
            openphish_path=temp_datasets['openphish_path'],
            phishtank_path=temp_datasets['phishtank_path'],
            benign_path=temp_datasets['benign_path']
        )
        
        # Test basic normalization
        assert pipeline._normalize_domain("http://Example.COM/path") == "example.com"
        assert pipeline._normalize_domain("https://www.google.com") == "google.com"
        assert pipeline._normalize_domain("http://site.com:8080/page") == "site.com"
        
        # Test www. removal
        assert pipeline._normalize_domain("https://www.facebook.com") == "facebook.com"
        
        # Test lowercase conversion
        assert pipeline._normalize_domain("https://GitHub.COM") == "github.com"
    
    def test_filter_malformed_urls(self, temp_datasets):
        """Test filtering of malformed URLs."""
        pipeline = DataPipeline(
            openphish_path=temp_datasets['openphish_path'],
            phishtank_path=temp_datasets['phishtank_path'],
            benign_path=temp_datasets['benign_path']
        )
        
        # Create test DataFrame with some malformed URLs
        df = pd.DataFrame({
            'url': [
                'http://valid.com',
                'https://also-valid.com/path',
                'not-a-url',  # No scheme
                'http://',  # No netloc
                '',  # Empty
                'ftp://valid-but-ftp.com'  # Valid but FTP
            ],
            'label': [0, 0, 0, 0, 0, 0],
            'normalized_domain': ['valid.com', 'also-valid.com', '', '', '', 'valid-but-ftp.com']
        })
        
        df_filtered, filtered_count = pipeline._filter_malformed_urls(df)
        
        # Should keep valid http/https URLs
        assert len(df_filtered) == 3  # http://valid.com, https://also-valid.com, ftp://valid-but-ftp.com
        assert filtered_count == 3
    
    def test_deduplicate_urls(self, temp_datasets):
        """Test URL deduplication by normalized domain."""
        pipeline = DataPipeline(
            openphish_path=temp_datasets['openphish_path'],
            phishtank_path=temp_datasets['phishtank_path'],
            benign_path=temp_datasets['benign_path']
        )
        
        # Create test DataFrame with duplicates
        df = pd.DataFrame({
            'url': [
                'http://example.com/page1',
                'https://example.com/page2',  # Duplicate domain
                'http://www.example.com/page3',  # Duplicate domain (www.)
                'http://different.com/page'
            ],
            'label': [0, 0, 0, 0],
            'normalized_domain': ['example.com', 'example.com', 'example.com', 'different.com']
        })
        
        df_deduped, duplicates_removed = pipeline._deduplicate_urls(df)
        
        # Should keep only first occurrence of each domain
        assert len(df_deduped) == 2  # example.com and different.com
        assert duplicates_removed == 2
    
    def test_stratified_split(self, temp_datasets):
        """Test stratified train/validation/test split."""
        pipeline = DataPipeline(
            openphish_path=temp_datasets['openphish_path'],
            phishtank_path=temp_datasets['phishtank_path'],
            benign_path=temp_datasets['benign_path']
        )
        
        # Create test DataFrame with balanced classes
        df = pd.DataFrame({
            'url': [f'http://site{i}.com' for i in range(100)],
            'label': [0] * 50 + [1] * 50,  # 50 benign, 50 phishing
            'normalized_domain': [f'site{i}.com' for i in range(100)]
        })
        
        train_df, validation_df, test_df = pipeline._stratified_split(df)
        
        # Check split sizes (approximately 70/15/15)
        assert len(train_df) == 70
        assert len(validation_df) == 15
        assert len(test_df) == 15
        
        # Check stratification (should maintain 50/50 ratio in each split)
        train_phishing_ratio = (train_df['label'] == 1).sum() / len(train_df)
        val_phishing_ratio = (validation_df['label'] == 1).sum() / len(validation_df)
        test_phishing_ratio = (test_df['label'] == 1).sum() / len(test_df)
        
        assert abs(train_phishing_ratio - 0.5) < 0.1  # Within 10% of 50%
        assert abs(val_phishing_ratio - 0.5) < 0.2  # Within 20% of 50% (smaller sample)
        assert abs(test_phishing_ratio - 0.5) < 0.2  # Within 20% of 50% (smaller sample)
    
    def test_balance_training_data(self, temp_datasets):
        """Test balancing of training data to target ratio."""
        pipeline = DataPipeline(
            openphish_path=temp_datasets['openphish_path'],
            phishtank_path=temp_datasets['phishtank_path'],
            benign_path=temp_datasets['benign_path'],
            train_balance_ratio=0.60  # 60% phishing, 40% benign
        )
        
        # Create imbalanced training DataFrame (more benign than phishing)
        train_df = pd.DataFrame({
            'url': [f'http://site{i}.com' for i in range(100)],
            'label': [0] * 80 + [1] * 20,  # 80 benign, 20 phishing
            'normalized_domain': [f'site{i}.com' for i in range(100)]
        })
        
        balanced_df = pipeline._balance_training_data(train_df)
        
        # Check that phishing ratio is approximately 60%
        phishing_count = (balanced_df['label'] == 1).sum()
        phishing_ratio = phishing_count / len(balanced_df)
        
        assert abs(phishing_ratio - 0.60) < 0.05  # Within 5% of target
    
    def test_verify_no_domain_overlap(self, temp_datasets):
        """Test verification of no domain overlap between splits."""
        pipeline = DataPipeline(
            openphish_path=temp_datasets['openphish_path'],
            phishtank_path=temp_datasets['phishtank_path'],
            benign_path=temp_datasets['benign_path']
        )
        
        # Create non-overlapping splits
        train_df = pd.DataFrame({
            'url': ['http://train1.com', 'http://train2.com'],
            'label': [0, 1],
            'normalized_domain': ['train1.com', 'train2.com']
        })
        
        validation_df = pd.DataFrame({
            'url': ['http://val1.com', 'http://val2.com'],
            'label': [0, 1],
            'normalized_domain': ['val1.com', 'val2.com']
        })
        
        test_df = pd.DataFrame({
            'url': ['http://test1.com', 'http://test2.com'],
            'label': [0, 1],
            'normalized_domain': ['test1.com', 'test2.com']
        })
        
        # Should not raise error
        pipeline._verify_no_domain_overlap(train_df, validation_df, test_df)
        
        # Create overlapping splits
        train_df_overlap = pd.DataFrame({
            'url': ['http://train1.com', 'http://overlap.com'],
            'label': [0, 1],
            'normalized_domain': ['train1.com', 'overlap.com']
        })
        
        validation_df_overlap = pd.DataFrame({
            'url': ['http://val1.com', 'http://overlap.com'],
            'label': [0, 1],
            'normalized_domain': ['val1.com', 'overlap.com']
        })
        
        # Should raise ValueError
        with pytest.raises(ValueError, match="domains in both train and validation sets"):
            pipeline._verify_no_domain_overlap(train_df_overlap, validation_df_overlap, test_df)
    
    def test_prepare_dataset_end_to_end(self, temp_datasets):
        """Test end-to-end dataset preparation."""
        pipeline = DataPipeline(
            openphish_path=temp_datasets['openphish_path'],
            phishtank_path=temp_datasets['phishtank_path'],
            benign_path=temp_datasets['benign_path']
        )
        
        dataset = pipeline.prepare_dataset()
        
        # Check that dataset is PreparedDataset instance
        assert isinstance(dataset, PreparedDataset)
        
        # Check that all splits are present
        assert len(dataset.X_train) > 0
        assert len(dataset.y_train) > 0
        assert len(dataset.X_validation) > 0
        assert len(dataset.y_validation) > 0
        assert len(dataset.X_test) > 0
        assert len(dataset.y_test) > 0
        
        # Check that X has 'url' column
        assert 'url' in dataset.X_train.columns
        assert 'url' in dataset.X_validation.columns
        assert 'url' in dataset.X_test.columns
        
        # Check that y contains labels (0 or 1)
        assert set(dataset.y_train.unique()).issubset({0, 1})
        assert set(dataset.y_validation.unique()).issubset({0, 1})
        assert set(dataset.y_test.unique()).issubset({0, 1})
        
        # Check that statistics are computed
        assert isinstance(dataset.statistics, DatasetStatistics)
        assert dataset.statistics.total_samples > 0
        assert dataset.statistics.phishing_count > 0
        assert dataset.statistics.benign_count > 0
        
        # Check that training data is balanced to ~60% phishing
        train_phishing_ratio = dataset.statistics.train_phishing_ratio
        assert abs(train_phishing_ratio - 0.60) < 0.05  # Within 5% of target
        
        # Check that validation and test preserve natural imbalance
        # (In our test data, we have 15 phishing and 15 benign, so ~50%)
        val_phishing_ratio = dataset.statistics.validation_phishing_ratio
        test_phishing_ratio = dataset.statistics.test_phishing_ratio
        assert 0.3 < val_phishing_ratio < 0.7  # Natural imbalance preserved
        assert 0.3 < test_phishing_ratio < 0.7  # Natural imbalance preserved
    
    def test_compute_statistics(self, temp_datasets):
        """Test computation of dataset statistics."""
        pipeline = DataPipeline(
            openphish_path=temp_datasets['openphish_path'],
            phishtank_path=temp_datasets['phishtank_path'],
            benign_path=temp_datasets['benign_path']
        )
        
        # Create test DataFrames
        train_df = pd.DataFrame({
            'url': ['http://train1.com', 'http://train2.com', 'http://train3.com'],
            'label': [0, 1, 1],
            'normalized_domain': ['train1.com', 'train2.com', 'train3.com']
        })
        
        validation_df = pd.DataFrame({
            'url': ['http://val1.com'],
            'label': [0],
            'normalized_domain': ['val1.com']
        })
        
        test_df = pd.DataFrame({
            'url': ['http://test1.com'],
            'label': [1],
            'normalized_domain': ['test1.com']
        })
        
        statistics = pipeline._compute_statistics(
            train_df, validation_df, test_df,
            filtered_count=2,
            duplicates_removed=3,
            unique_domains=5
        )
        
        # Check statistics
        assert statistics.total_samples == 5
        assert statistics.phishing_count == 3
        assert statistics.benign_count == 2
        assert statistics.train_size == 3
        assert statistics.validation_size == 1
        assert statistics.test_size == 1
        assert statistics.filtered_malformed == 2
        assert statistics.duplicates_removed == 3
        assert statistics.unique_domains == 5
        
        # Check class distribution
        assert abs(statistics.class_distribution['phishing'] - 0.6) < 0.01
        assert abs(statistics.class_distribution['benign'] - 0.4) < 0.01
        
        # Check feature distributions
        assert 'url_length' in statistics.feature_distributions
        assert 'https_usage' in statistics.feature_distributions
