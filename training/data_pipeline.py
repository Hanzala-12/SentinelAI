"""
Data Pipeline for ML-First Unified Detection System.

This module implements the Training_Pipeline component that prepares datasets
for model training. It loads phishing and benign URLs from multiple sources,
performs deduplication, filtering, stratified splitting, and balancing.

**Validates: Requirements 11.1-11.9**
"""

import logging
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)


@dataclass
class DatasetStatistics:
    """Statistics about the prepared dataset.
    
    **Validates: Requirement 11.8**
    """
    total_samples: int
    phishing_count: int
    benign_count: int
    class_distribution: dict[str, float]
    feature_distributions: dict[str, dict[str, float]]
    missing_value_counts: dict[str, int]
    train_size: int
    validation_size: int
    test_size: int
    train_phishing_ratio: float
    validation_phishing_ratio: float
    test_phishing_ratio: float
    unique_domains: int
    filtered_malformed: int
    duplicates_removed: int


@dataclass
class PreparedDataset:
    """Prepared dataset with train/validation/test splits.
    
    **Validates: Requirements 11.3, 11.6, 11.7**
    """
    X_train: pd.DataFrame
    y_train: pd.Series
    X_validation: pd.DataFrame
    y_validation: pd.Series
    X_test: pd.DataFrame
    y_test: pd.Series
    statistics: DatasetStatistics
    metadata: dict[str, Any]


class DataPipeline:
    """Data preparation pipeline for ML model training.
    
    This class implements the Training_Pipeline component that:
    1. Loads phishing URLs from OpenPhish and PhishTank datasets
    2. Loads benign URLs from Alexa Top 1M or Tranco list
    3. Deduplicates URLs by normalized domain
    4. Filters out malformed URLs
    5. Performs stratified train/validation/test split (70/15/15)
    6. Balances training data to 60/40 phishing/benign ratio
    7. Preserves natural imbalance in validation and test sets
    8. Logs comprehensive dataset statistics
    
    **Validates: Requirements 11.1-11.9**
    """
    
    def __init__(
        self,
        openphish_path: str = "evaluation/datasets/openphish.txt",
        phishtank_path: str = "evaluation/datasets/phishing_domains.txt",
        benign_path: str = "evaluation/datasets/top-sites/top-1m.csv",
        train_ratio: float = 0.70,
        validation_ratio: float = 0.15,
        test_ratio: float = 0.15,
        train_balance_ratio: float = 0.60,  # 60% phishing, 40% benign
        random_state: int = 42
    ):
        """Initialize data pipeline.
        
        Args:
            openphish_path: Path to OpenPhish dataset (one URL per line)
            phishtank_path: Path to PhishTank dataset (one domain per line)
            benign_path: Path to benign URLs (CSV format: rank,domain)
            train_ratio: Proportion of data for training (default: 0.70)
            validation_ratio: Proportion of data for validation (default: 0.15)
            test_ratio: Proportion of data for test (default: 0.15)
            train_balance_ratio: Target phishing ratio in training set (default: 0.60)
            random_state: Random seed for reproducibility
            
        **Validates: Requirements 11.1-11.3, 11.6**
        """
        self.openphish_path = Path(openphish_path)
        self.phishtank_path = Path(phishtank_path)
        self.benign_path = Path(benign_path)
        self.train_ratio = train_ratio
        self.validation_ratio = validation_ratio
        self.test_ratio = test_ratio
        self.train_balance_ratio = train_balance_ratio
        self.random_state = random_state
        
        # Validate split ratios
        if not np.isclose(train_ratio + validation_ratio + test_ratio, 1.0):
            raise ValueError(
                f"Split ratios must sum to 1.0, got {train_ratio + validation_ratio + test_ratio}"
            )
    
    def prepare_dataset(self) -> PreparedDataset:
        """Prepare complete dataset with train/validation/test splits.
        
        Returns:
            PreparedDataset containing splits and statistics
            
        **Validates: Requirements 11.1-11.9**
        """
        logger.info("Starting data pipeline...")
        
        # Step 1: Load datasets
        logger.info("Loading phishing URLs...")
        phishing_urls = self._load_phishing_urls()
        logger.info(f"Loaded {len(phishing_urls)} phishing URLs")
        
        logger.info("Loading benign URLs...")
        benign_urls = self._load_benign_urls()
        logger.info(f"Loaded {len(benign_urls)} benign URLs")
        
        # Step 2: Create labeled dataset
        df = self._create_labeled_dataset(phishing_urls, benign_urls)
        logger.info(f"Created dataset with {len(df)} total URLs")
        
        # Step 3: Filter malformed URLs
        df_filtered, filtered_count = self._filter_malformed_urls(df)
        logger.info(f"Filtered {filtered_count} malformed URLs, {len(df_filtered)} remaining")
        
        # Step 4: Deduplicate by normalized domain
        df_deduped, duplicates_removed = self._deduplicate_urls(df_filtered)
        logger.info(f"Removed {duplicates_removed} duplicates, {len(df_deduped)} unique URLs")
        
        # Step 5: Stratified train/validation/test split
        train_df, validation_df, test_df = self._stratified_split(df_deduped)
        logger.info(
            f"Split dataset: train={len(train_df)}, "
            f"validation={len(validation_df)}, test={len(test_df)}"
        )
        
        # Step 6: Balance training data
        train_df_balanced = self._balance_training_data(train_df)
        logger.info(
            f"Balanced training data: {len(train_df_balanced)} samples "
            f"({self.train_balance_ratio:.0%} phishing)"
        )
        
        # Step 7: Verify no domain overlap
        self._verify_no_domain_overlap(train_df_balanced, validation_df, test_df)
        logger.info("Verified no domain overlap between splits")
        
        # Step 8: Prepare X, y splits
        X_train = train_df_balanced[['url']]
        y_train = train_df_balanced['label']
        X_validation = validation_df[['url']]
        y_validation = validation_df['label']
        X_test = test_df[['url']]
        y_test = test_df['label']
        
        # Step 9: Compute statistics
        statistics = self._compute_statistics(
            train_df_balanced, validation_df, test_df,
            filtered_count, duplicates_removed, len(df_deduped)
        )
        
        # Step 10: Log statistics
        self._log_statistics(statistics)
        
        metadata = {
            'openphish_path': str(self.openphish_path),
            'phishtank_path': str(self.phishtank_path),
            'benign_path': str(self.benign_path),
            'train_ratio': self.train_ratio,
            'validation_ratio': self.validation_ratio,
            'test_ratio': self.test_ratio,
            'train_balance_ratio': self.train_balance_ratio,
            'random_state': self.random_state
        }
        
        return PreparedDataset(
            X_train=X_train,
            y_train=y_train,
            X_validation=X_validation,
            y_validation=y_validation,
            X_test=X_test,
            y_test=y_test,
            statistics=statistics,
            metadata=metadata
        )
    
    def _load_phishing_urls(self) -> list[str]:
        """Load phishing URLs from OpenPhish and PhishTank datasets.
        
        Returns:
            List of phishing URLs
            
        **Validates: Requirement 11.1**
        """
        phishing_urls = []
        
        # Load OpenPhish (full URLs)
        if self.openphish_path.exists():
            with open(self.openphish_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        phishing_urls.append(url)
        else:
            logger.warning(f"OpenPhish file not found: {self.openphish_path}")
        
        # Load PhishTank (domains only, need to add scheme)
        if self.phishtank_path.exists():
            with open(self.phishtank_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        # Add http:// scheme if not present
                        if not domain.startswith(('http://', 'https://')):
                            url = f"http://{domain}"
                        else:
                            url = domain
                        phishing_urls.append(url)
        else:
            logger.warning(f"PhishTank file not found: {self.phishtank_path}")
        
        return phishing_urls
    
    def _load_benign_urls(self) -> list[str]:
        """Load benign URLs from Alexa Top 1M or Tranco list.
        
        Returns:
            List of benign URLs
            
        **Validates: Requirement 11.2**
        """
        benign_urls = []
        
        if not self.benign_path.exists():
            logger.warning(f"Benign URLs file not found: {self.benign_path}")
            return benign_urls
        
        # Load CSV format: rank,domain
        try:
            df = pd.read_csv(self.benign_path, header=None, names=['rank', 'domain'])
            for domain in df['domain']:
                # Add https:// scheme (benign sites typically use HTTPS)
                url = f"https://{domain}"
                benign_urls.append(url)
        except Exception as e:
            logger.error(f"Error loading benign URLs: {e}")
        
        return benign_urls
    
    def _create_labeled_dataset(
        self,
        phishing_urls: list[str],
        benign_urls: list[str]
    ) -> pd.DataFrame:
        """Create labeled dataset from phishing and benign URLs.
        
        Args:
            phishing_urls: List of phishing URLs
            benign_urls: List of benign URLs
            
        Returns:
            DataFrame with columns: url, label, normalized_domain
        """
        data = []
        
        # Add phishing URLs (label=1)
        for url in phishing_urls:
            normalized_domain = self._normalize_domain(url)
            data.append({
                'url': url,
                'label': 1,
                'normalized_domain': normalized_domain
            })
        
        # Add benign URLs (label=0)
        for url in benign_urls:
            normalized_domain = self._normalize_domain(url)
            data.append({
                'url': url,
                'label': 0,
                'normalized_domain': normalized_domain
            })
        
        return pd.DataFrame(data)
    
    def _normalize_domain(self, url: str) -> str:
        """Normalize domain for deduplication.
        
        Extracts the domain from URL and converts to lowercase.
        
        Args:
            url: Raw URL string
            
        Returns:
            Normalized domain string
            
        **Validates: Requirement 11.4**
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            # Remove port if present
            domain = domain.split(':')[0]
            # Convert to lowercase
            domain = domain.lower()
            # Remove www. prefix for better deduplication
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except Exception:
            return url.lower()
    
    def _filter_malformed_urls(self, df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
        """Filter out URLs with missing or malformed components.
        
        Args:
            df: DataFrame with url column
            
        Returns:
            Tuple of (filtered DataFrame, count of filtered URLs)
            
        **Validates: Requirement 11.5**
        """
        initial_count = len(df)
        
        def is_valid_url(url: str) -> bool:
            """Check if URL is valid."""
            try:
                parsed = urlparse(url)
                # Must have scheme
                if not parsed.scheme:
                    return False
                # Must have netloc or path
                if not parsed.netloc and not parsed.path:
                    return False
                # Netloc should not be empty for http/https
                if parsed.scheme in ('http', 'https') and not parsed.netloc:
                    return False
                return True
            except Exception:
                return False
        
        df_filtered = df[df['url'].apply(is_valid_url)].copy()
        filtered_count = initial_count - len(df_filtered)
        
        return df_filtered, filtered_count
    
    def _deduplicate_urls(self, df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
        """Deduplicate URLs by normalized domain.
        
        Keeps the first occurrence of each domain.
        
        Args:
            df: DataFrame with normalized_domain column
            
        Returns:
            Tuple of (deduplicated DataFrame, count of duplicates removed)
            
        **Validates: Requirement 11.4**
        """
        initial_count = len(df)
        df_deduped = df.drop_duplicates(subset=['normalized_domain'], keep='first').copy()
        duplicates_removed = initial_count - len(df_deduped)
        
        return df_deduped, duplicates_removed
    
    def _stratified_split(
        self,
        df: pd.DataFrame
    ) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Perform stratified train/validation/test split.
        
        Args:
            df: DataFrame with label column
            
        Returns:
            Tuple of (train_df, validation_df, test_df)
            
        **Validates: Requirement 11.3**
        """
        # First split: train vs (validation + test)
        train_df, temp_df = train_test_split(
            df,
            test_size=(self.validation_ratio + self.test_ratio),
            stratify=df['label'],
            random_state=self.random_state
        )
        
        # Second split: validation vs test
        # Calculate relative test size
        relative_test_size = self.test_ratio / (self.validation_ratio + self.test_ratio)
        validation_df, test_df = train_test_split(
            temp_df,
            test_size=relative_test_size,
            stratify=temp_df['label'],
            random_state=self.random_state
        )
        
        return train_df, validation_df, test_df
    
    def _balance_training_data(self, train_df: pd.DataFrame) -> pd.DataFrame:
        """Balance training data to target phishing/benign ratio.
        
        Args:
            train_df: Training DataFrame with label column
            
        Returns:
            Balanced training DataFrame
            
        **Validates: Requirement 11.6**
        """
        phishing_df = train_df[train_df['label'] == 1]
        benign_df = train_df[train_df['label'] == 0]
        
        phishing_count = len(phishing_df)
        benign_count = len(benign_df)
        
        # Calculate target counts for desired ratio
        # If we want 60% phishing and 40% benign:
        # phishing_count / (phishing_count + benign_count) = 0.60
        # Solve for benign_count given phishing_count
        target_benign_count = int(phishing_count * (1 - self.train_balance_ratio) / self.train_balance_ratio)
        
        # Downsample benign if we have too many
        if benign_count > target_benign_count:
            benign_df_sampled = benign_df.sample(
                n=target_benign_count,
                random_state=self.random_state
            )
        else:
            # If we don't have enough benign, adjust phishing count instead
            target_phishing_count = int(benign_count * self.train_balance_ratio / (1 - self.train_balance_ratio))
            if phishing_count > target_phishing_count:
                phishing_df = phishing_df.sample(
                    n=target_phishing_count,
                    random_state=self.random_state
                )
            benign_df_sampled = benign_df
        
        # Combine and shuffle
        balanced_df = pd.concat([phishing_df, benign_df_sampled], ignore_index=True)
        balanced_df = balanced_df.sample(frac=1, random_state=self.random_state).reset_index(drop=True)
        
        return balanced_df
    
    def _verify_no_domain_overlap(
        self,
        train_df: pd.DataFrame,
        validation_df: pd.DataFrame,
        test_df: pd.DataFrame
    ) -> None:
        """Verify no domain overlap between train, validation, and test sets.
        
        Args:
            train_df: Training DataFrame
            validation_df: Validation DataFrame
            test_df: Test DataFrame
            
        Raises:
            ValueError: If domain overlap is detected
            
        **Validates: Requirement 11.9**
        """
        train_domains = set(train_df['normalized_domain'])
        validation_domains = set(validation_df['normalized_domain'])
        test_domains = set(test_df['normalized_domain'])
        
        train_val_overlap = train_domains & validation_domains
        train_test_overlap = train_domains & test_domains
        val_test_overlap = validation_domains & test_domains
        
        if train_val_overlap:
            raise ValueError(
                f"Found {len(train_val_overlap)} domains in both train and validation sets"
            )
        
        if train_test_overlap:
            raise ValueError(
                f"Found {len(train_test_overlap)} domains in both train and test sets"
            )
        
        if val_test_overlap:
            raise ValueError(
                f"Found {len(val_test_overlap)} domains in both validation and test sets"
            )
    
    def _compute_statistics(
        self,
        train_df: pd.DataFrame,
        validation_df: pd.DataFrame,
        test_df: pd.DataFrame,
        filtered_count: int,
        duplicates_removed: int,
        unique_domains: int
    ) -> DatasetStatistics:
        """Compute comprehensive dataset statistics.
        
        Args:
            train_df: Training DataFrame
            validation_df: Validation DataFrame
            test_df: Test DataFrame
            filtered_count: Number of filtered malformed URLs
            duplicates_removed: Number of duplicates removed
            unique_domains: Number of unique domains
            
        Returns:
            DatasetStatistics object
            
        **Validates: Requirement 11.8**
        """
        total_samples = len(train_df) + len(validation_df) + len(test_df)
        
        # Class distribution
        train_phishing = (train_df['label'] == 1).sum()
        train_benign = (train_df['label'] == 0).sum()
        val_phishing = (validation_df['label'] == 1).sum()
        val_benign = (validation_df['label'] == 0).sum()
        test_phishing = (test_df['label'] == 1).sum()
        test_benign = (test_df['label'] == 0).sum()
        
        total_phishing = train_phishing + val_phishing + test_phishing
        total_benign = train_benign + val_benign + test_benign
        
        class_distribution = {
            'phishing': total_phishing / total_samples,
            'benign': total_benign / total_samples
        }
        
        # Feature distributions (basic URL characteristics)
        all_urls = pd.concat([
            train_df['url'],
            validation_df['url'],
            test_df['url']
        ])
        
        url_lengths = all_urls.apply(len)
        https_usage = all_urls.apply(lambda u: u.startswith('https://')).sum() / len(all_urls)
        
        feature_distributions = {
            'url_length': {
                'mean': float(url_lengths.mean()),
                'std': float(url_lengths.std()),
                'min': float(url_lengths.min()),
                'max': float(url_lengths.max())
            },
            'https_usage': {
                'ratio': float(https_usage)
            }
        }
        
        # Missing value counts (should be zero after filtering)
        missing_value_counts = {
            'url': 0,
            'label': 0,
            'normalized_domain': 0
        }
        
        return DatasetStatistics(
            total_samples=total_samples,
            phishing_count=total_phishing,
            benign_count=total_benign,
            class_distribution=class_distribution,
            feature_distributions=feature_distributions,
            missing_value_counts=missing_value_counts,
            train_size=len(train_df),
            validation_size=len(validation_df),
            test_size=len(test_df),
            train_phishing_ratio=train_phishing / len(train_df),
            validation_phishing_ratio=val_phishing / len(validation_df),
            test_phishing_ratio=test_phishing / len(test_df),
            unique_domains=unique_domains,
            filtered_malformed=filtered_count,
            duplicates_removed=duplicates_removed
        )
    
    def _log_statistics(self, statistics: DatasetStatistics) -> None:
        """Log comprehensive dataset statistics.
        
        Args:
            statistics: DatasetStatistics object
            
        **Validates: Requirement 11.8**
        """
        logger.info("=" * 80)
        logger.info("DATASET STATISTICS")
        logger.info("=" * 80)
        
        logger.info(f"Total samples: {statistics.total_samples}")
        logger.info(f"  Phishing: {statistics.phishing_count} ({statistics.class_distribution['phishing']:.2%})")
        logger.info(f"  Benign: {statistics.benign_count} ({statistics.class_distribution['benign']:.2%})")
        logger.info("")
        
        logger.info("Split sizes:")
        logger.info(f"  Training: {statistics.train_size} ({statistics.train_phishing_ratio:.2%} phishing)")
        logger.info(f"  Validation: {statistics.validation_size} ({statistics.validation_phishing_ratio:.2%} phishing)")
        logger.info(f"  Test: {statistics.test_size} ({statistics.test_phishing_ratio:.2%} phishing)")
        logger.info("")
        
        logger.info("Data quality:")
        logger.info(f"  Unique domains: {statistics.unique_domains}")
        logger.info(f"  Duplicates removed: {statistics.duplicates_removed}")
        logger.info(f"  Malformed URLs filtered: {statistics.filtered_malformed}")
        logger.info("")
        
        logger.info("Feature distributions:")
        url_length_stats = statistics.feature_distributions['url_length']
        logger.info(
            f"  URL length: mean={url_length_stats['mean']:.1f}, "
            f"std={url_length_stats['std']:.1f}, "
            f"min={url_length_stats['min']:.0f}, "
            f"max={url_length_stats['max']:.0f}"
        )
        https_ratio = statistics.feature_distributions['https_usage']['ratio']
        logger.info(f"  HTTPS usage: {https_ratio:.2%}")
        logger.info("")
        
        logger.info("Missing values:")
        for col, count in statistics.missing_value_counts.items():
            logger.info(f"  {col}: {count}")
        
        logger.info("=" * 80)


def main():
    """Main function for testing data pipeline."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    pipeline = DataPipeline()
    dataset = pipeline.prepare_dataset()
    
    print("\nDataset prepared successfully!")
    print(f"Training samples: {len(dataset.X_train)}")
    print(f"Validation samples: {len(dataset.X_validation)}")
    print(f"Test samples: {len(dataset.X_test)}")


if __name__ == '__main__':
    main()
