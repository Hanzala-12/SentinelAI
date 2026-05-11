"""
Dataset loader with configurable sampling for ML training.

This module wraps the unified loader to provide:
- Stratified sampling (configurable size per dataset)
- Automatic class balancing
- Train/test split support
- Feature extraction integration
"""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from evaluation.utils.unified_loader import load_all_datasets

logger = logging.getLogger(__name__)


class SampledDatasetLoader:
    """Load datasets with configurable stratified sampling."""

    def __init__(self, datasets_dir: str | Path) -> None:
        """Initialize loader with datasets directory."""
        self.datasets_dir = Path(datasets_dir)

    def load_with_sampling(
        self,
        sample_size: int = 100,
        balance: bool = True,
    ) -> pd.DataFrame:
        """
        Load and sample datasets.

        Args:
            sample_size: Number of samples per dataset (default 100)
            balance: Whether to balance classes within each sample (default True)

        Returns:
            DataFrame with sampled URLs ready for ML
        """
        # Load all datasets
        merged_df, summaries = load_all_datasets(self.datasets_dir)

        logger.info(f"Loaded {len(merged_df)} total rows from all datasets")
        logger.info(f"Class distribution: {merged_df['label'].value_counts().to_dict()}")

        # Sample from each dataset
        samples = []
        for source_dataset in merged_df["source_dataset"].unique():
            source_data = merged_df[merged_df["source_dataset"] == source_dataset]

            if balance:
                # Sample equally from each class within this source
                class_0 = source_data[source_data["label"] == 0]
                class_1 = source_data[source_data["label"] == 1]

                # Determine how many of each class to sample
                samples_per_class = sample_size // 2

                # Sample up to samples_per_class from each class
                class_0_sample = class_0.sample(n=min(len(class_0), samples_per_class), random_state=42)
                class_1_sample = class_1.sample(n=min(len(class_1), samples_per_class), random_state=42)

                samples.append(class_0_sample)
                samples.append(class_1_sample)

                logger.info(
                    f"Source '{source_dataset}': "
                    f"sampled {len(class_0_sample)} benign + {len(class_1_sample)} phishing"
                )
            else:
                # Simple random sampling
                sample = source_data.sample(n=min(len(source_data), sample_size), random_state=42)
                samples.append(sample)
                logger.info(f"Source '{source_dataset}': sampled {len(sample)} URLs")

        # Combine samples
        sampled_df = pd.concat(samples, ignore_index=True)

        logger.info(f"Total sampled URLs: {len(sampled_df)}")
        logger.info(f"Sampled class distribution: {sampled_df['label'].value_counts().to_dict()}")

        # Shuffle to mix datasets
        sampled_df = sampled_df.sample(frac=1, random_state=42).reset_index(drop=True)

        return sampled_df

    def load_with_specific_split(
        self,
        train_size: int = 100,
        test_size: int = 50,
        balance: bool = True,
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        """
        Load datasets with explicit train/test split (alternative to sklearn's split).

        Args:
            train_size: Number of samples per dataset for training
            test_size: Number of samples per dataset for testing
            balance: Whether to balance classes (default True)

        Returns:
            Tuple of (train_df, test_df)
        """
        # Load all datasets
        merged_df, _ = load_all_datasets(str(self.datasets_dir))

        train_samples = []
        test_samples = []

        for source_dataset in merged_df["source_dataset"].unique():
            source_data = merged_df[merged_df["source_dataset"] == source_dataset]

            if balance:
                # Split within each class
                class_0 = source_data[source_data["label"] == 0]
                class_1 = source_data[source_data["label"] == 1]

                train_per_class = train_size // 2
                test_per_class = test_size // 2

                # Sample training set
                class_0_train = class_0.sample(
                    n=min(len(class_0), train_per_class), random_state=42
                )
                class_1_train = class_1.sample(
                    n=min(len(class_1), train_per_class), random_state=42
                )

                # Sample test set from remaining
                remaining_class_0 = class_0.drop(class_0_train.index)
                remaining_class_1 = class_1.drop(class_1_train.index)

                class_0_test = remaining_class_0.sample(
                    n=min(len(remaining_class_0), test_per_class), random_state=42
                )
                class_1_test = remaining_class_1.sample(
                    n=min(len(remaining_class_1), test_per_class), random_state=42
                )

                train_samples.append(pd.concat([class_0_train, class_1_train]))
                test_samples.append(pd.concat([class_0_test, class_1_test]))
            else:
                # Simple split
                indices = source_data.index.tolist()
                split_idx = int(len(indices) * (train_size / (train_size + test_size)))

                train_samples.append(source_data.iloc[:split_idx])
                test_samples.append(source_data.iloc[split_idx : split_idx + test_size])

        train_df = pd.concat(train_samples, ignore_index=True).sample(
            frac=1, random_state=42
        ).reset_index(drop=True)
        test_df = pd.concat(test_samples, ignore_index=True).sample(
            frac=1, random_state=42
        ).reset_index(drop=True)

        logger.info(f"Train set: {len(train_df)} samples")
        logger.info(f"Test set: {len(test_df)} samples")

        return train_df, test_df
