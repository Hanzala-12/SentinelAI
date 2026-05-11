"""
Sklearn-based ML models for phishing detection.

This module provides:
- Model training with proper train/test splits
- Multiple model types (baseline, production)
- Probability predictions for threshold tuning
- Reproducible random states
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class PhishingMLModel:
    """Base class for phishing ML models."""

    def __init__(self, random_state: int = 42) -> None:
        """Initialize model with reproducible random state."""
        self.random_state = random_state
        self.model: Any = None
        self.scaler: StandardScaler | None = None
        self.feature_names: list[str] = []
        self.is_fitted = False

    def fit(self, X_train: pd.DataFrame, y_train: pd.Series) -> None:
        """Fit model on training data."""
        raise NotImplementedError

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Get binary predictions (0 or 1)."""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet. Call fit() first.")
        return self.model.predict(X)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Get probability predictions for positive class."""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet. Call fit() first.")
        # Returns [P(class=0), P(class=1)] - we want P(class=1)
        return self.model.predict_proba(X)[:, 1]

    def evaluate(self, X_test: pd.DataFrame, y_test: pd.Series) -> dict[str, float]:
        """Compute evaluation metrics."""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet. Call fit() first.")

        y_pred = self.predict(X_test)
        y_proba = self.predict_proba(X_test)

        metrics = {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision": float(precision_score(y_test, y_pred, zero_division=0)),
            "recall": float(recall_score(y_test, y_pred, zero_division=0)),
            "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
            "auc_roc": float(roc_auc_score(y_test, y_proba)),
        }

        # Confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        metrics["tp"] = int(tp)
        metrics["fp"] = int(fp)
        metrics["tn"] = int(tn)
        metrics["fn"] = int(fn)

        # False positive/negative rates
        metrics["fpr"] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        metrics["fnr"] = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        return metrics


class BaselineLogisticRegression(PhishingMLModel):
    """Logistic Regression baseline model."""

    def __init__(self, random_state: int = 42) -> None:
        super().__init__(random_state)
        self.model = LogisticRegression(random_state=random_state, max_iter=1000)
        self.scaler = StandardScaler()

    def fit(self, X_train: pd.DataFrame, y_train: pd.Series) -> None:
        """Fit model on training data."""
        self.feature_names = list(X_train.columns)

        # Scale features
        X_scaled = self.scaler.fit_transform(X_train)

        # Train model
        self.model.fit(X_scaled, y_train)
        self.is_fitted = True

        logger.info(f"Fitted {self.__class__.__name__} with {len(self.feature_names)} features")

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Get binary predictions."""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet. Call fit() first.")
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Get probability predictions."""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet. Call fit() first.")
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)[:, 1]


class ProductionRandomForest(PhishingMLModel):
    """Random Forest model for production use."""

    def __init__(self, n_estimators: int = 100, random_state: int = 42) -> None:
        super().__init__(random_state)
        self.n_estimators = n_estimators
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=random_state,
            n_jobs=-1,
        )

    def fit(self, X_train: pd.DataFrame, y_train: pd.Series) -> None:
        """Fit model on training data."""
        self.feature_names = list(X_train.columns)

        # Train model (Random Forest handles scaling internally)
        self.model.fit(X_train, y_train)
        self.is_fitted = True

        logger.info(f"Fitted {self.__class__.__name__} with {len(self.feature_names)} features")

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Get binary predictions."""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet. Call fit() first.")
        return self.model.predict(X)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Get probability predictions."""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet. Call fit() first.")
        return self.model.predict_proba(X)[:, 1]

    def get_feature_importance(self) -> pd.DataFrame:
        """Get feature importance scores."""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet. Call fit() first.")

        importance_df = pd.DataFrame({
            "feature": self.feature_names,
            "importance": self.model.feature_importances_,
        }).sort_values("importance", ascending=False)

        return importance_df


class MLPipeline:
    """Complete ML pipeline: load data -> extract features -> train -> evaluate."""

    def __init__(
        self,
        model_type: str = "random_forest",
        test_size: float = 0.25,
        random_state: int = 42,
    ) -> None:
        """
        Initialize ML pipeline.

        Args:
            model_type: 'logistic_regression' or 'random_forest'
            test_size: Fraction of data for testing (default 25%)
            random_state: Seed for reproducibility
        """
        self.model_type = model_type
        self.test_size = test_size
        self.random_state = random_state

        # Create model
        if model_type == "logistic_regression":
            self.model = BaselineLogisticRegression(random_state=random_state)
        elif model_type == "random_forest":
            self.model = ProductionRandomForest(random_state=random_state)
        else:
            raise ValueError(f"Unknown model type: {model_type}")

        self.X_train: pd.DataFrame | None = None
        self.X_test: pd.DataFrame | None = None
        self.y_train: pd.Series | None = None
        self.y_test: pd.Series | None = None

    def prepare_data(
        self,
        features_df: pd.DataFrame,
        label_column: str = "label",
    ) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
        """
        Split data into train/test sets.

        Args:
            features_df: DataFrame with features and label column
            label_column: Name of label column

        Returns:
            Tuple of (X_train, X_test, y_train, y_test)
        """
        if label_column not in features_df.columns:
            raise ValueError(f"Label column '{label_column}' not found in features")

        # Extract features and labels
        feature_cols = [col for col in features_df.columns if col not in ["url", "label"]]
        X = features_df[feature_cols]
        y = features_df[label_column]

        # Check class distribution
        logger.info(f"Class distribution: {y.value_counts().to_dict()}")

        # Split with stratification to preserve class balance
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X,
            y,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y,
        )

        logger.info(
            f"Train set: {len(self.X_train)} samples, "
            f"Test set: {len(self.X_test)} samples"
        )
        logger.info(f"Train class distribution: {self.y_train.value_counts().to_dict()}")
        logger.info(f"Test class distribution: {self.y_test.value_counts().to_dict()}")

        return self.X_train, self.X_test, self.y_train, self.y_test

    def train(self) -> None:
        """Train model on training set."""
        if self.X_train is None or self.y_train is None:
            raise ValueError("Call prepare_data() first")

        self.model.fit(self.X_train, self.y_train)

    def evaluate(self) -> dict[str, float]:
        """Evaluate model on test set."""
        if self.X_test is None or self.y_test is None:
            raise ValueError("Call prepare_data() first")

        metrics = self.model.evaluate(self.X_test, self.y_test)
        logger.info(f"Test set metrics: {metrics}")

        return metrics

    def predict_batch(self, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """Get predictions and probabilities for batch."""
        y_pred = self.model.predict(X)
        y_proba = self.model.predict_proba(X)
        return y_pred, y_proba

    def get_detailed_report(self) -> dict[str, Any]:
        """Get detailed evaluation report."""
        if self.X_test is None or self.y_test is None:
            raise ValueError("Call prepare_data() first")

        y_pred = self.model.predict(self.X_test)
        y_proba = self.model.predict_proba(self.X_test)

        report = {
            "model_type": self.model_type,
            "test_set_size": len(self.X_test),
            "metrics": self.model.evaluate(self.X_test, self.y_test),
            "classification_report": classification_report(self.y_test, y_pred, output_dict=True),
            "confusion_matrix": confusion_matrix(self.y_test, y_pred).tolist(),
        }

        # Feature importance (if available)
        if hasattr(self.model, "get_feature_importance"):
            importance_df = self.model.get_feature_importance()
            report["top_features"] = importance_df.head(10).to_dict("records")

        return report

    def threshold_sweep(
        self,
        thresholds: list[float] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Evaluate performance at different probability thresholds.

        Args:
            thresholds: List of probability thresholds (default: 0.1-0.9)

        Returns:
            List of metrics dicts for each threshold
        """
        if self.X_test is None or self.y_test is None:
            raise ValueError("Call prepare_data() first")

        if thresholds is None:
            thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

        y_proba = self.model.predict_proba(self.X_test)
        results = []

        for threshold in thresholds:
            y_pred = (y_proba >= threshold).astype(int)

            metrics = {
                "threshold": threshold,
                "accuracy": float(accuracy_score(self.y_test, y_pred)),
                "precision": float(precision_score(self.y_test, y_pred, zero_division=0)),
                "recall": float(recall_score(self.y_test, y_pred, zero_division=0)),
                "f1_score": float(f1_score(self.y_test, y_pred, zero_division=0)),
            }

            tn, fp, fn, tp = confusion_matrix(self.y_test, y_pred).ravel()
            metrics["tp"] = int(tp)
            metrics["fp"] = int(fp)
            metrics["tn"] = int(tn)
            metrics["fn"] = int(fn)

            results.append(metrics)

        return results
