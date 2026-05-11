"""
Data models for ML-First Unified Detection System.

This module defines the core data structures used throughout the ML inference pipeline:
- MLFeaturePack: Container for extracted features
- RiskAggregationResult: Result of combining ML, heuristic, and threat intel signals
- DecisionResult: Final classification decision
- ModelBundle: Container for ML model artifacts
- LoadedModelBundle: In-memory representation of loaded model artifacts

These models support the ML-first architecture where machine learning serves as the
primary decision engine with offline-safe feature extraction.
"""

import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class MLFeaturePack:
    """Container for ML features extracted from a URL.
    
    Attributes:
        features: List of 16 numerical feature values
        feature_names: List of 16 feature names corresponding to feature values
        extraction_metadata: Additional metadata about feature extraction (e.g., errors, warnings)
        extraction_time_ms: Time taken to extract features in milliseconds
    
    **Validates: Requirements 6.1, 6.2**
    """
    features: list[float]  # 16 elements
    feature_names: list[str]  # 16 elements
    extraction_metadata: dict[str, Any]
    extraction_time_ms: float
    
    def __post_init__(self):
        """Validate feature pack dimensions."""
        if len(self.features) != 16:
            raise ValueError(f"Expected 16 features, got {len(self.features)}")
        if len(self.feature_names) != 16:
            raise ValueError(f"Expected 16 feature names, got {len(self.feature_names)}")


@dataclass
class RiskAggregationResult:
    """Result of aggregating ML probability with heuristic and threat intel signals.
    
    Attributes:
        final_score: Final risk score in range [0, 100]
        component_contributions: Breakdown of score contributions by component
            Example: {'ml': 72.0, 'heuristic': 12.0, 'threat_intel': 4.0}
        confidence: Confidence in the aggregated score in range [0, 1]
        aggregation_metadata: Additional metadata about the aggregation process
    
    **Validates: Requirements 15.1-15.5**
    """
    final_score: int  # [0, 100]
    component_contributions: dict[str, float]  # {'ml': 72.0, 'heuristic': 12.0, 'threat_intel': 4.0}
    confidence: float  # [0, 1]
    aggregation_metadata: dict[str, Any]
    
    def __post_init__(self):
        """Validate risk aggregation result."""
        if not 0 <= self.final_score <= 100:
            raise ValueError(f"final_score must be in [0, 100], got {self.final_score}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")


@dataclass
class DecisionResult:
    """Final classification decision based on risk score.
    
    Attributes:
        classification: Classification label ('SAFE', 'SUSPICIOUS', 'PHISHING')
        threshold_used: The risk score threshold that determined this classification
        confidence: Confidence in the decision in range [0, 1]
        decision_metadata: Additional metadata about the decision process
    
    **Validates: Requirements 15.1-15.5**
    """
    classification: str  # 'SAFE', 'SUSPICIOUS', 'PHISHING'
    threshold_used: int
    confidence: float
    decision_metadata: dict[str, Any]
    
    def __post_init__(self):
        """Validate decision result."""
        valid_classifications = {'SAFE', 'SUSPICIOUS', 'PHISHING'}
        if self.classification not in valid_classifications:
            raise ValueError(
                f"classification must be one of {valid_classifications}, got {self.classification}"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")


@dataclass
class LoadedModelBundle:
    """In-memory representation of loaded ML model artifacts.
    
    Attributes:
        model: The trained ML classifier (sklearn or xgboost model)
        scaler: The fitted feature scaler
        calibrator: The fitted probability calibrator
        feature_schema: Feature schema dictionary containing feature names and metadata
        metadata: Model metadata including version, training date, hyperparameters
    """
    model: Any  # sklearn or xgboost model
    scaler: Any  # sklearn scaler
    calibrator: Any  # sklearn calibrator
    feature_schema: dict[str, Any]
    metadata: dict[str, Any]


@dataclass
class ModelBundle:
    """Container for ML model artifact paths and loading logic.
    
    This class represents a versioned bundle of ML artifacts including the trained model,
    feature scaler, probability calibrator, feature schema, and metadata. It provides
    methods to load artifacts into memory and validate bundle integrity.
    
    Attributes:
        model_version: Version identifier (e.g., 'ml_first_v1')
        model_path: Path to the trained model pickle file
        scaler_path: Path to the feature scaler pickle file
        calibrator_path: Path to the probability calibrator pickle file
        feature_schema_path: Path to the feature schema JSON file
        metadata_path: Path to the model metadata JSON file
    
    **Validates: Requirements 6.1, 6.2, 15.1-15.5**
    """
    model_version: str  # 'ml_first_v1'
    model_path: Path
    scaler_path: Path
    calibrator_path: Path
    feature_schema_path: Path
    metadata_path: Path
    
    def load(self) -> LoadedModelBundle:
        """Load all artifacts into memory.
        
        Returns:
            LoadedModelBundle containing all loaded artifacts
            
        Raises:
            FileNotFoundError: If any required artifact file is missing
            pickle.UnpicklingError: If pickle files are corrupted
            json.JSONDecodeError: If JSON files are malformed
        """
        import json
        
        # Load pickle artifacts
        with open(self.model_path, 'rb') as f:
            model = pickle.load(f)
        
        with open(self.scaler_path, 'rb') as f:
            scaler = pickle.load(f)
        
        with open(self.calibrator_path, 'rb') as f:
            calibrator = pickle.load(f)
        
        # Load JSON artifacts
        with open(self.feature_schema_path, 'r') as f:
            feature_schema = json.load(f)
        
        with open(self.metadata_path, 'r') as f:
            metadata = json.load(f)
        
        return LoadedModelBundle(
            model=model,
            scaler=scaler,
            calibrator=calibrator,
            feature_schema=feature_schema,
            metadata=metadata
        )
    
    def validate(self) -> bool:
        """Validate bundle integrity.
        
        Checks that all required artifact files exist and are readable.
        
        Returns:
            True if all artifacts exist and are valid, False otherwise
        """
        required_paths = [
            self.model_path,
            self.scaler_path,
            self.calibrator_path,
            self.feature_schema_path,
            self.metadata_path
        ]
        
        for path in required_paths:
            if not path.exists():
                return False
            if not path.is_file():
                return False
        
        return True
