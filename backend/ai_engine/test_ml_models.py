"""
Unit tests for ML data models.

Tests cover:
- MLFeaturePack validation and construction
- RiskAggregationResult validation
- DecisionResult validation
- ModelBundle validation and loading logic
"""

import json
import pickle
import tempfile
from pathlib import Path

import pytest

from backend.ai_engine.ml_models import (
    DecisionResult,
    LoadedModelBundle,
    MLFeaturePack,
    ModelBundle,
    RiskAggregationResult,
)


class TestMLFeaturePack:
    """Tests for MLFeaturePack data model."""
    
    def test_valid_feature_pack(self):
        """Test creating a valid MLFeaturePack."""
        features = [1.0] * 16
        feature_names = [f"feature_{i}" for i in range(16)]
        
        pack = MLFeaturePack(
            features=features,
            feature_names=feature_names,
            extraction_metadata={"source": "test"},
            extraction_time_ms=10.5
        )
        
        assert len(pack.features) == 16
        assert len(pack.feature_names) == 16
        assert pack.extraction_time_ms == 10.5
    
    def test_invalid_feature_count(self):
        """Test that MLFeaturePack rejects incorrect feature count."""
        with pytest.raises(ValueError, match="Expected 16 features"):
            MLFeaturePack(
                features=[1.0] * 10,  # Wrong count
                feature_names=[f"feature_{i}" for i in range(16)],
                extraction_metadata={},
                extraction_time_ms=10.0
            )
    
    def test_invalid_feature_names_count(self):
        """Test that MLFeaturePack rejects incorrect feature names count."""
        with pytest.raises(ValueError, match="Expected 16 feature names"):
            MLFeaturePack(
                features=[1.0] * 16,
                feature_names=[f"feature_{i}" for i in range(10)],  # Wrong count
                extraction_metadata={},
                extraction_time_ms=10.0
            )


class TestRiskAggregationResult:
    """Tests for RiskAggregationResult data model."""
    
    def test_valid_risk_aggregation(self):
        """Test creating a valid RiskAggregationResult."""
        result = RiskAggregationResult(
            final_score=75,
            component_contributions={"ml": 60.0, "heuristic": 10.0, "threat_intel": 5.0},
            confidence=0.85,
            aggregation_metadata={"method": "weighted_sum"}
        )
        
        assert result.final_score == 75
        assert 0 <= result.final_score <= 100
        assert 0.0 <= result.confidence <= 1.0
    
    def test_invalid_final_score_too_high(self):
        """Test that RiskAggregationResult rejects scores > 100."""
        with pytest.raises(ValueError, match="final_score must be in"):
            RiskAggregationResult(
                final_score=150,
                component_contributions={},
                confidence=0.5,
                aggregation_metadata={}
            )
    
    def test_invalid_final_score_negative(self):
        """Test that RiskAggregationResult rejects negative scores."""
        with pytest.raises(ValueError, match="final_score must be in"):
            RiskAggregationResult(
                final_score=-10,
                component_contributions={},
                confidence=0.5,
                aggregation_metadata={}
            )
    
    def test_invalid_confidence_too_high(self):
        """Test that RiskAggregationResult rejects confidence > 1.0."""
        with pytest.raises(ValueError, match="confidence must be in"):
            RiskAggregationResult(
                final_score=50,
                component_contributions={},
                confidence=1.5,
                aggregation_metadata={}
            )
    
    def test_invalid_confidence_negative(self):
        """Test that RiskAggregationResult rejects negative confidence."""
        with pytest.raises(ValueError, match="confidence must be in"):
            RiskAggregationResult(
                final_score=50,
                component_contributions={},
                confidence=-0.1,
                aggregation_metadata={}
            )


class TestDecisionResult:
    """Tests for DecisionResult data model."""
    
    def test_valid_decision_safe(self):
        """Test creating a valid SAFE DecisionResult."""
        result = DecisionResult(
            classification="SAFE",
            threshold_used=25,
            confidence=0.95,
            decision_metadata={"reason": "low_risk_score"}
        )
        
        assert result.classification == "SAFE"
        assert result.threshold_used == 25
        assert 0.0 <= result.confidence <= 1.0
    
    def test_valid_decision_suspicious(self):
        """Test creating a valid SUSPICIOUS DecisionResult."""
        result = DecisionResult(
            classification="SUSPICIOUS",
            threshold_used=50,
            confidence=0.70,
            decision_metadata={}
        )
        
        assert result.classification == "SUSPICIOUS"
    
    def test_valid_decision_phishing(self):
        """Test creating a valid PHISHING DecisionResult."""
        result = DecisionResult(
            classification="PHISHING",
            threshold_used=50,
            confidence=0.90,
            decision_metadata={}
        )
        
        assert result.classification == "PHISHING"
    
    def test_invalid_classification(self):
        """Test that DecisionResult rejects invalid classification labels."""
        with pytest.raises(ValueError, match="classification must be one of"):
            DecisionResult(
                classification="UNKNOWN",
                threshold_used=50,
                confidence=0.5,
                decision_metadata={}
            )
    
    def test_invalid_confidence(self):
        """Test that DecisionResult rejects invalid confidence values."""
        with pytest.raises(ValueError, match="confidence must be in"):
            DecisionResult(
                classification="SAFE",
                threshold_used=25,
                confidence=2.0,
                decision_metadata={}
            )


class TestModelBundle:
    """Tests for ModelBundle data model."""
    
    def test_validate_missing_files(self):
        """Test that validate() returns False when files are missing."""
        bundle = ModelBundle(
            model_version="test_v1",
            model_path=Path("/nonexistent/model.pkl"),
            scaler_path=Path("/nonexistent/scaler.pkl"),
            calibrator_path=Path("/nonexistent/calibrator.pkl"),
            feature_schema_path=Path("/nonexistent/schema.json"),
            metadata_path=Path("/nonexistent/metadata.json")
        )
        
        assert bundle.validate() is False
    
    def test_validate_with_existing_files(self):
        """Test that validate() returns True when all files exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create dummy files
            model_path = tmpdir_path / "model.pkl"
            scaler_path = tmpdir_path / "scaler.pkl"
            calibrator_path = tmpdir_path / "calibrator.pkl"
            schema_path = tmpdir_path / "schema.json"
            metadata_path = tmpdir_path / "metadata.json"
            
            for path in [model_path, scaler_path, calibrator_path]:
                with open(path, 'wb') as f:
                    pickle.dump({"dummy": "data"}, f)
            
            for path in [schema_path, metadata_path]:
                with open(path, 'w') as f:
                    json.dump({"dummy": "data"}, f)
            
            bundle = ModelBundle(
                model_version="test_v1",
                model_path=model_path,
                scaler_path=scaler_path,
                calibrator_path=calibrator_path,
                feature_schema_path=schema_path,
                metadata_path=metadata_path
            )
            
            assert bundle.validate() is True
    
    def test_load_artifacts(self):
        """Test loading model artifacts from disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create dummy artifacts
            model_data = {"type": "model", "params": [1, 2, 3]}
            scaler_data = {"type": "scaler", "mean": 0.5}
            calibrator_data = {"type": "calibrator", "coeffs": [0.1, 0.2]}
            schema_data = {"features": ["f1", "f2"], "version": "1.0"}
            metadata_data = {"model_version": "test_v1", "training_date": "2024-01-01"}
            
            model_path = tmpdir_path / "model.pkl"
            scaler_path = tmpdir_path / "scaler.pkl"
            calibrator_path = tmpdir_path / "calibrator.pkl"
            schema_path = tmpdir_path / "schema.json"
            metadata_path = tmpdir_path / "metadata.json"
            
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
            with open(scaler_path, 'wb') as f:
                pickle.dump(scaler_data, f)
            with open(calibrator_path, 'wb') as f:
                pickle.dump(calibrator_data, f)
            with open(schema_path, 'w') as f:
                json.dump(schema_data, f)
            with open(metadata_path, 'w') as f:
                json.dump(metadata_data, f)
            
            bundle = ModelBundle(
                model_version="test_v1",
                model_path=model_path,
                scaler_path=scaler_path,
                calibrator_path=calibrator_path,
                feature_schema_path=schema_path,
                metadata_path=metadata_path
            )
            
            loaded = bundle.load()
            
            assert isinstance(loaded, LoadedModelBundle)
            assert loaded.model == model_data
            assert loaded.scaler == scaler_data
            assert loaded.calibrator == calibrator_data
            assert loaded.feature_schema == schema_data
            assert loaded.metadata == metadata_data
    
    def test_load_missing_file_raises_error(self):
        """Test that load() raises FileNotFoundError for missing files."""
        bundle = ModelBundle(
            model_version="test_v1",
            model_path=Path("/nonexistent/model.pkl"),
            scaler_path=Path("/nonexistent/scaler.pkl"),
            calibrator_path=Path("/nonexistent/calibrator.pkl"),
            feature_schema_path=Path("/nonexistent/schema.json"),
            metadata_path=Path("/nonexistent/metadata.json")
        )
        
        with pytest.raises(FileNotFoundError):
            bundle.load()
