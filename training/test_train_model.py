"""
Unit tests for model training module.

**Validates: Requirements 12.1-12.8, 19.1-19.7**
"""

import json
import pickle
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from training.data_pipeline import PreparedDataset, DatasetStatistics
from training.train_model import ModelTrainer, TrainingResult, ModelArtifacts


@pytest.fixture
def mock_dataset():
    """Create a mock PreparedDataset for testing."""
    # Create small synthetic dataset
    n_train = 100
    n_val = 20
    n_test = 20
    
    # Training data
    X_train = pd.DataFrame({
        'url': [f'http://example{i}.com/path' for i in range(n_train)]
    })
    y_train = pd.Series([i % 2 for i in range(n_train)])  # Alternating 0/1
    
    # Validation data
    X_validation = pd.DataFrame({
        'url': [f'http://validation{i}.com/path' for i in range(n_val)]
    })
    y_validation = pd.Series([i % 2 for i in range(n_val)])
    
    # Test data
    X_test = pd.DataFrame({
        'url': [f'http://test{i}.com/path' for i in range(n_test)]
    })
    y_test = pd.Series([i % 2 for i in range(n_test)])
    
    # Statistics
    statistics = DatasetStatistics(
        total_samples=n_train + n_val + n_test,
        phishing_count=70,
        benign_count=70,
        class_distribution={'phishing': 0.5, 'benign': 0.5},
        feature_distributions={},
        missing_value_counts={},
        train_size=n_train,
        validation_size=n_val,
        test_size=n_test,
        train_phishing_ratio=0.5,
        validation_phishing_ratio=0.5,
        test_phishing_ratio=0.5,
        unique_domains=140,
        filtered_malformed=0,
        duplicates_removed=0
    )
    
    return PreparedDataset(
        X_train=X_train,
        y_train=y_train,
        X_validation=X_validation,
        y_validation=y_validation,
        X_test=X_test,
        y_test=y_test,
        statistics=statistics,
        metadata={}
    )


class TestModelTrainer:
    """Test suite for ModelTrainer class."""
    
    def test_initialization(self):
        """Test ModelTrainer initialization."""
        trainer = ModelTrainer(
            random_state=42,
            n_jobs=1,
            cv_folds=3,
            n_iter=5,
            verbose=0
        )
        
        assert trainer.random_state == 42
        assert trainer.n_jobs == 1
        assert trainer.cv_folds == 3
        assert trainer.n_iter == 5
        assert trainer.verbose == 0
        assert trainer.feature_engine is not None
    
    def test_extract_features(self, mock_dataset):
        """Test feature extraction from URL DataFrame."""
        trainer = ModelTrainer(random_state=42, n_jobs=1, verbose=0)
        
        X_features, feature_names = trainer._extract_features(mock_dataset.X_train)
        
        # Check shape
        assert X_features.shape[0] == len(mock_dataset.X_train)
        assert X_features.shape[1] == 16  # 16 features
        
        # Check feature names
        assert len(feature_names) == 16
        assert 'url_length' in feature_names
        assert 'character_entropy' in feature_names
        
        # Check feature values are numeric
        assert np.isfinite(X_features).all()
    
    @pytest.mark.slow
    def test_train_random_forest(self, mock_dataset):
        """Test Random Forest training with hyperparameter search.
        
        **Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.8**
        """
        trainer = ModelTrainer(
            random_state=42,
            n_jobs=1,
            cv_folds=2,  # Small for testing
            n_iter=2,    # Small for testing
            verbose=0
        )
        
        # Extract and scale features
        X_train_features, feature_names = trainer._extract_features(mock_dataset.X_train)
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train_features)
        
        # Train Random Forest
        rf_artifacts = trainer._train_random_forest(
            X_train_scaled,
            mock_dataset.y_train,
            scaler,
            feature_names
        )
        
        # Check artifacts
        assert isinstance(rf_artifacts, ModelArtifacts)
        assert isinstance(rf_artifacts.model, RandomForestClassifier)
        assert rf_artifacts.scaler is scaler
        assert rf_artifacts.feature_names == feature_names
        
        # Check training result
        result = rf_artifacts.training_result
        assert result.model_name == 'random_forest'
        assert 0.0 <= result.best_score <= 1.0
        assert len(result.cv_scores) == 2  # cv_folds=2
        assert result.mean_cv_score > 0.0
        assert result.training_time_seconds > 0.0
        
        # Check metadata
        assert rf_artifacts.metadata['model_type'] == 'RandomForestClassifier'
        assert 'n_estimators' in rf_artifacts.metadata
        assert 'max_depth' in rf_artifacts.metadata
    
    @pytest.mark.slow
    def test_train_xgboost(self, mock_dataset):
        """Test XGBoost training with hyperparameter search.
        
        **Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.8**
        """
        trainer = ModelTrainer(
            random_state=42,
            n_jobs=1,
            cv_folds=2,  # Small for testing
            n_iter=2,    # Small for testing
            verbose=0
        )
        
        # Extract and scale features
        X_train_features, feature_names = trainer._extract_features(mock_dataset.X_train)
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train_features)
        
        # Train XGBoost
        xgb_artifacts = trainer._train_xgboost(
            X_train_scaled,
            mock_dataset.y_train,
            scaler,
            feature_names
        )
        
        # Check artifacts
        assert isinstance(xgb_artifacts, ModelArtifacts)
        assert isinstance(xgb_artifacts.model, XGBClassifier)
        assert xgb_artifacts.scaler is scaler
        assert xgb_artifacts.feature_names == feature_names
        
        # Check training result
        result = xgb_artifacts.training_result
        assert result.model_name == 'xgboost'
        assert 0.0 <= result.best_score <= 1.0
        assert len(result.cv_scores) == 2  # cv_folds=2
        assert result.mean_cv_score > 0.0
        assert result.training_time_seconds > 0.0
        
        # Check metadata
        assert xgb_artifacts.metadata['model_type'] == 'XGBClassifier'
        assert 'n_estimators' in xgb_artifacts.metadata
        assert 'learning_rate' in xgb_artifacts.metadata
    
    def test_select_best_model(self):
        """Test best model selection based on mean PR-AUC.
        
        **Validates: Requirement 12.6**
        """
        trainer = ModelTrainer(random_state=42, n_jobs=1, verbose=0)
        
        # Create mock model artifacts
        rf_result = TrainingResult(
            model_name='random_forest',
            best_params={},
            best_score=0.85,
            cv_scores=[0.84, 0.86],
            mean_cv_score=0.85,
            std_cv_score=0.01,
            training_time_seconds=10.0,
            n_cv_folds=2
        )
        
        xgb_result = TrainingResult(
            model_name='xgboost',
            best_params={},
            best_score=0.90,
            cv_scores=[0.89, 0.91],
            mean_cv_score=0.90,
            std_cv_score=0.01,
            training_time_seconds=15.0,
            n_cv_folds=2
        )
        
        rf_artifacts = ModelArtifacts(
            model=MagicMock(),
            scaler=MagicMock(),
            feature_names=[],
            training_result=rf_result,
            metadata={}
        )
        
        xgb_artifacts = ModelArtifacts(
            model=MagicMock(),
            scaler=MagicMock(),
            feature_names=[],
            training_result=xgb_result,
            metadata={}
        )
        
        model_artifacts = {
            'random_forest': rf_artifacts,
            'xgboost': xgb_artifacts
        }
        
        # Select best model
        best_name, best_artifacts = trainer.select_best_model(model_artifacts)
        
        # XGBoost should be selected (higher mean PR-AUC)
        assert best_name == 'xgboost'
        assert best_artifacts is xgb_artifacts
    
    def test_retrain_on_full_data(self, mock_dataset):
        """Test retraining on combined train+validation set.
        
        **Validates: Requirement 12.7**
        """
        trainer = ModelTrainer(random_state=42, n_jobs=1, verbose=0)
        
        # Create mock model artifacts
        mock_model = RandomForestClassifier(n_estimators=10, random_state=42)
        mock_scaler = MagicMock()
        
        training_result = TrainingResult(
            model_name='random_forest',
            best_params={'n_estimators': 10, 'max_depth': 5},
            best_score=0.85,
            cv_scores=[0.84, 0.86],
            mean_cv_score=0.85,
            std_cv_score=0.01,
            training_time_seconds=10.0,
            n_cv_folds=2
        )
        
        original_artifacts = ModelArtifacts(
            model=mock_model,
            scaler=mock_scaler,
            feature_names=['f1', 'f2'],
            training_result=training_result,
            metadata={'original': True}
        )
        
        # Retrain on full data
        retrained_artifacts = trainer.retrain_on_full_data(
            mock_dataset,
            original_artifacts
        )
        
        # Check that model was retrained
        assert isinstance(retrained_artifacts.model, RandomForestClassifier)
        assert retrained_artifacts.training_result is training_result
        assert retrained_artifacts.metadata['retrained_on_full_data'] is True
        assert 'full_training_samples' in retrained_artifacts.metadata
        assert 'full_training_time_seconds' in retrained_artifacts.metadata
    
    def test_save_model_artifacts(self):
        """Test saving model artifacts to disk.
        
        **Validates: Requirements 12.7, 15.1-15.5**
        """
        trainer = ModelTrainer(random_state=42, n_jobs=1, verbose=0)
        
        # Create mock model artifacts
        mock_model = RandomForestClassifier(n_estimators=10, random_state=42)
        from sklearn.preprocessing import StandardScaler
        mock_scaler = StandardScaler()
        
        training_result = TrainingResult(
            model_name='random_forest',
            best_params={'n_estimators': 10},
            best_score=0.85,
            cv_scores=[0.84, 0.86],
            mean_cv_score=0.85,
            std_cv_score=0.01,
            training_time_seconds=10.0,
            n_cv_folds=2
        )
        
        artifacts = ModelArtifacts(
            model=mock_model,
            scaler=mock_scaler,
            feature_names=['f1', 'f2', 'f3'],
            training_result=training_result,
            metadata={'test': True}
        )
        
        # Save to temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / 'test_model'
            trainer.save_model_artifacts(artifacts, 'random_forest', output_dir)
            
            # Check that all files were created
            assert (output_dir / 'model.pkl').exists()
            assert (output_dir / 'scaler.pkl').exists()
            assert (output_dir / 'feature_schema.json').exists()
            assert (output_dir / 'metadata.json').exists()
            
            # Check model.pkl
            with open(output_dir / 'model.pkl', 'rb') as f:
                loaded_model = pickle.load(f)
            assert isinstance(loaded_model, RandomForestClassifier)
            
            # Check scaler.pkl
            with open(output_dir / 'scaler.pkl', 'rb') as f:
                loaded_scaler = pickle.load(f)
            assert isinstance(loaded_scaler, StandardScaler)
            
            # Check feature_schema.json
            with open(output_dir / 'feature_schema.json', 'r') as f:
                feature_schema = json.load(f)
            assert feature_schema['feature_names'] == ['f1', 'f2', 'f3']
            assert feature_schema['n_features'] == 3
            assert 'feature_extraction_version' in feature_schema
            
            # Check metadata.json
            with open(output_dir / 'metadata.json', 'r') as f:
                metadata = json.load(f)
            assert metadata['model_version'] == 'ml_first_v1'
            assert metadata['model_name'] == 'random_forest'
            assert metadata['best_score'] == 0.85
            assert metadata['mean_cv_score'] == 0.85
            assert 'training_date' in metadata


class TestTrainingResult:
    """Test suite for TrainingResult dataclass."""
    
    def test_training_result_creation(self):
        """Test TrainingResult creation."""
        result = TrainingResult(
            model_name='random_forest',
            best_params={'n_estimators': 100},
            best_score=0.85,
            cv_scores=[0.84, 0.85, 0.86],
            mean_cv_score=0.85,
            std_cv_score=0.01,
            training_time_seconds=120.5,
            n_cv_folds=3
        )
        
        assert result.model_name == 'random_forest'
        assert result.best_params == {'n_estimators': 100}
        assert result.best_score == 0.85
        assert len(result.cv_scores) == 3
        assert result.mean_cv_score == 0.85
        assert result.std_cv_score == 0.01
        assert result.training_time_seconds == 120.5
        assert result.n_cv_folds == 3


class TestModelArtifacts:
    """Test suite for ModelArtifacts dataclass."""
    
    def test_model_artifacts_creation(self):
        """Test ModelArtifacts creation."""
        mock_model = MagicMock()
        mock_scaler = MagicMock()
        
        training_result = TrainingResult(
            model_name='xgboost',
            best_params={},
            best_score=0.90,
            cv_scores=[0.89, 0.91],
            mean_cv_score=0.90,
            std_cv_score=0.01,
            training_time_seconds=100.0,
            n_cv_folds=2
        )
        
        artifacts = ModelArtifacts(
            model=mock_model,
            scaler=mock_scaler,
            feature_names=['f1', 'f2'],
            training_result=training_result,
            metadata={'key': 'value'}
        )
        
        assert artifacts.model is mock_model
        assert artifacts.scaler is mock_scaler
        assert artifacts.feature_names == ['f1', 'f2']
        assert artifacts.training_result is training_result
        assert artifacts.metadata == {'key': 'value'}
