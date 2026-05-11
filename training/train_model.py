"""
Model Training for ML-First Unified Detection System.

This module implements the model training component that:
1. Loads prepared dataset from DataPipeline
2. Extracts features using MLFeatureEngine
3. Trains Random Forest and XGBoost with hyperparameter search
4. Uses 5-fold stratified cross-validation
5. Selects best model based on mean PR-AUC
6. Retrains on train+validation set
7. Saves model artifacts to backend/models/url/ml_first_v1/

**Validates: Requirements 12.1-12.8**
"""

import json
import logging
import pickle
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from backend.ai_engine.ml_feature_engine import MLFeatureEngine
from training.data_pipeline import DataPipeline, PreparedDataset

logger = logging.getLogger(__name__)


@dataclass
class TrainingResult:
    """Result of model training process.
    
    **Validates: Requirement 12.8**
    """
    model_name: str
    best_params: dict[str, Any]
    best_score: float
    cv_scores: list[float]
    mean_cv_score: float
    std_cv_score: float
    training_time_seconds: float
    n_cv_folds: int


@dataclass
class ModelArtifacts:
    """Container for trained model artifacts.
    
    **Validates: Requirements 12.7, 15.1-15.5**
    """
    model: Any  # Trained classifier
    scaler: StandardScaler
    feature_names: list[str]
    training_result: TrainingResult
    metadata: dict[str, Any]


class ModelTrainer:
    """Train and evaluate ML models for phishing detection.
    
    This class implements the model training pipeline that:
    1. Extracts features from URLs using MLFeatureEngine
    2. Scales features using StandardScaler
    3. Performs hyperparameter search with cross-validation
    4. Selects best model based on PR-AUC
    5. Retrains on combined train+validation set
    6. Saves model artifacts
    
    **Validates: Requirements 12.1-12.8**
    """
    
    # Hyperparameter search spaces
    RF_PARAM_GRID = {
        'n_estimators': [100, 200, 300],
        'max_depth': [10, 20, 30, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
        'max_features': ['sqrt', 'log2', None],
        'class_weight': ['balanced', 'balanced_subsample']
    }
    
    XGB_PARAM_GRID = {
        'n_estimators': [100, 200, 300],
        'max_depth': [6, 10, 15],
        'learning_rate': [0.01, 0.05, 0.1],
        'subsample': [0.8, 0.9, 1.0],
        'colsample_bytree': [0.8, 0.9, 1.0],
        'scale_pos_weight': [1, 5, 10]
    }
    
    def __init__(
        self,
        random_state: int = 42,
        n_jobs: int = -1,
        cv_folds: int = 5,
        n_iter: int = 50,
        verbose: int = 1
    ):
        """Initialize model trainer.
        
        Args:
            random_state: Random seed for reproducibility
            n_jobs: Number of parallel jobs (-1 = use all cores)
            cv_folds: Number of cross-validation folds
            n_iter: Number of iterations for random search
            verbose: Verbosity level
            
        **Validates: Requirements 12.4, 12.5**
        """
        self.random_state = random_state
        self.n_jobs = n_jobs
        self.cv_folds = cv_folds
        self.n_iter = n_iter
        self.verbose = verbose
        self.feature_engine = MLFeatureEngine()
    
    def train_models(self, dataset: PreparedDataset) -> dict[str, ModelArtifacts]:
        """Train Random Forest and XGBoost models with hyperparameter search.
        
        Args:
            dataset: PreparedDataset from DataPipeline
            
        Returns:
            Dictionary mapping model names to ModelArtifacts
            
        **Validates: Requirements 12.1, 12.2**
        """
        logger.info("Starting model training pipeline...")
        
        # Step 1: Extract features from training data
        logger.info("Extracting features from training data...")
        X_train_features, feature_names = self._extract_features(dataset.X_train)
        logger.info(f"Extracted {X_train_features.shape[1]} features from {X_train_features.shape[0]} training samples")
        
        # Step 2: Scale features
        logger.info("Scaling features...")
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train_features)
        
        # Step 3: Train Random Forest
        logger.info("=" * 80)
        logger.info("Training Random Forest...")
        logger.info("=" * 80)
        rf_artifacts = self._train_random_forest(
            X_train_scaled,
            dataset.y_train,
            scaler,
            feature_names
        )
        
        # Step 4: Train XGBoost
        logger.info("=" * 80)
        logger.info("Training XGBoost...")
        logger.info("=" * 80)
        xgb_artifacts = self._train_xgboost(
            X_train_scaled,
            dataset.y_train,
            scaler,
            feature_names
        )
        
        return {
            'random_forest': rf_artifacts,
            'xgboost': xgb_artifacts
        }
    
    def select_best_model(
        self,
        model_artifacts: dict[str, ModelArtifacts]
    ) -> tuple[str, ModelArtifacts]:
        """Select best model based on mean PR-AUC.
        
        Args:
            model_artifacts: Dictionary of trained model artifacts
            
        Returns:
            Tuple of (best_model_name, best_model_artifacts)
            
        **Validates: Requirement 12.6**
        """
        logger.info("=" * 80)
        logger.info("Selecting best model based on mean PR-AUC...")
        logger.info("=" * 80)
        
        best_model_name = None
        best_model_artifacts = None
        best_score = -1.0
        
        for model_name, artifacts in model_artifacts.items():
            mean_score = artifacts.training_result.mean_cv_score
            logger.info(
                f"{model_name}: mean PR-AUC = {mean_score:.4f} "
                f"(std = {artifacts.training_result.std_cv_score:.4f})"
            )
            
            if mean_score > best_score:
                best_score = mean_score
                best_model_name = model_name
                best_model_artifacts = artifacts
        
        logger.info("")
        logger.info(f"Selected model: {best_model_name} with mean PR-AUC = {best_score:.4f}")
        logger.info("=" * 80)
        
        return best_model_name, best_model_artifacts
    
    def retrain_on_full_data(
        self,
        dataset: PreparedDataset,
        model_artifacts: ModelArtifacts
    ) -> ModelArtifacts:
        """Retrain selected model on train+validation set.
        
        Args:
            dataset: PreparedDataset from DataPipeline
            model_artifacts: ModelArtifacts of selected model
            
        Returns:
            Updated ModelArtifacts with model retrained on full data
            
        **Validates: Requirement 12.7**
        """
        logger.info("=" * 80)
        logger.info("Retraining selected model on train+validation set...")
        logger.info("=" * 80)
        
        # Combine train and validation data
        X_combined = pd.concat([dataset.X_train, dataset.X_validation], ignore_index=True)
        y_combined = pd.concat([dataset.y_train, dataset.y_validation], ignore_index=True)
        
        logger.info(f"Combined dataset size: {len(X_combined)} samples")
        logger.info(f"  Phishing: {(y_combined == 1).sum()} ({(y_combined == 1).sum() / len(y_combined):.2%})")
        logger.info(f"  Benign: {(y_combined == 0).sum()} ({(y_combined == 0).sum() / len(y_combined):.2%})")
        
        # Extract and scale features
        X_combined_features, _ = self._extract_features(X_combined)
        
        # Refit scaler on combined data
        scaler = StandardScaler()
        X_combined_scaled = scaler.fit_transform(X_combined_features)
        
        # Retrain model with best hyperparameters
        start_time = time.time()
        model = model_artifacts.model.__class__(**model_artifacts.training_result.best_params)
        model.set_params(random_state=self.random_state, n_jobs=self.n_jobs)
        model.fit(X_combined_scaled, y_combined)
        training_time = time.time() - start_time
        
        logger.info(f"Retraining completed in {training_time:.2f} seconds")
        logger.info("=" * 80)
        
        # Update artifacts
        return ModelArtifacts(
            model=model,
            scaler=scaler,
            feature_names=model_artifacts.feature_names,
            training_result=model_artifacts.training_result,
            metadata={
                **model_artifacts.metadata,
                'retrained_on_full_data': True,
                'full_training_samples': len(X_combined),
                'full_training_time_seconds': training_time
            }
        )
    
    def save_model_artifacts(
        self,
        model_artifacts: ModelArtifacts,
        model_name: str,
        output_dir: Path
    ) -> None:
        """Save model artifacts to disk.
        
        Args:
            model_artifacts: ModelArtifacts to save
            model_name: Name of the model (e.g., 'random_forest', 'xgboost')
            output_dir: Output directory path
            
        **Validates: Requirements 12.7, 15.1-15.5**
        """
        logger.info("=" * 80)
        logger.info(f"Saving model artifacts to {output_dir}...")
        logger.info("=" * 80)
        
        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save model
        model_path = output_dir / 'model.pkl'
        with open(model_path, 'wb') as f:
            pickle.dump(model_artifacts.model, f)
        logger.info(f"Saved model to {model_path}")
        
        # Save scaler
        scaler_path = output_dir / 'scaler.pkl'
        with open(scaler_path, 'wb') as f:
            pickle.dump(model_artifacts.scaler, f)
        logger.info(f"Saved scaler to {scaler_path}")
        
        # Save feature schema
        feature_schema = {
            'feature_names': model_artifacts.feature_names,
            'n_features': len(model_artifacts.feature_names),
            'feature_extraction_version': '1.0'
        }
        feature_schema_path = output_dir / 'feature_schema.json'
        with open(feature_schema_path, 'w') as f:
            json.dump(feature_schema, f, indent=2)
        logger.info(f"Saved feature schema to {feature_schema_path}")
        
        # Save metadata
        metadata = {
            'model_version': 'ml_first_v1',
            'model_name': model_name,
            'training_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'best_params': model_artifacts.training_result.best_params,
            'best_score': model_artifacts.training_result.best_score,
            'mean_cv_score': model_artifacts.training_result.mean_cv_score,
            'std_cv_score': model_artifacts.training_result.std_cv_score,
            'cv_scores': model_artifacts.training_result.cv_scores,
            'training_time_seconds': model_artifacts.training_result.training_time_seconds,
            'n_cv_folds': model_artifacts.training_result.n_cv_folds,
            **model_artifacts.metadata
        }
        metadata_path = output_dir / 'metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"Saved metadata to {metadata_path}")
        
        logger.info("=" * 80)
        logger.info("Model artifacts saved successfully!")
        logger.info("=" * 80)
    
    def _extract_features(self, X: pd.DataFrame) -> tuple[np.ndarray, list[str]]:
        """Extract features from URL DataFrame.
        
        Args:
            X: DataFrame with 'url' column
            
        Returns:
            Tuple of (feature_matrix, feature_names)
        """
        features_list = []
        feature_names = None
        
        for url in X['url']:
            feature_pack = self.feature_engine.extract(url)
            features_list.append(feature_pack.features)
            
            if feature_names is None:
                feature_names = feature_pack.feature_names
        
        return np.array(features_list), feature_names
    
    def _train_random_forest(
        self,
        X_train: np.ndarray,
        y_train: pd.Series,
        scaler: StandardScaler,
        feature_names: list[str]
    ) -> ModelArtifacts:
        """Train Random Forest with hyperparameter search.
        
        Args:
            X_train: Scaled training features
            y_train: Training labels
            scaler: Fitted scaler
            feature_names: List of feature names
            
        Returns:
            ModelArtifacts for Random Forest
            
        **Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.8**
        """
        # Create base model
        rf = RandomForestClassifier(
            random_state=self.random_state,
            n_jobs=self.n_jobs,
            verbose=self.verbose
        )
        
        # Create cross-validation strategy
        cv = StratifiedKFold(
            n_splits=self.cv_folds,
            shuffle=True,
            random_state=self.random_state
        )
        
        # Perform random search
        logger.info(f"Performing random search with {self.n_iter} iterations...")
        logger.info(f"Using {self.cv_folds}-fold stratified cross-validation")
        logger.info(f"Optimization metric: Precision-Recall AUC")
        
        start_time = time.time()
        
        search = RandomizedSearchCV(
            estimator=rf,
            param_distributions=self.RF_PARAM_GRID,
            n_iter=self.n_iter,
            scoring='average_precision',  # PR-AUC
            cv=cv,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
            verbose=self.verbose,
            return_train_score=True
        )
        
        search.fit(X_train, y_train)
        
        training_time = time.time() - start_time
        
        # Extract results
        best_params = search.best_params_
        best_score = search.best_score_
        cv_results = search.cv_results_
        
        # Get cross-validation scores for best model
        best_index = search.best_index_
        cv_scores = []
        for fold_idx in range(self.cv_folds):
            score = cv_results[f'split{fold_idx}_test_score'][best_index]
            cv_scores.append(score)
        
        mean_cv_score = np.mean(cv_scores)
        std_cv_score = np.std(cv_scores)
        
        # Log results
        logger.info("")
        logger.info("Random Forest Training Results:")
        logger.info(f"  Best parameters: {best_params}")
        logger.info(f"  Best PR-AUC: {best_score:.4f}")
        logger.info(f"  Mean CV PR-AUC: {mean_cv_score:.4f} (±{std_cv_score:.4f})")
        logger.info(f"  CV scores: {[f'{s:.4f}' for s in cv_scores]}")
        logger.info(f"  Training time: {training_time:.2f} seconds")
        logger.info("")
        
        # Create training result
        training_result = TrainingResult(
            model_name='random_forest',
            best_params=best_params,
            best_score=best_score,
            cv_scores=cv_scores,
            mean_cv_score=mean_cv_score,
            std_cv_score=std_cv_score,
            training_time_seconds=training_time,
            n_cv_folds=self.cv_folds
        )
        
        # Create metadata
        metadata = {
            'model_type': 'RandomForestClassifier',
            'n_estimators': best_params['n_estimators'],
            'max_depth': best_params['max_depth'],
            'min_samples_split': best_params['min_samples_split'],
            'min_samples_leaf': best_params['min_samples_leaf'],
            'max_features': best_params['max_features'],
            'class_weight': best_params['class_weight']
        }
        
        return ModelArtifacts(
            model=search.best_estimator_,
            scaler=scaler,
            feature_names=feature_names,
            training_result=training_result,
            metadata=metadata
        )
    
    def _train_xgboost(
        self,
        X_train: np.ndarray,
        y_train: pd.Series,
        scaler: StandardScaler,
        feature_names: list[str]
    ) -> ModelArtifacts:
        """Train XGBoost with hyperparameter search.
        
        Args:
            X_train: Scaled training features
            y_train: Training labels
            scaler: Fitted scaler
            feature_names: List of feature names
            
        Returns:
            ModelArtifacts for XGBoost
            
        **Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.8**
        """
        # Create base model
        xgb = XGBClassifier(
            random_state=self.random_state,
            n_jobs=self.n_jobs,
            verbosity=self.verbose,
            use_label_encoder=False,
            eval_metric='aucpr'
        )
        
        # Create cross-validation strategy
        cv = StratifiedKFold(
            n_splits=self.cv_folds,
            shuffle=True,
            random_state=self.random_state
        )
        
        # Perform random search
        logger.info(f"Performing random search with {self.n_iter} iterations...")
        logger.info(f"Using {self.cv_folds}-fold stratified cross-validation")
        logger.info(f"Optimization metric: Precision-Recall AUC")
        
        start_time = time.time()
        
        search = RandomizedSearchCV(
            estimator=xgb,
            param_distributions=self.XGB_PARAM_GRID,
            n_iter=self.n_iter,
            scoring='average_precision',  # PR-AUC
            cv=cv,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
            verbose=self.verbose,
            return_train_score=True
        )
        
        search.fit(X_train, y_train)
        
        training_time = time.time() - start_time
        
        # Extract results
        best_params = search.best_params_
        best_score = search.best_score_
        cv_results = search.cv_results_
        
        # Get cross-validation scores for best model
        best_index = search.best_index_
        cv_scores = []
        for fold_idx in range(self.cv_folds):
            score = cv_results[f'split{fold_idx}_test_score'][best_index]
            cv_scores.append(score)
        
        mean_cv_score = np.mean(cv_scores)
        std_cv_score = np.std(cv_scores)
        
        # Log results
        logger.info("")
        logger.info("XGBoost Training Results:")
        logger.info(f"  Best parameters: {best_params}")
        logger.info(f"  Best PR-AUC: {best_score:.4f}")
        logger.info(f"  Mean CV PR-AUC: {mean_cv_score:.4f} (±{std_cv_score:.4f})")
        logger.info(f"  CV scores: {[f'{s:.4f}' for s in cv_scores]}")
        logger.info(f"  Training time: {training_time:.2f} seconds")
        logger.info("")
        
        # Create training result
        training_result = TrainingResult(
            model_name='xgboost',
            best_params=best_params,
            best_score=best_score,
            cv_scores=cv_scores,
            mean_cv_score=mean_cv_score,
            std_cv_score=std_cv_score,
            training_time_seconds=training_time,
            n_cv_folds=self.cv_folds
        )
        
        # Create metadata
        metadata = {
            'model_type': 'XGBClassifier',
            'n_estimators': best_params['n_estimators'],
            'max_depth': best_params['max_depth'],
            'learning_rate': best_params['learning_rate'],
            'subsample': best_params['subsample'],
            'colsample_bytree': best_params['colsample_bytree'],
            'scale_pos_weight': best_params['scale_pos_weight']
        }
        
        return ModelArtifacts(
            model=search.best_estimator_,
            scaler=scaler,
            feature_names=feature_names,
            training_result=training_result,
            metadata=metadata
        )


def main():
    """Main function for training models."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Step 1: Prepare dataset
    logger.info("=" * 80)
    logger.info("STEP 1: Preparing dataset...")
    logger.info("=" * 80)
    pipeline = DataPipeline()
    dataset = pipeline.prepare_dataset()
    
    # Step 2: Train models
    logger.info("")
    logger.info("=" * 80)
    logger.info("STEP 2: Training models...")
    logger.info("=" * 80)
    trainer = ModelTrainer()
    model_artifacts = trainer.train_models(dataset)
    
    # Step 3: Select best model
    logger.info("")
    logger.info("=" * 80)
    logger.info("STEP 3: Selecting best model...")
    logger.info("=" * 80)
    best_model_name, best_model_artifacts = trainer.select_best_model(model_artifacts)
    
    # Step 4: Retrain on full data
    logger.info("")
    logger.info("=" * 80)
    logger.info("STEP 4: Retraining on train+validation set...")
    logger.info("=" * 80)
    final_model_artifacts = trainer.retrain_on_full_data(dataset, best_model_artifacts)
    
    # Step 5: Save model artifacts
    logger.info("")
    logger.info("=" * 80)
    logger.info("STEP 5: Saving model artifacts...")
    logger.info("=" * 80)
    output_dir = Path('backend/models/url/ml_first_v1')
    trainer.save_model_artifacts(final_model_artifacts, best_model_name, output_dir)
    
    logger.info("")
    logger.info("=" * 80)
    logger.info("MODEL TRAINING COMPLETED SUCCESSFULLY!")
    logger.info("=" * 80)
    logger.info(f"Best model: {best_model_name}")
    logger.info(f"Mean CV PR-AUC: {final_model_artifacts.training_result.mean_cv_score:.4f}")
    logger.info(f"Model artifacts saved to: {output_dir}")
    logger.info("=" * 80)


if __name__ == '__main__':
    main()
