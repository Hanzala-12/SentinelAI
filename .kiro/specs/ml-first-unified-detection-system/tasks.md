# Implementation Plan: ML-First Unified Detection System

## Overview

This implementation plan transforms PhishLens from a fragmented heuristic-first architecture into an ML-first unified detection system. The implementation follows a bottom-up approach: building the ML inference foundation (feature extraction, model training, calibration), then integrating it into the decision pipeline, and finally refactoring the backend to use the new architecture.

The plan prioritizes offline-safe feature engineering, eliminates feature leakage, implements probability calibration, and establishes a reproducible training-to-deployment pipeline.

## Tasks

- [x] 1. Set up ML infrastructure and data models
  - Create directory structure for ML artifacts: `backend/models/url/ml_first_v1/`
  - Define data models: `MLFeaturePack`, `RiskAggregationResult`, `DecisionResult`, `ModelBundle`
  - Create `backend/ai_engine/ml_models.py` with dataclass definitions
  - Set up logging configuration for ML components
  - _Requirements: 6.1, 6.2, 15.1-15.5_

- [x] 1.1 Write unit tests for data models
  - Test dataclass initialization and validation
  - Test serialization/deserialization of data models
  - _Requirements: 19.1, 19.2_

- [x] 2. Implement offline-safe feature extraction engine
  - [x] 2.1 Create `MLFeatureEngine` class in `backend/ai_engine/ml_feature_engine.py`
    - Implement URL parsing and component extraction
    - Implement 16 feature extraction functions (URL length, character entropy, digit ratio, special char count, subdomain count, path depth, query param count, TLD category, domain token count, longest token length, vowel-consonant ratio, homoglyph risk score, HTTPS usage, IP address usage, port specification, normalized entropy)
    - Implement error handling for malformed URLs with safe defaults
    - Return `MLFeaturePack` with features, feature names, and metadata
    - _Requirements: 2.1-2.9, 10.1-10.16_

  - [x] 2.2 Write unit tests for feature extraction
    - Test each feature extraction function individually
    - Test malformed URL handling with default values
    - Test edge cases: empty paths, missing components, special characters
    - Verify feature vector always has 16 dimensions
    - _Requirements: 19.1, 19.4_

  - [x] 2.3 Verify no feature leakage
    - Review feature extraction logic to ensure no brand dictionaries
    - Review feature extraction logic to ensure no phishing keyword lists
    - Ensure all features use only URL string analysis
    - _Requirements: 3.1-3.7_

- [x] 3. Checkpoint - Verify feature extraction works offline
  - Test feature extraction on sample URLs without network access
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Build training data pipeline
  - [x] 4.1 Create `training/data_pipeline.py` for dataset preparation
    - Implement dataset loading from OpenPhish, PhishTank, and Alexa/Tranco
    - Implement URL deduplication by normalized domain
    - Implement filtering for malformed URLs
    - Implement stratified train/validation/test split (70/15/15)
    - Balance training data to 60/40 phishing/benign ratio
    - Preserve natural imbalance in validation and test sets
    - Log dataset statistics (class distribution, feature distributions)
    - _Requirements: 11.1-11.9_

  - [x] 4.2 Write unit tests for data pipeline
    - Test dataset loading and deduplication
    - Test stratified splitting logic
    - Test balancing logic for training set
    - Verify no domain overlap between splits
    - _Requirements: 19.1_

- [ ] 5. Implement model training pipeline
  - [x] 5.1 Create `training/train_model.py` for model training
    - Implement Random Forest and XGBoost model training
    - Implement hyperparameter search (grid search or random search)
    - Use Precision-Recall AUC as optimization metric
    - Use 5-fold stratified cross-validation
    - Tune hyperparameters: max_depth, n_estimators, learning_rate, min_samples_split
    - Select best model configuration based on mean PR-AUC
    - Retrain selected model on train+validation set
    - Log cross-validation scores and training time
    - _Requirements: 12.1-12.8_

  - [x] 5.2 Implement feature scaling
    - Fit StandardScaler or MinMaxScaler on training data
    - Save scaler to `backend/models/url/ml_first_v1/scaler.pkl`
    - _Requirements: 15.2_

  - [~] 5.3 Compute and save feature importance
    - Extract feature importance from trained model
    - Save feature importance to metadata
    - _Requirements: 13.1, 13.2_

  - [~] 5.4 Write integration tests for training pipeline
    - Test end-to-end training on small synthetic dataset
    - Verify model artifacts are created
    - Verify hyperparameter logging
    - _Requirements: 19.3_

- [ ] 6. Implement probability calibration
  - [x] 6.1 Create `ProbabilityCalibrator` class in `backend/intelligence/calibration.py`
    - Implement Platt scaling (LogisticRegression) calibration
    - Implement isotonic regression calibration
    - Implement `fit()` method for calibration set
    - Implement `calibrate()` method for single probability
    - _Requirements: 4.1-4.3_

  - [~] 6.2 Integrate calibration into training pipeline
    - Hold out 15% of training data for calibration (minimum 1000 samples)
    - Fit calibrator on held-out calibration set
    - Save calibrator to `backend/models/url/ml_first_v1/calibrator.pkl`
    - _Requirements: 4.4, 4.5_

  - [ ] 6.3 Write unit tests for calibration
    - Test Platt scaling calibration logic
    - Test isotonic regression calibration logic
    - Test calibration on synthetic probability distributions
    - _Requirements: 19.2_

- [~] 7. Checkpoint - Verify training pipeline produces complete model bundle
  - Run training pipeline on sample dataset
  - Verify model.pkl, scaler.pkl, calibrator.pkl are created
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Implement model bundle management
  - [~] 8.1 Create `ModelBundle` class in `backend/ai_engine/model_bundle.py`
    - Implement `load()` method to load all artifacts into memory
    - Implement `validate()` method to check bundle integrity
    - Implement feature schema validation
    - _Requirements: 15.1-15.9_

  - [~] 8.2 Create model metadata and feature schema
    - Create `feature_schema.json` with feature names, types, extraction logic version
    - Create `metadata.json` with model version, training date, hyperparameters, evaluation metrics, SHA256 checksums
    - _Requirements: 15.4, 15.5, 15.9_

  - [~] 8.3 Write unit tests for model bundle
    - Test bundle loading and validation
    - Test feature schema compatibility checking
    - Test error handling for missing artifacts
    - _Requirements: 19.7_

- [ ] 9. Build evaluation pipeline with realistic imbalance
  - [~] 9.1 Create `evaluation/evaluate_ml_model.py` for model evaluation
    - Implement evaluation on test set with 99/1 imbalance
    - Compute Precision-Recall AUC as primary metric
    - Compute recall at fixed precision thresholds (90%, 95%, 99%)
    - Compute false positive rate at fixed recall thresholds (75%, 85%, 95%)
    - Compute confusion matrix
    - _Requirements: 5.1-5.7, 9.1-9.5_

  - [~] 9.2 Implement calibration evaluation
    - Compute Expected Calibration Error (ECE)
    - Generate calibration plot comparing predicted probabilities to empirical frequencies
    - Verify ECE < 0.10
    - _Requirements: 4.7, 16.4_

  - [~] 9.3 Generate comprehensive evaluation report
    - Generate precision-recall curve plot
    - Report performance stratified by TLD category
    - Report performance stratified by URL length bins
    - Identify top-10 most important features
    - Save report as JSON and HTML in `evaluation/reports/ml_first_v1/`
    - Include dataset statistics and model hyperparameters
    - _Requirements: 16.1-16.9_

  - [~] 9.4 Write integration tests for evaluation pipeline
    - Test evaluation on small synthetic test set
    - Verify all metrics are computed correctly
    - Verify report generation
    - _Requirements: 19.3_

- [~] 10. Checkpoint - Verify evaluation pipeline meets performance targets
  - Run evaluation pipeline on test set
  - Verify recall > 75%, FPR < 10%, PR-AUC > 0.80
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 11. Implement ML inference engine
  - [~] 11.1 Create `MLInferenceEngine` class in `backend/ai_engine/ml_inference_engine.py`
    - Implement model bundle loading at initialization
    - Implement feature extraction using `MLFeatureEngine`
    - Implement ML model inference
    - Implement probability calibration using `ProbabilityCalibrator`
    - Implement error handling for inference failures (return SUSPICIOUS)
    - Log inference latency and failures
    - _Requirements: 6.4, 6.5, 8.1-8.6, 18.1, 18.5_

  - [~] 11.2 Implement feature importance and SHAP explanations
    - Compute feature contributions for each prediction
    - Implement SHAP value computation for local explanations
    - Return top-5 contributing features
    - _Requirements: 13.3, 13.4_

  - [~] 11.3 Write unit tests for ML inference engine
    - Test model loading and initialization
    - Test inference on sample URLs
    - Test error handling for inference failures
    - Test feature contribution computation
    - _Requirements: 19.1, 19.5_

  - [~] 11.4 Write integration tests for end-to-end ML pipeline
    - Test URL → Feature_Engine → ML_Model → Calibration_Layer → Output
    - Verify probability outputs are in [0, 1]
    - Verify feature vector dimensionality is constant
    - _Requirements: 19.3, 19.5_

- [ ] 12. Implement risk aggregation layer
  - [~] 12.1 Create `RiskAggregator` class in `backend/intelligence/risk_aggregator.py`
    - Implement weighted aggregation of ML probability, heuristic signals, threat intelligence
    - Implement configurable weights via environment variables
    - Implement confidence calculation
    - Return `RiskAggregationResult` with final score, component contributions, confidence
    - _Requirements: 1.6, 1.7_

  - [~] 12.2 Write unit tests for risk aggregation
    - Test weighted aggregation formula
    - Test confidence calculation
    - Test edge cases: missing heuristics, missing threat intel
    - _Requirements: 19.2_

- [ ] 13. Implement ML-first decision engine
  - [~] 13.1 Create `MLFirstDecisionEngine` class in `backend/intelligence/decision_engine.py`
    - Implement risk score to classification mapping (SAFE < 25, SUSPICIOUS 25-50, PHISHING ≥ 50)
    - Implement confidence-based classification adjustment
    - Implement fail-safe behavior for ML inference failures
    - Return `DecisionResult` with classification, threshold, confidence
    - _Requirements: 1.1-1.5, 8.1-8.4_

  - [~] 13.2 Write unit tests for decision engine
    - Test classification thresholds
    - Test confidence adjustment logic
    - Test fail-safe behavior
    - _Requirements: 19.2_

- [~] 14. Checkpoint - Verify ML-first decision pipeline works end-to-end
  - Test URL → Feature_Engine → ML_Model → Calibration → Risk_Aggregation → Decision
  - Verify classifications are correct for sample URLs
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 15. Implement explanation generator
  - [~] 15.1 Create `ExplanationGenerator` class in `backend/services/explanation_generator.py`
    - Combine ML feature contributions with heuristic signals
    - Generate human-readable explanation text
    - Include top-5 contributing features
    - Include heuristic context
    - _Requirements: 13.5, 13.6, 13.7_

  - [~] 15.2 Write unit tests for explanation generator
    - Test explanation text generation
    - Test feature contribution formatting
    - Test heuristic signal integration
    - _Requirements: 19.1_

- [ ] 16. Refactor backend to integrate ML-first pipeline
  - [~] 16.1 Refactor `AnalysisService` in `backend/services/analysis_service.py`
    - Add `MLInferenceEngine` initialization
    - Call `MLInferenceEngine` before `ThreatReasoningEngine`
    - Pass calibrated ML probability to `RiskAggregator`
    - _Requirements: 14.3_

  - [~] 16.2 Refactor `ThreatReasoningEngine` in `backend/intelligence/reasoning_engine.py`
    - Remove heuristic score overrides
    - Consume calibrated ML probabilities from `MLInferenceEngine`
    - Remove `_calibrate_url_model_score` method
    - Move heuristic logic to `ExplanationGenerator`
    - _Requirements: 14.2, 14.4, 14.5, 14.7_

  - [~] 16.3 Update API response schema
    - Add ML probability, calibrated probability, feature contributions to response
    - Add component contributions (ML, heuristic, threat intel) to response
    - Maintain backward compatibility with existing response fields
    - _Requirements: 17.7_

  - [~] 16.4 Write integration tests for refactored backend
    - Test end-to-end API request with ML-first pipeline
    - Test response schema includes ML fields
    - Test backward compatibility
    - _Requirements: 19.3_

- [ ] 17. Implement feature flag for ML-first pipeline
  - [~] 17.1 Add `USE_ML_FIRST_PIPELINE` feature flag
    - Add environment variable `USE_ML_FIRST_PIPELINE` (default: False)
    - Implement conditional routing in `AnalysisService`
    - When enabled, use ML-first pipeline; when disabled, use legacy pipeline
    - _Requirements: 17.1-17.3_

  - [~] 17.2 Implement shadow mode logging
    - Log classification decisions from both pipelines when feature flag is in shadow mode
    - Compute agreement metrics between legacy and ML-first pipelines
    - _Requirements: 17.4, 17.5_

  - [~] 17.3 Implement A/B testing endpoint
    - Create endpoint that randomly routes requests to legacy or ML-first pipelines
    - Log routing decisions and results
    - _Requirements: 17.6_

  - [~] 17.4 Write integration tests for feature flag
    - Test feature flag toggling between pipelines
    - Test shadow mode logging
    - Test A/B testing endpoint
    - _Requirements: 19.3_

- [~] 18. Checkpoint - Verify refactored backend works with feature flag
  - Test API with feature flag enabled and disabled
  - Verify both pipelines produce valid responses
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 19. Implement monitoring and observability
  - [~] 19.1 Add ML inference metrics
    - Log ML inference latency for each request
    - Log feature extraction latency for each request
    - Log calibrated probability distribution over time
    - Log classification distribution (SAFE, SUSPICIOUS, PHISHING) over time
    - Emit metrics for ML inference failures
    - Emit metrics for feature extraction failures
    - _Requirements: 18.1-18.6_

  - [~] 19.2 Add alerting rules
    - Alert when ML inference failure rate exceeds 1%
    - Alert when p95 inference latency exceeds 500ms
    - _Requirements: 18.7, 18.8_

  - [~] 19.3 Expose Prometheus-compatible metrics endpoint
    - Create `/metrics` endpoint for Prometheus scraping
    - Include ML inference metrics, latency metrics, failure metrics
    - _Requirements: 18.9_

- [ ] 20. Implement offline mode consistency
  - [~] 20.1 Add `PHISHLENS_OFFLINE_EVAL` environment variable
    - When set, disable all network-dependent features
    - Ensure Feature_Engine, ML_Model, Calibration_Layer work without network
    - _Requirements: 7.4_

  - [~] 20.2 Verify offline mode consistency
    - Test that evaluation and production produce identical classifications for identical URLs in offline mode
    - Verify ML_Model artifact is byte-identical across deployment modes
    - _Requirements: 7.5, 7.7_

  - [~] 20.3 Write regression tests for offline mode
    - Test classification consistency between evaluation and production
    - Test feature extraction without network access
    - _Requirements: 19.6_

- [ ] 21. Create comprehensive documentation
  - [~] 21.1 Write architecture README
    - Document ML-first architecture with diagrams
    - Document data flow from URL to classification
    - Document component responsibilities
    - _Requirements: 20.1_

  - [~] 21.2 Write training guide
    - Document how to prepare training data
    - Document how to train and evaluate models
    - Document hyperparameter tuning process
    - _Requirements: 20.2_

  - [~] 21.3 Write deployment guide
    - Document how to deploy Model_Bundle artifacts
    - Document how to enable ML-first pipeline with feature flag
    - Document rollback procedures
    - _Requirements: 20.3_

  - [~] 21.4 Write troubleshooting guide
    - Document common failure modes and resolutions
    - Document how to debug ML inference failures
    - Document how to interpret monitoring metrics
    - _Requirements: 20.4_

  - [~] 21.5 Write API documentation
    - Document MLInferenceEngine, Feature_Engine, Calibration_Layer APIs
    - Include code examples and expected outputs
    - _Requirements: 20.5_

  - [~] 21.6 Write feature engineering guide
    - Document each of the 16 features and their rationale
    - Document feature extraction logic
    - Document how to add new features
    - _Requirements: 20.6_

  - [~] 21.7 Write model retraining runbook
    - Document step-by-step model retraining process
    - Document model deployment process
    - Document validation and rollback procedures
    - _Requirements: 20.7_

- [~] 22. Final checkpoint - End-to-end validation
  - Run full training pipeline on production datasets
  - Run evaluation pipeline and verify performance targets met
  - Deploy model bundle to staging environment
  - Test API with ML-first pipeline enabled
  - Run regression tests comparing legacy and ML-first pipelines
  - Verify monitoring metrics are being collected
  - Verify documentation is complete and accurate
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation throughout implementation
- The implementation follows a bottom-up approach: ML foundation → integration → refactoring
- Feature flag allows safe migration from legacy to ML-first pipeline
- All core ML components (Feature_Engine, ML_Model, Calibration_Layer) are offline-safe by design
- Testing strategy focuses on unit tests for individual components and integration tests for end-to-end flows
- Documentation is comprehensive to support long-term maintenance and team onboarding
