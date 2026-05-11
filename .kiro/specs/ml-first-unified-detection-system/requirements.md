# Requirements Document: ML-First Unified Detection System

## Introduction

PhishLens is a phishing detection platform that currently suffers from fragmented decision logic where heuristics, ML models, and threat intelligence operate independently. The system exhibits critical architectural issues including zero recall in offline mode, potential ML feature leakage, uncalibrated probability outputs, evaluation-production mismatch, and lack of a unified model artifact pipeline.

This requirements document specifies the transformation of PhishLens into an ML-first unified detection system where machine learning serves as the primary decision engine, heuristics provide explanatory context, and the system maintains consistent performance regardless of network availability.

## Glossary

- **ML_Model**: The machine learning classifier (Random Forest or XGBoost) that produces phishing probability scores from URL features
- **Feature_Engine**: The component that extracts offline-safe features from URLs without requiring network access
- **Calibration_Layer**: The component that transforms raw ML probabilities into calibrated probabilities using Platt scaling or isotonic regression
- **Risk_Aggregation_Layer**: The component that combines calibrated ML probability with optional heuristic and threat intelligence signals
- **Decision_Engine**: The component that maps final risk scores to classification labels (SAFE, SUSPICIOUS, PHISHING)
- **Model_Bundle**: The artifact package containing model.pkl, scaler.pkl, calibrator.pkl, and feature_schema.json
- **Offline_Mode**: Operation mode where network-dependent signals (WHOIS, DOM analysis, threat intelligence) are unavailable
- **Feature_Leakage**: The condition where features encode information too similar to the target label, causing overfitting
- **Probability_Calibration**: The process of adjusting ML output probabilities to match empirical frequencies
- **Heuristic_Engine**: The legacy rule-based scoring system that now serves explanatory purposes only
- **Threat_Intelligence**: External reputation data from providers like VirusTotal, URLScan, AbuseIPDB
- **Training_Pipeline**: The reproducible workflow that transforms raw datasets into trained Model_Bundle artifacts
- **Inference_Engine**: The production component that loads Model_Bundle and classifies URLs
- **Evaluation_Pipeline**: The testing framework that measures model performance under realistic traffic distributions

## Requirements

### Requirement 1: ML-First Decision Architecture

**User Story:** As a security engineer, I want the ML model to be the primary decision engine, so that classification decisions are data-driven rather than rule-based.

#### Acceptance Criteria

1. THE Decision_Engine SHALL use ML_Model probability as the primary input with weight 0.7-0.9
2. THE Decision_Engine SHALL use Heuristic_Engine signals as secondary input with weight 0.1-0.2
3. THE Decision_Engine SHALL use Threat_Intelligence as optional input with weight 0.0-0.1
4. WHEN ML_Model produces a probability score, THE Decision_Engine SHALL NOT override the score with heuristic rules
5. WHEN Heuristic_Engine produces signals, THE System SHALL use them for explanation generation only
6. THE Risk_Aggregation_Layer SHALL compute final score as weighted sum of calibrated ML probability, heuristic signals, and threat intelligence
7. FOR ALL classification decisions, the ML_Model contribution SHALL be greater than the combined heuristic and threat intelligence contribution

### Requirement 2: Offline-Safe Feature Engineering

**User Story:** As a system operator, I want the system to maintain consistent performance without network access, so that classification does not fail when network signals are unavailable.

#### Acceptance Criteria

1. THE Feature_Engine SHALL extract features using only URL string analysis
2. THE Feature_Engine SHALL NOT depend on WHOIS lookups for feature extraction
3. THE Feature_Engine SHALL NOT depend on DOM analysis for feature extraction
4. THE Feature_Engine SHALL NOT depend on external API calls for feature extraction
5. WHEN network signals are unavailable, THE Feature_Engine SHALL produce complete feature vectors
6. THE Feature_Engine SHALL extract lexical features including URL length, character entropy, special character counts
7. THE Feature_Engine SHALL extract structural features including subdomain count, path depth, query parameter count
8. THE Feature_Engine SHALL extract domain heuristics including TLD type, homoglyph detection, brand similarity
9. FOR ALL URLs, the Feature_Engine SHALL produce feature vectors with identical dimensionality regardless of network availability

### Requirement 3: Feature Leakage Elimination

**User Story:** As a machine learning engineer, I want features to be independent of ground truth labels, so that the model generalizes to unseen phishing patterns.

#### Acceptance Criteria

1. THE Feature_Engine SHALL NOT include `impersonates_known_brand` as a feature
2. THE Feature_Engine SHALL NOT include `has_phishing_keyword` as a feature
3. THE Feature_Engine SHALL NOT include explicit brand dictionary lookups as features
4. THE Feature_Engine SHALL NOT include explicit phishing keyword counts as features
5. THE Feature_Engine SHALL use character-level entropy instead of keyword matching
6. THE Feature_Engine SHALL use structural similarity metrics instead of brand dictionaries
7. FOR ALL features, the feature extraction logic SHALL NOT reference phishing-specific dictionaries or labeled data

### Requirement 4: Probability Calibration

**User Story:** As a security analyst, I want ML probability scores to reflect true likelihood, so that risk assessments are reliable for decision-making.

#### Acceptance Criteria

1. THE Calibration_Layer SHALL transform raw ML probabilities into calibrated probabilities
2. THE Calibration_Layer SHALL use Platt scaling or isotonic regression for calibration
3. WHEN ML_Model produces raw probability P, THE Calibration_Layer SHALL output calibrated probability C where C reflects empirical frequency
4. THE Training_Pipeline SHALL fit the calibrator on a held-out calibration dataset
5. THE Model_Bundle SHALL include the fitted calibrator artifact
6. THE Inference_Engine SHALL apply calibration before passing probabilities to Risk_Aggregation_Layer
7. FOR ALL calibrated probabilities, the calibration error (Expected Calibration Error) SHALL be less than 0.10

### Requirement 5: Realistic Evaluation Under Imbalance

**User Story:** As a machine learning engineer, I want evaluation to reflect real-world traffic distribution, so that performance metrics predict production behavior.

#### Acceptance Criteria

1. THE Evaluation_Pipeline SHALL test models using 95-99% benign and 1-5% phishing traffic distribution
2. THE Evaluation_Pipeline SHALL report Precision-Recall AUC as the primary metric
3. THE Evaluation_Pipeline SHALL report recall at fixed precision thresholds (90%, 95%, 99%)
4. THE Evaluation_Pipeline SHALL report false positive rate at fixed recall thresholds (75%, 85%, 95%)
5. WHEN evaluating model performance, THE Evaluation_Pipeline SHALL NOT use balanced 50/50 datasets
6. THE Evaluation_Pipeline SHALL use stratified k-fold cross-validation with k=5
7. FOR ALL evaluation runs, the test set SHALL maintain the specified imbalance ratio

### Requirement 6: Unified Model Artifact Pipeline

**User Story:** As a deployment engineer, I want a single reproducible pipeline from training to inference, so that model behavior is consistent across environments.

#### Acceptance Criteria

1. THE Training_Pipeline SHALL produce a Model_Bundle containing model.pkl, scaler.pkl, calibrator.pkl, and feature_schema.json
2. THE Training_Pipeline SHALL version Model_Bundle artifacts with semantic versioning
3. THE Training_Pipeline SHALL log training hyperparameters, dataset statistics, and evaluation metrics
4. THE Inference_Engine SHALL load Model_Bundle once at initialization
5. THE Inference_Engine SHALL NOT retrain models during online operation
6. THE Inference_Engine SHALL validate feature schema compatibility before inference
7. FOR ALL Model_Bundle artifacts, the Training_Pipeline SHALL ensure reproducibility through fixed random seeds and dependency pinning

### Requirement 7: Offline Mode Consistency

**User Story:** As a system operator, I want the same ML model to be used in offline evaluation, production API, and batch processing, so that performance is consistent across deployment modes.

#### Acceptance Criteria

1. THE Evaluation_Pipeline SHALL use the same Feature_Engine as the Inference_Engine
2. THE Evaluation_Pipeline SHALL use the same ML_Model as the Inference_Engine
3. THE Evaluation_Pipeline SHALL use the same Calibration_Layer as the Inference_Engine
4. WHEN PHISHLENS_OFFLINE_EVAL environment variable is set, THE System SHALL disable all network-dependent features
5. WHEN operating in Offline_Mode, THE System SHALL produce identical classifications for identical URLs across evaluation and production
6. THE System SHALL NOT use different feature extraction logic between training and inference
7. FOR ALL deployment modes, the ML_Model artifact SHALL be byte-identical

### Requirement 8: Fail-Safe Behavior

**User Story:** As a security engineer, I want the system to fail conservatively when ML inference fails, so that potential threats are not incorrectly classified as safe.

#### Acceptance Criteria

1. WHEN ML_Model inference fails, THE Decision_Engine SHALL classify the URL as SUSPICIOUS
2. WHEN ML_Model inference fails, THE Decision_Engine SHALL NOT fallback to heuristic-only classification
3. WHEN Feature_Engine fails to extract features, THE Decision_Engine SHALL classify the URL as SUSPICIOUS
4. WHEN Calibration_Layer fails, THE Decision_Engine SHALL use uncalibrated ML probability with a conservative threshold
5. IF ML_Model artifact is missing, THEN THE System SHALL refuse to start and log a critical error
6. THE System SHALL log all ML inference failures with full context for debugging
7. FOR ALL failure modes, the System SHALL prefer false positives over false negatives

### Requirement 9: Performance Targets

**User Story:** As a security operations manager, I want the system to meet minimum performance thresholds, so that phishing threats are detected reliably with acceptable false positive rates.

#### Acceptance Criteria

1. THE ML_Model SHALL achieve recall greater than 75% on the phishing test set
2. THE ML_Model SHALL achieve false positive rate less than 10% on the benign test set
3. THE ML_Model SHALL achieve Precision-Recall AUC greater than 0.80
4. WHEN evaluated under 99/1 imbalance, THE ML_Model SHALL maintain recall above 70%
5. WHEN evaluated under 99/1 imbalance, THE ML_Model SHALL maintain precision above 15%
6. THE Inference_Engine SHALL classify URLs in less than 500ms at p95 latency
7. FOR ALL performance metrics, the Evaluation_Pipeline SHALL report 95% confidence intervals

### Requirement 10: Feature Set Specification

**User Story:** As a machine learning engineer, I want a well-defined feature set without leakage, so that the model is robust and maintainable.

#### Acceptance Criteria

1. THE Feature_Engine SHALL extract URL length as a feature
2. THE Feature_Engine SHALL extract character entropy (Shannon entropy) as a feature
3. THE Feature_Engine SHALL extract digit ratio as a feature
4. THE Feature_Engine SHALL extract special character count as a feature
5. THE Feature_Engine SHALL extract subdomain count as a feature
6. THE Feature_Engine SHALL extract path depth as a feature
7. THE Feature_Engine SHALL extract query parameter count as a feature
8. THE Feature_Engine SHALL extract TLD category (generic, country-code, suspicious) as a feature
9. THE Feature_Engine SHALL extract domain token count as a feature
10. THE Feature_Engine SHALL extract longest token length as a feature
11. THE Feature_Engine SHALL extract vowel-consonant ratio as a feature
12. THE Feature_Engine SHALL extract homoglyph risk score as a feature
13. THE Feature_Engine SHALL extract HTTPS usage as a feature
14. THE Feature_Engine SHALL extract IP address usage as a feature
15. THE Feature_Engine SHALL extract port specification as a feature
16. FOR ALL features, the Feature_Engine SHALL compute values using only the URL string

### Requirement 11: Training Data Pipeline

**User Story:** As a machine learning engineer, I want a reproducible data preparation pipeline, so that training datasets are consistent and auditable.

#### Acceptance Criteria

1. THE Training_Pipeline SHALL load phishing URLs from OpenPhish and PhishTank datasets
2. THE Training_Pipeline SHALL load benign URLs from Alexa Top 1M or Tranco list
3. THE Training_Pipeline SHALL perform stratified train/validation/test split with 70/15/15 ratio
4. THE Training_Pipeline SHALL deduplicate URLs by normalized domain
5. THE Training_Pipeline SHALL filter out URLs with missing or malformed components
6. THE Training_Pipeline SHALL balance training data to 60/40 phishing/benign ratio
7. THE Training_Pipeline SHALL preserve natural imbalance in validation and test sets
8. THE Training_Pipeline SHALL log dataset statistics including class distribution, feature distributions, and missing value counts
9. FOR ALL dataset splits, the Training_Pipeline SHALL ensure no domain overlap between train, validation, and test sets

### Requirement 12: Model Selection and Hyperparameter Tuning

**User Story:** As a machine learning engineer, I want systematic model selection and tuning, so that the best performing model is deployed.

#### Acceptance Criteria

1. THE Training_Pipeline SHALL evaluate Random Forest and XGBoost classifiers
2. THE Training_Pipeline SHALL perform grid search or random search for hyperparameter tuning
3. THE Training_Pipeline SHALL use Precision-Recall AUC as the optimization metric
4. THE Training_Pipeline SHALL use 5-fold stratified cross-validation for hyperparameter selection
5. THE Training_Pipeline SHALL tune max_depth, n_estimators, learning_rate, and min_samples_split hyperparameters
6. THE Training_Pipeline SHALL select the model configuration with highest mean PR-AUC across folds
7. THE Training_Pipeline SHALL retrain the selected model on the combined train+validation set before final evaluation
8. FOR ALL hyperparameter configurations, the Training_Pipeline SHALL log cross-validation scores and training time

### Requirement 13: Model Interpretability and Explainability

**User Story:** As a security analyst, I want to understand why the model classified a URL as phishing, so that I can validate and trust the decision.

#### Acceptance Criteria

1. THE Training_Pipeline SHALL compute feature importance scores using the trained ML_Model
2. THE Training_Pipeline SHALL include feature importance in the Model_Bundle metadata
3. THE Inference_Engine SHALL provide top-5 contributing features for each classification
4. THE Inference_Engine SHALL provide SHAP values or equivalent local explanations for individual predictions
5. THE System SHALL display feature contributions in the explanation output
6. THE System SHALL combine ML feature contributions with heuristic signals in the final explanation
7. FOR ALL classifications, the explanation SHALL include both ML reasoning and heuristic context

### Requirement 14: Refactored Backend Architecture

**User Story:** As a backend engineer, I want a clean separation between ML inference and decision logic, so that the system is maintainable and testable.

#### Acceptance Criteria

1. THE System SHALL create a new `MLInferenceEngine` class that encapsulates ML_Model loading and inference
2. THE System SHALL refactor `ThreatReasoningEngine` to consume calibrated ML probabilities from `MLInferenceEngine`
3. THE System SHALL refactor `AnalysisService` to call `MLInferenceEngine` before `ThreatReasoningEngine`
4. THE System SHALL remove heuristic score overrides from `ThreatReasoningEngine`
5. THE System SHALL move heuristic logic to an `ExplanationGenerator` class
6. THE System SHALL ensure `Decision_Engine` uses ML probability as the primary signal
7. THE System SHALL remove the `_calibrate_url_model_score` method that applies manual calibration rules
8. FOR ALL classification requests, the flow SHALL be: URL → Feature_Engine → ML_Model → Calibration_Layer → Risk_Aggregation_Layer → Decision_Engine

### Requirement 15: Model Bundle Structure

**User Story:** As a deployment engineer, I want a standardized model artifact format, so that models can be versioned, deployed, and rolled back reliably.

#### Acceptance Criteria

1. THE Model_Bundle SHALL include `model.pkl` containing the trained classifier
2. THE Model_Bundle SHALL include `scaler.pkl` containing the fitted feature scaler
3. THE Model_Bundle SHALL include `calibrator.pkl` containing the fitted probability calibrator
4. THE Model_Bundle SHALL include `feature_schema.json` containing feature names, types, and extraction logic version
5. THE Model_Bundle SHALL include `metadata.json` containing model version, training date, hyperparameters, and evaluation metrics
6. THE Model_Bundle SHALL be stored in `backend/models/url/ml_first_v{version}/`
7. THE Inference_Engine SHALL validate Model_Bundle integrity by checking for all required files
8. THE Inference_Engine SHALL validate feature schema compatibility before loading the model
9. FOR ALL Model_Bundle versions, the metadata SHALL include SHA256 checksums of all artifact files

### Requirement 16: Evaluation Reporting

**User Story:** As a machine learning engineer, I want comprehensive evaluation reports, so that I can assess model quality and identify improvement opportunities.

#### Acceptance Criteria

1. THE Evaluation_Pipeline SHALL generate a report including precision, recall, F1-score, and PR-AUC
2. THE Evaluation_Pipeline SHALL generate a confusion matrix for the test set
3. THE Evaluation_Pipeline SHALL generate a precision-recall curve plot
4. THE Evaluation_Pipeline SHALL generate a calibration plot comparing predicted probabilities to empirical frequencies
5. THE Evaluation_Pipeline SHALL report performance stratified by TLD category
6. THE Evaluation_Pipeline SHALL report performance stratified by URL length bins
7. THE Evaluation_Pipeline SHALL identify the top-10 most important features
8. THE Evaluation_Pipeline SHALL save the report as JSON and HTML in `evaluation/reports/ml_first_v{version}/`
9. FOR ALL evaluation reports, the Evaluation_Pipeline SHALL include dataset statistics and model hyperparameters

### Requirement 17: Backward Compatibility and Migration

**User Story:** As a product manager, I want the new ML-first system to coexist with the legacy system during migration, so that we can validate performance before full cutover.

#### Acceptance Criteria

1. THE System SHALL support a feature flag `USE_ML_FIRST_PIPELINE` to toggle between legacy and ML-first pipelines
2. WHEN `USE_ML_FIRST_PIPELINE` is enabled, THE System SHALL use the new ML-first architecture
3. WHEN `USE_ML_FIRST_PIPELINE` is disabled, THE System SHALL use the legacy heuristic-first architecture
4. THE System SHALL log classification decisions from both pipelines when the feature flag is in shadow mode
5. THE System SHALL compute agreement metrics between legacy and ML-first pipelines
6. THE System SHALL provide an A/B testing endpoint that randomly routes requests to legacy or ML-first pipelines
7. FOR ALL migration phases, the System SHALL maintain API response schema compatibility

### Requirement 18: Monitoring and Observability

**User Story:** As a site reliability engineer, I want comprehensive monitoring of ML inference, so that I can detect model degradation and system issues.

#### Acceptance Criteria

1. THE Inference_Engine SHALL log ML inference latency for each request
2. THE Inference_Engine SHALL log feature extraction latency for each request
3. THE Inference_Engine SHALL log calibrated probability distribution over time
4. THE Inference_Engine SHALL log classification distribution (SAFE, SUSPICIOUS, PHISHING) over time
5. THE Inference_Engine SHALL emit metrics for ML inference failures
6. THE Inference_Engine SHALL emit metrics for feature extraction failures
7. THE System SHALL alert when ML inference failure rate exceeds 1%
8. THE System SHALL alert when p95 inference latency exceeds 500ms
9. FOR ALL production deployments, the System SHALL expose Prometheus-compatible metrics endpoints

### Requirement 19: Testing and Validation

**User Story:** As a quality assurance engineer, I want comprehensive tests for the ML pipeline, so that regressions are caught before deployment.

#### Acceptance Criteria

1. THE System SHALL include unit tests for Feature_Engine covering all feature extraction functions
2. THE System SHALL include unit tests for Calibration_Layer covering calibration logic
3. THE System SHALL include integration tests for the full ML inference pipeline
4. THE System SHALL include property-based tests for Feature_Engine ensuring feature vector dimensionality is constant
5. THE System SHALL include property-based tests for ML_Model ensuring probability outputs are in [0, 1]
6. THE System SHALL include regression tests comparing ML-first and legacy pipeline outputs on a fixed test set
7. THE System SHALL include smoke tests verifying Model_Bundle loading and inference
8. FOR ALL test suites, the System SHALL achieve at least 85% code coverage for ML-related modules

### Requirement 20: Documentation and Runbooks

**User Story:** As a new team member, I want comprehensive documentation of the ML system, so that I can understand, maintain, and extend it.

#### Acceptance Criteria

1. THE System SHALL include a README documenting the ML-first architecture with diagrams
2. THE System SHALL include a training guide documenting how to train and evaluate models
3. THE System SHALL include a deployment guide documenting how to deploy Model_Bundle artifacts
4. THE System SHALL include a troubleshooting guide documenting common failure modes and resolutions
5. THE System SHALL include API documentation for MLInferenceEngine, Feature_Engine, and Calibration_Layer
6. THE System SHALL include a feature engineering guide documenting each feature and its rationale
7. THE System SHALL include a runbook for model retraining and deployment
8. FOR ALL documentation, the System SHALL include code examples and expected outputs

