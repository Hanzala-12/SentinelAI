# ProbabilityCalibrator

## Overview

The `ProbabilityCalibrator` class transforms raw ML model probabilities into calibrated probabilities that better reflect true empirical frequencies. This is critical for reliable risk assessment in the ML-first unified detection system.

**Validates: Requirements 4.1-4.3**

## Why Calibration Matters

Raw ML model outputs often don't reflect true probabilities:
- **Overconfident models**: Predict 0.9 but actual frequency is 0.6
- **Underconfident models**: Predict 0.4 but actual frequency is 0.7

Calibration corrects these systematic biases, ensuring that when the model predicts 0.7, approximately 70% of those predictions are actually positive.

## Calibration Methods

### 1. Platt Scaling (Default)
- **Algorithm**: Fits logistic regression on raw probabilities
- **Formula**: `P_calibrated = 1 / (1 + exp(A * P_raw + B))`
- **Pros**: 
  - Parametric (fewer parameters to fit)
  - Works well with small calibration sets (100-1000 samples)
  - Fast inference
- **Cons**: 
  - Assumes sigmoid relationship
  - Less flexible than isotonic regression

### 2. Isotonic Regression
- **Algorithm**: Fits non-parametric monotonic function
- **Pros**: 
  - More flexible (no distributional assumptions)
  - Can capture complex calibration patterns
- **Cons**: 
  - Requires larger calibration sets (1000+ samples)
  - Risk of overfitting with small datasets

## Usage

### Basic Usage

```python
from backend.intelligence.calibration import ProbabilityCalibrator
import numpy as np

# Initialize calibrator
calibrator = ProbabilityCalibrator(method='platt')

# Fit on held-out calibration set
raw_probs = np.array([0.1, 0.3, 0.5, 0.7, 0.9, ...])  # Raw ML outputs
y_true = np.array([0, 0, 1, 1, 1, ...])  # True labels

calibrator.fit(raw_probs, y_true)

# Calibrate single probability
calibrated = calibrator.calibrate(0.75)
print(f"Raw: 0.75 -> Calibrated: {calibrated:.4f}")

# Calibrate batch of probabilities (more efficient)
test_probs = np.array([0.2, 0.5, 0.8])
calibrated_batch = calibrator.calibrate_batch(test_probs)
```

### Integration with ML Pipeline

```python
# During training
from backend.intelligence.calibration import ProbabilityCalibrator

# 1. Train ML model on training set
model.fit(X_train, y_train)

# 2. Get predictions on held-out calibration set
raw_probs_cal = model.predict_proba(X_cal)[:, 1]

# 3. Fit calibrator
calibrator = ProbabilityCalibrator(method='platt')
calibrator.fit(raw_probs_cal, y_cal)

# 4. Save calibrator with model bundle
import pickle
with open('calibrator.pkl', 'wb') as f:
    pickle.dump(calibrator, f)

# During inference
# 1. Load calibrator
with open('calibrator.pkl', 'rb') as f:
    calibrator = pickle.load(f)

# 2. Get raw ML prediction
raw_prob = model.predict_proba(X_test)[:, 1]

# 3. Calibrate
calibrated_prob = calibrator.calibrate(raw_prob[0])
```

## Calibration Dataset Requirements

### Minimum Requirements
- **Size**: At least 1000 samples (500 phishing, 500 benign)
- **Source**: 15% of training data held out before model training
- **Distribution**: Maintain natural imbalance or use stratified sampling
- **Classes**: Must contain both positive and negative examples

### Best Practices
- Use stratified sampling to ensure both classes are represented
- Keep calibration set separate from training and test sets
- Larger calibration sets improve reliability (especially for isotonic regression)
- Monitor calibration quality using Expected Calibration Error (ECE)

## Evaluation Metrics

### Expected Calibration Error (ECE)
Measures average absolute difference between predicted probability and empirical frequency across bins.

**Target**: ECE < 0.10

```python
def compute_ece(probs, labels, n_bins=10):
    """Compute Expected Calibration Error"""
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    
    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        
        in_bin = (probs >= bin_lower) & (probs < bin_upper)
        if i == n_bins - 1:
            in_bin = (probs >= bin_lower) & (probs <= bin_upper)
        
        if np.sum(in_bin) > 0:
            bin_accuracy = np.mean(labels[in_bin])
            bin_confidence = np.mean(probs[in_bin])
            bin_weight = np.sum(in_bin) / len(probs)
            
            ece += bin_weight * np.abs(bin_accuracy - bin_confidence)
    
    return ece
```

## Error Handling

The calibrator includes comprehensive error handling:

### Validation Errors
- Empty calibration set → `ValueError`
- Mismatched array lengths → `ValueError`
- Probabilities outside [0, 1] → `ValueError`
- Labels not in {0, 1} → `ValueError`
- Single class only → `ValueError`

### Runtime Errors
- Calibration before fitting → `RuntimeError`
- Calibration fitting failure → `RuntimeError`

### Fail-Safe Behavior
If calibration fails during inference, the calibrator logs a warning and returns the uncalibrated probability to ensure the system continues operating.

## Testing

### Unit Tests
Located in `backend/intelligence/test_calibration.py`
- 34 unit tests covering all functionality
- Tests for both Platt and isotonic methods
- Edge case handling
- Error validation

### Integration Tests
Located in `backend/intelligence/calibration/test_integration.py`
- End-to-end workflow tests
- Realistic imbalanced data scenarios
- Method comparison
- ECE validation

Run tests:
```bash
# Unit tests
pytest backend/intelligence/test_calibration.py -v

# Integration tests
pytest backend/intelligence/calibration/test_integration.py -v -s

# All calibration tests
pytest backend/intelligence/test_calibration.py backend/intelligence/calibration/test_integration.py -v
```

## Performance Characteristics

### Fitting Time
- **Platt scaling**: O(n) where n = calibration set size
- **Isotonic regression**: O(n log n)

### Inference Time
- **Single probability**: < 1ms
- **Batch (1000 probabilities)**: < 10ms

### Memory
- **Platt scaling**: ~1KB (2 parameters)
- **Isotonic regression**: ~10KB (stores calibration curve)

## References

1. Platt, J. (1999). "Probabilistic outputs for support vector machines"
2. Zadrozny, B., & Elkan, C. (2002). "Transforming classifier scores into accurate multiclass probability estimates"
3. Niculescu-Mizil, A., & Caruana, R. (2005). "Predicting good probabilities with supervised learning"

## See Also

- Design Document: `.kiro/specs/ml-first-unified-detection-system/design.md`
- Requirements: `.kiro/specs/ml-first-unified-detection-system/requirements.md` (Requirements 4.1-4.3)
- Model Bundle Structure: Requirement 15
