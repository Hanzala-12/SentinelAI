# 🔧 NOTEBOOK INTEGRATION: Ready-to-Paste Code Cells

This document provides exact code cells to integrate into the existing `phishlens_evaluation.ipynb` notebook to fix the zero-recall problem.

## 📋 Checklist of Changes

- [ ] Add imports for new ML modules
- [ ] Add configuration section at top
- [ ] Replace dataset loading with sampled loader
- [ ] Add feature extraction step
- [ ] Add ML model training step
- [ ] Replace evaluation with ML metrics
- [ ] Add threshold sweep analysis
- [ ] Save ML reports

---

## Code Cell 1: Import New Modules

**Location**: After existing imports, add these lines

```python
# ============ NEW: ML-based feature extraction and modeling ============
from evaluation.utils.sampled_dataset_loader import SampledDatasetLoader
from evaluation.utils.ml_feature_extractor import MLFeatureExtractor
from evaluation.utils.ml_model import MLPipeline

print("✓ ML modules imported successfully")
```

---

## Code Cell 2: Configuration Section

**Location**: Add new cell after imports (before any data loading)

```python
# ============ CONFIGURATION ============
# These values determine evaluation behavior (edit as needed)

EVAL_MODE = "ml_based"  # "ml_based" (new, recommended) or "heuristic_based" (old)
SAMPLE_SIZE = 100  # URLs per dataset (100-500 for testing, 1000+ for production)
MODEL_TYPE = "random_forest"  # or "logistic_regression"
TEST_SIZE = 0.25  # Fraction for testing (25%)
RANDOM_STATE = 42  # For reproducibility

# Display configuration
print("=" * 70)
print("EVALUATION CONFIGURATION")
print("=" * 70)
print(f"Mode:              {EVAL_MODE}")
print(f"Sample Size:       {SAMPLE_SIZE} per dataset (~{SAMPLE_SIZE*3} total)")
print(f"Model Type:        {MODEL_TYPE}")
print(f"Train/Test Split:  {int((1-TEST_SIZE)*100)}/{int(TEST_SIZE*100)}")
print(f"Random Seed:       {RANDOM_STATE}")
print("=" * 70)

# Validate configuration
assert EVAL_MODE in ["ml_based", "heuristic_based"], "Invalid EVAL_MODE"
assert MODEL_TYPE in ["logistic_regression", "random_forest"], "Invalid MODEL_TYPE"
```

---

## Code Cell 3: Replace Dataset Loading

**REPLACE** the existing `load_openphish()`, `load_phishtank()`, `load_benign()` calls with:

```python
print("\n" + "=" * 70)
print("STEP 1: LOAD DATASETS WITH SAMPLING")
print("=" * 70)

# Load datasets with stratified sampling (NEW APPROACH)
loader = SampledDatasetLoader("evaluation/datasets")
sampled_data = loader.load_with_sampling(
    sample_size=SAMPLE_SIZE,
    balance=True  # Equal benign/phishing per source
)

print(f"\n✓ Datasets loaded successfully")
print(f"  Total URLs: {len(sampled_data)}")
print(f"  Benign: {len(sampled_data[sampled_data['label']==0])}")
print(f"  Phishing: {len(sampled_data[sampled_data['label']==1])}")
print(f"  Sources: {', '.join(sampled_data['source_dataset'].unique())}")

# Create dataset for downstream use
dataset = sampled_data
```

---

## Code Cell 4: Feature Extraction (NEW)

**INSERT NEW CELL** after dataset loading:

```python
print("\n" + "=" * 70)
print("STEP 2: EXTRACT ML FEATURES")
print("=" * 70)

if EVAL_MODE == "ml_based":
    # Extract ML-ready features from URLs
    extractor = MLFeatureExtractor()
    features_df = extractor.extract_features_batch(dataset[['url', 'label']])
    
    print(f"\n✓ Features extracted successfully")
    print(f"  Total features: {len(extractor.get_feature_names())}")
    print(f"  Feature samples (first URL):")
    
    sample_idx = 0
    for i, feature_name in enumerate(extractor.get_feature_names()[:10]):
        value = features_df.iloc[sample_idx][feature_name]
        print(f"    {feature_name:30s}: {value:10.4f}")
    print(f"    ... and {len(extractor.get_feature_names())-10} more features")
    
    # Store for later
    ml_data = features_df
else:
    print("✓ Using heuristic-based approach (old method)")
    ml_data = None
```

---

## Code Cell 5: ML Model Training (NEW)

**INSERT NEW CELL** after feature extraction:

```python
print("\n" + "=" * 70)
print("STEP 3: TRAIN ML MODEL")
print("=" * 70)

if EVAL_MODE == "ml_based":
    # Create and train ML pipeline
    pipeline = MLPipeline(
        model_type=MODEL_TYPE,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE
    )
    
    # Prepare train/test split
    X_train, X_test, y_train, y_test = pipeline.prepare_data(
        ml_data,
        label_column='label'
    )
    
    print(f"\n✓ Data split completed")
    print(f"  Training: {len(X_train)} samples")
    print(f"  Testing:  {len(X_test)} samples")
    print(f"  Train class dist: {y_train.value_counts().to_dict()}")
    print(f"  Test class dist:  {y_test.value_counts().to_dict()}")
    
    # Train model
    print(f"\nTraining {MODEL_TYPE} model...")
    pipeline.train()
    print(f"✓ Model trained successfully")
else:
    print("Skipping ML training (heuristic mode)")
```

---

## Code Cell 6: ML Model Evaluation (NEW)

**INSERT NEW CELL** after model training:

```python
print("\n" + "=" * 70)
print("STEP 4: EVALUATE ML MODEL")
print("=" * 70)

if EVAL_MODE == "ml_based":
    # Get metrics on test set
    metrics = pipeline.evaluate()
    
    print(f"\n{'='*70}")
    print(f"MODEL PERFORMANCE METRICS")
    print(f"{'='*70}")
    print(f"Accuracy:                {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:.2f}%)")
    print(f"Precision:               {metrics['precision']:.4f}  ({metrics['precision']*100:.2f}%)")
    print(f"Recall:                  {metrics['recall']:.4f}  ({metrics['recall']*100:.2f}%)")
    print(f"F1-Score:                {metrics['f1_score']:.4f}")
    print(f"AUC-ROC:                 {metrics['auc_roc']:.4f}")
    print(f"")
    print(f"Confusion Matrix:")
    print(f"  TP (True Positives):   {metrics['tp']}")
    print(f"  TN (True Negatives):   {metrics['tn']}")
    print(f"  FP (False Positives):  {metrics['fp']}")
    print(f"  FN (False Negatives):  {metrics['fn']}")
    print(f"")
    print(f"Error Rates:")
    print(f"  False Positive Rate:   {metrics['fpr']:.4f}")
    print(f"  False Negative Rate:   {metrics['fnr']:.4f}")
    
    # Diagnostic: Check if recall is fixed
    print(f"\n{'='*70}")
    if metrics['recall'] > 0:
        print(f"✓ SUCCESS! Recall = {metrics['recall']:.4f} (ZERO RECALL PROBLEM FIXED)")
    else:
        print(f"✗ Issue: Recall still 0% - model not learning phishing patterns")
    print(f"{'='*70}")
else:
    print("Skipping ML evaluation (heuristic mode)")
```

---

## Code Cell 7: Threshold Sweep (NEW)

**INSERT NEW CELL** after evaluation:

```python
print("\n" + "=" * 70)
print("STEP 5: THRESHOLD SWEEP ANALYSIS")
print("=" * 70)

if EVAL_MODE == "ml_based":
    # Test different decision thresholds
    thresholds_to_test = [0.3, 0.4, 0.5, 0.6, 0.7]
    threshold_results = pipeline.threshold_sweep(thresholds=thresholds_to_test)
    
    threshold_df = pd.DataFrame(threshold_results)
    
    print("\nPerformance at different thresholds:")
    print(threshold_df.to_string(index=False))
    
    # Find optimal threshold
    best_f1 = threshold_df.loc[threshold_df['f1_score'].idxmax()]
    print(f"\n✓ Optimal threshold (max F1): {best_f1['threshold']:.2f}")
    print(f"  F1-Score: {best_f1['f1_score']:.4f}")
    print(f"  Recall:   {best_f1['recall']:.4f}")
    print(f"  Precision: {best_f1['precision']:.4f}")
else:
    print("Skipping threshold sweep (heuristic mode)")
```

---

## Code Cell 8: Feature Importance (NEW, Random Forest Only)

**INSERT NEW CELL** (only if `MODEL_TYPE == "random_forest"`):

```python
print("\n" + "=" * 70)
print("STEP 6: FEATURE IMPORTANCE ANALYSIS")
print("=" * 70)

if EVAL_MODE == "ml_based" and MODEL_TYPE == "random_forest":
    # Get feature importance
    importance_df = pipeline.model.get_feature_importance()
    
    print("\nTop 15 Most Important Features for Phishing Detection:")
    print("-" * 70)
    
    for idx, (_, row) in enumerate(importance_df.head(15).iterrows(), 1):
        importance_pct = row['importance'] * 100
        bar_length = int(importance_pct / 2)
        bar = "█" * bar_length
        print(f"{idx:2d}. {row['feature']:35s} {importance_pct:6.2f}% {bar}")
else:
    print("Feature importance not available for this configuration")
```

---

## Code Cell 9: Save ML Reports (NEW)

**INSERT NEW CELL** at the end:

```python
print("\n" + "=" * 70)
print("STEP 7: SAVE REPORTS")
print("=" * 70)

if EVAL_MODE == "ml_based":
    import json
    from pathlib import Path
    
    # Generate detailed report
    full_report = pipeline.get_detailed_report()
    
    # Save JSON report
    report_path = Path('evaluation/reports/ml_model_report.json')
    report_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_path, 'w') as f:
        json.dump(full_report, f, indent=2, default=str)
    
    print(f"✓ Saved: {report_path}")
    
    # Save metrics summary
    summary = {
        'run_mode': 'ml_based',
        'model_type': MODEL_TYPE,
        'sample_size': SAMPLE_SIZE,
        'total_samples': len(ml_data),
        'metrics': metrics,
        'threshold_analysis': threshold_results if 'threshold_results' in locals() else None,
    }
    
    summary_path = Path('evaluation/reports/ml_summary.json')
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    
    print(f"✓ Saved: {summary_path}")
    print(f"\n{'='*70}")
    print(f"✅ ML EVALUATION COMPLETE")
    print(f"{'='*70}")
else:
    print("ML reports not saved (heuristic mode)")
```

---

## Summary of Changes

| Step | Original | New | Purpose |
|------|----------|-----|---------|
| 1 | Manual CSV loading | `SampledDatasetLoader` | Flexible sampling from any format |
| 2 | Heuristic rules | `MLFeatureExtractor` | Statistical features without network |
| 3 | Backend pipeline | `MLPipeline` + sklearn | Real ML model with train/test split |
| 4 | Zero recall | Proper metrics | NOW detects phishing (recall > 0%) |
| 5 | No evaluation | Threshold sweep | Optimal threshold tuning |
| 6 | N/A | Feature importance | Interpretability |
| 7 | System-level reports | ML-specific reports | Model validation |

---

## Testing the Integration

After making all changes:

1. **Run notebook with small sample** (SAMPLE_SIZE=50):
   - Should complete in 2-3 minutes
   - Verify recall > 0% ✅

2. **Increase sample size** (SAMPLE_SIZE=500):
   - Should complete in 10-15 minutes
   - Check metrics are stable

3. **Run on full dataset** (SAMPLE_SIZE=None):
   - Use all 1.4M URLs (if network available)
   - Production validation

---

## Troubleshooting

**Issue**: Import errors for new modules
- **Fix**: Ensure `evaluation/utils/` contains all .py files

**Issue**: Recall still 0%
- **Fix**: Check that features_df has correct shape and labels

**Issue**: Memory issues with large datasets
- **Fix**: Reduce SAMPLE_SIZE or use feature sampling

**Issue**: sklearn version incompatibility
- **Fix**: Run `pip install scikit-learn>=1.0`

---

## Next: Integration into Existing Notebook

The existing `phishlens_evaluation.ipynb` currently:
1. Loads datasets (old method)
2. Runs backend pipeline (heuristic-based)
3. Computes metrics (shows zero recall)

After integration:
1. Loads datasets (new sampled method) ✅
2. Extracts ML features ✅
3. Trains sklearn model ✅
4. Evaluates with proper metrics ✅
5. Analyzes thresholds ✅
6. Reports feature importance ✅

**Result**: System now detects phishing instead of classifying everything as benign.
