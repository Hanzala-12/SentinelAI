# PhishLens ML Phishing Detection Evaluation Report

**Project:** PhishLens

**Date:** May 11, 2026

**Prepared for:** Submission / Technical Review

---

## Executive Summary

This report documents the completed PhishLens notebook-based machine learning evaluation pipeline for phishing detection. The system was upgraded from a weak heuristic-only flow to an offline-capable ML pipeline using 40 extracted URL features and a Random Forest classifier.

The notebook now runs end-to-end and demonstrates strong phishing detection behavior on the sampled evaluation set. The model achieved **92.0% recall**, correcting the prior zero-recall failure mode.

### Key Results

| Metric | Value |
|---|---:|
| Accuracy | 78.9% |
| Precision | 79.3% |
| Recall | 92.0% |
| F1-Score | 0.8519 |
| AUC-ROC | 0.9477 |
| True Positives | 23 |
| True Negatives | 7 |
| False Positives | 6 |
| False Negatives | 2 |

### Outcome

The revised pipeline now detects phishing URLs reliably in offline mode, produces interpretable feature importance outputs, and generates reproducible evaluation artifacts suitable for review.

---

## 1. Problem Statement

The original PhishLens evaluation flow suffered from a critical detection failure:

- offline mode disabled WHOIS and web-page fetching
- the remaining heuristic signals were too weak
- the system collapsed toward safe classifications
- phishing recall was effectively zero in the earlier benchmark

This made the system unsuitable for dependable phishing screening under offline or constrained environments.

---

## 2. Objectives

The upgrade was designed to achieve the following:

1. Restore meaningful phishing detection under offline conditions.
2. Replace brittle heuristic dependence with learning-based classification.
3. Add real phishing-oriented URL features.
4. Support scalable dataset sampling for large corpora.
5. Produce notebook-ready metrics, plots, and submission-grade outputs.

---

## 3. Solution Overview

The final notebook implements a three-part ML pipeline:

### 3.1 Dataset Loading

A sampled loader reads the available evaluation corpora and builds a balanced training corpus from large sources.

Observed notebook sample:

- **Total URLs loaded:** 150
- **Phishing URLs:** 100
- **Benign URLs:** 50
- **Class balance:** 66.7% phishing / 33.3% benign

### 3.2 Feature Engineering

The pipeline extracts **40 URL-level features** without network access, including:

- URL length and entropy
- digit, slash, dot, hyphen, and special-character ratios
- domain length and domain entropy
- subdomain depth and host structure
- suspicious TLD and legitimate TLD indicators
- phishing keyword and brand impersonation signals
- obfuscation and redirect-pattern checks

These features are designed to capture common phishing URL patterns while staying fully offline.

### 3.3 Model Training

The notebook trains a **Random Forest** model using a stratified train/test split.

Model characteristics:

- offline-only operation
- probability-aware prediction output
- feature importance support
- stratified train/test splitting
- reproducible evaluation path

---

## 4. Notebook Execution Flow

The final notebook is organized into a clear sequence:

1. Set the working directory and import dependencies.
2. Load the sampled dataset.
3. Extract ML features.
4. Prepare the train/test split.
5. Train the Random Forest model.
6. Evaluate performance metrics.
7. Visualize confusion matrix and metric scores.
8. Inspect feature importance.
9. Summarize the final results.

This notebook now executes successfully end to end.

---

## 5. Evaluation Results

### 5.1 Classification Performance

The evaluation run produced the following results on the held-out test set:

- **Accuracy:** 78.9%
- **Precision:** 79.3%
- **Recall:** 92.0%
- **F1-Score:** 0.8519
- **AUC-ROC:** 0.9477

### 5.2 Confusion Matrix

|  | Predicted Benign | Predicted Phishing |
|---|---:|---:|
| **Actual Benign** | 7 | 6 |
| **Actual Phishing** | 2 | 23 |

### 5.3 Interpretation

The key success criterion was recall, since the original failure mode was that phishing URLs were not being detected at all. The new result shows that the classifier now identifies the majority of phishing URLs correctly.

Residual tradeoff:

- The false positive rate is not negligible in this small sample.
- That is acceptable for a first-pass detector, but threshold tuning or more training data would likely improve precision.

---

## 6. Feature Importance Findings

The Random Forest model highlighted the following as the most important features:

1. `path_length`
2. `tld_legitimate`
3. `url_length`
4. `url_entropy_normalized`
5. `url_slash_count`
6. `domain_length_normalized`
7. `url_entropy`
8. `url_length_normalized`
9. `domain_entropy`
10. `domain_length`

### Interpretation

These results are consistent with phishing behavior:

- suspicious URLs often contain long or obfuscated paths
- phishing campaigns frequently use unusual domain structures
- entropy and path structure are useful signals of automation and evasion

---

## 7. Deliverables Produced

The following notebook artifacts were produced during the implementation:

- ML feature extraction notebook cells
- train/test split and model training logic
- metrics calculation and confusion matrix
- threshold and performance visualizations
- feature importance analysis
- final summary output

Supporting code modules also exist in the repository:

- `evaluation/utils/ml_feature_extractor.py`
- `evaluation/utils/ml_model.py`
- `evaluation/utils/sampled_dataset_loader.py`

---

## 8. Limitations

This submission reflects the notebook sample used during validation, not a full production-scale benchmark.

Important limitations:

- the current evaluation used a sampled dataset, not the full corpus
- performance may shift with larger and more diverse data
- the false positive rate should be rechecked at scale
- model calibration should be revisited before deployment

---

## 9. Recommendations

Before production use, the following should be considered:

1. Increase sample size to test stability at larger scale.
2. Tune the classification threshold for precision/recall balance.
3. Validate on a larger held-out benchmark.
4. Save the trained model artifact for reproducible deployment.
5. Continue monitoring feature importance for drift or overfitting.

---

## Conclusion

The PhishLens notebook now demonstrates a functional offline phishing detection pipeline with strong recall and a clear feature-based explanation layer. The original zero-recall issue has been resolved by replacing the weak heuristic reliance with an offline ML pipeline built from real URL features.

**Final status:** ready for review, further scaling, and submission packaging.
