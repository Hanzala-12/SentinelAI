# PhishLens Evaluation Framework

This module provides a reproducible, system-level phishing benchmark pipeline for PhishLens.

## Scope

The evaluation runs URLs through the **real PhishLens pipeline**:

- signal extraction
- URL analysis
- calibration and suppression logic
- attack pattern classification
- reasoning and final risk scoring

It does **not** evaluate isolated model components only.

## Directory Structure

```text
evaluation/
  datasets/      # Input datasets (PhishTank/OpenPhish/benign)
  notebooks/     # Research notebook
  reports/       # Generated benchmark artifacts
  results/       # Row-level result tables
  utils/         # Reusable loaders/metrics/plots/pipeline runner
  run_benchmark.py
```

## Dataset Format

Minimum supported schema (or equivalent URL column names):

```csv
url,label
https://example.com,0
http://phish.example,1
```

Standard labels used internally:

- phishing = `1`
- benign = `0`

## Run Benchmark

From repository root:

```bash
python -m evaluation.run_benchmark ^
  --phishtank evaluation/datasets/phishtank.csv ^
  --openphish evaluation/datasets/openphish.csv ^
  --benign evaluation/datasets/benign_tranco.csv ^
  --threshold 40 ^
  --thresholds 20,30,40,50,60 ^
  --batch-size 16 ^
  --timeout-seconds 45
```

## Generated Outputs

Required report artifacts are written to `evaluation/reports/`:

- `evaluation_report.json`
- `evaluation_summary.csv`
- `confusion_matrix.png`
- `threshold_analysis.png`

Additional exports:

- `score_distribution.png`
- `attack_pattern_frequency.png`
- `evaluation/results/evaluation_records.csv`
- `evaluation/results/false_positives.csv`
- `evaluation/results/false_negatives.csv`

## Notebook

Use:

`evaluation/notebooks/phishlens_evaluation.ipynb`

The notebook is structured in 10 sections for academic presentation, including false positive/negative investigation and threshold analysis.

