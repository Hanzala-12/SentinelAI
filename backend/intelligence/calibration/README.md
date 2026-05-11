# PhishLens Calibration Workflow

This directory contains corpus-driven calibration assets used to harden phishing detection quality.

## Corpus

- `corpus_v1.json` includes malicious, benign, and ambiguous web-flow samples:
  - phishing credential harvest pages
  - redirect-based scam flows
  - notification abuse scams
  - benign OAuth/SSO flows
  - benign MFA/login pages
  - benign popups and marketing urgency edge cases

## Evaluation Runner

Run:

```powershell
.\.venv\Scripts\python -m backend.intelligence.calibration.run_evaluation
```

Optional static-only run:

```powershell
.\.venv\Scripts\python -m backend.intelligence.calibration.run_evaluation --disable-interaction
```

Outputs:

- `backend/intelligence/calibration/reports/evaluation_report.json`

Report includes:

- confusion matrix (TP/TN/FP/FN)
- expectation pass rate
- average risk and confidence by label
- high-severity signals on benign pages (false-positive hotspots)
- low-impact noisy signal frequency
- attack-pattern match coverage
- per-sample suppression notes and interaction-event counts

