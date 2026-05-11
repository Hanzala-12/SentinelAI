# PhishLens Local Model Artifacts

This directory now contains deterministic, offline-loadable model artifacts used by analysis services.

## URL Model

- Path: `backend/models/url/phishing_url_model_v1.pkl`
- Metadata: `backend/models/url/phishing_url_model_v1.json`
- Loader: `backend/ai_engine/phishing_url_model.py`
- Runtime behavior:
  - Local artifact only.
  - No runtime remote download.
  - Graceful heuristic fallback with explicit runtime issue signaling.

## NLP Model

- Path: `backend/models/nlp/distilbert-scam-detector/`
- Manifest: `backend/models/nlp/distilbert-scam-detector/model_manifest.json`
- Loader: `backend/ai_engine/text_analyzer.py`
- Runtime behavior:
  - Local model directory only (`local_files_only`).
  - CPU inference with deterministic settings when `torch` is available.
  - Rule-based fallback with explicit runtime warning signals when local inference is unavailable.

