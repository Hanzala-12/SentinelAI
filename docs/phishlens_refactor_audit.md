# PhishLens Refactor Audit (May 11, 2026)

## Initial Architecture Weaknesses

1. **Scoring pipeline was linear and opaque**
- Risk score was a fixed weighted sum of coarse outputs (`phishing`, `nlp`, `reputation`, `privacy`).
- No explicit threat reasoning chain, no transparent component attribution, and no evidence hierarchy.

2. **Signal extraction depth was inconsistent**
- URL checks existed, but were mixed with model extraction internals and legacy feature logic.
- DOM/behavioral checks were limited and not represented as first-class structured signals.
- Content analysis relied mainly on token matching and sentiment fallback.

3. **Threat-intel integration produced misleading signals**
- Provider “configured” status was emitted as detected issues, which polluted findings.
- Reputation scoring granted risk points for successful API calls even without malicious evidence.

4. **Explainability lacked SOC-grade output structure**
- Single explanation paragraph with minimal context.
- No explicit recommended actions, no component risk decomposition, and no technical report payload.

5. **Frontend was dashboard-centric rather than investigation-centric**
- UI mixed trends/settings themes with less emphasis on investigation workflow.
- No dedicated technical evidence page exposing structured signal findings.

## Refactor Changes Implemented

### 1) Modular Threat Intelligence Core

Added `backend/intelligence/`:
- `signal_extractor.py`: structured URL, DOM, and content signal extraction
- `reasoning_engine.py`: configurable weighted threat reasoning engine
- `models.py`: evidence and reasoning data contracts

### 2) First-Class Signal Extraction

Implemented URL signals:
- suspicious/abuse-prone TLD detection
- excessive subdomain depth
- hostname entropy
- typosquatting/brand lookalike cues
- IP-host URLs
- shortener detection
- suspicious query parameter profiling
- Unicode/Punycode spoofing risk
- encoded payload and obfuscation cues

Implemented DOM/HTML signals:
- credential form behavior (blank actions, external submissions, HTTP downgrade)
- hidden credential forms
- iframe abuse/invisible iframes
- meta/scripted redirect cues
- obfuscated JavaScript indicators
- high external script ratios
- brand impersonation content cues
- excessive hidden element patterns

Implemented content signals:
- urgency pressure language
- scare tactic wording
- reward lure patterns
- credential verification requests
- billing/payment pressure language
- impersonation language markers

### 3) Configurable Threat Reasoning Engine

Added weighted component model:
- `phishing_probability` (default 0.30)
- `dom_suspicion` (default 0.25)
- `content_scam_score` (default 0.20)
- `reputation_score` (default 0.15)
- `redirect_risk` (default 0.10)

Outputs include:
- final score and classification
- component scores and weighted contributions
- ranked evidence list
- reason chain
- recommended actions
- indicator grouping and signal counts

Weights are now configurable from settings/environment:
- `REASON_WEIGHT_PHISHING_PROBABILITY`
- `REASON_WEIGHT_DOM_SUSPICION`
- `REASON_WEIGHT_CONTENT_SCAM_SCORE`
- `REASON_WEIGHT_REPUTATION_SCORE`
- `REASON_WEIGHT_REDIRECT_RISK`

### 4) Explainability + Report Layer

Refactored explainability service to emit:
- concise analyst summary
- pattern identifiers
- structured threat report
- technical findings payload (URL/DOM/content/reputation/model signal groups)

API response now carries:
- `threat_report`
- `technical_findings`

while preserving:
- `risk_score`
- `classification`
- `detected_issues`
- `explanation`

### 5) Threat Intel Quality Corrections

Refactored `ThreatIntelService`:
- removed misleading “provider configured” issues
- provider findings now record verdict/score/confidence/summary
- reputation score is based on malicious evidence, not just API availability
- AbuseIPDB queries now run on resolved IPs instead of raw hostnames where possible

### 6) Frontend Workflow Refactor

Dashboard is now investigation-oriented with four focused pages:
1. **Home**: URL submission and quick analysis
2. **Threat Report**: reasoning chain, evidence, actions, AI enrichment
3. **History**: searchable/filterable scan records
4. **Technical Analysis**: raw signal categories and component breakdown

Design direction was changed to a professional SOC-style light interface with evidence-focused panels.

### 7) Extension Context Improvement

Extension now sends both:
- extracted page text
- raw page HTML (truncated)

to support stronger DOM/behavioral analysis server-side.

## Known Residual Gaps

1. **Transformer runtime dependency**
- If PyTorch is unavailable, NLP model inference falls back to heuristic language scoring (handled gracefully).

2. **Pretrained URL model artifact**
- Current remote default model URL may fail at runtime and fallback to heuristic mode.
- Recommendation: ship a pinned local model artifact or validated hosted model endpoint.

3. **Persistence depth**
- Scan history currently stores summary and issue fields, not full threat report snapshots.
- Recommendation: persist full `threat_report` + `technical_findings` JSON for forensic replay.

## Next Engineering Steps (Suggested)

1. Add persistence model/repository for full threat report snapshots.
2. Add asynchronous DOM fetch/sandbox pipeline for safer and richer behavioral analysis.
3. Add deterministic unit tests for signal extraction and reasoning weighting.
4. Add provider-level confidence calibration and explainable reputation timeline.
