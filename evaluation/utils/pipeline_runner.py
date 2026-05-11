from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

import pandas as pd

from backend.services.analysis_service import AnalysisService

try:
    from tqdm import tqdm
except Exception:  # pragma: no cover - tqdm is optional fallback
    tqdm = None


logger = logging.getLogger(__name__)

CLASS_ORDER = {"Safe": 0, "Suspicious": 1, "Dangerous": 2, "Critical": 3}


@dataclass(slots=True)
class EvaluationRecord:
    index: int
    url: str
    true_label: int
    source: str
    status: str
    error: str | None
    duration_seconds: float
    timeout_exceeded: bool
    risk_score: int | None
    predicted_classification: str | None
    predicted_label: int | None
    confidence: float | None
    attack_patterns: list[str]
    evidence_codes: list[str]
    suppressed_detection_count: int
    reasoning_chain: list[str]
    explanation: str | None


def _iter_rows(frame: pd.DataFrame, *, show_progress: bool):
    iterator = frame.itertuples(index=False)
    if show_progress and tqdm is not None:
        return tqdm(iterator, total=len(frame), desc="Evaluating URLs", unit="url")
    return iterator


def _predict_binary(classification: str | None, risk_score: int | None, threshold: int) -> int | None:
    if risk_score is not None:
        return int(risk_score >= threshold)
    if classification is None:
        return None
    return int(CLASS_ORDER.get(classification, 0) >= CLASS_ORDER["Suspicious"])


def evaluate_dataset(
    dataset: pd.DataFrame,
    *,
    threshold: int = 40,
    timeout_seconds: float = 45.0,
    batch_size: int = 16,
    disable_interaction: bool = False,
    show_progress: bool = True,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """
    Execute a full SentinelAI system-level evaluation over URL data.
    """
    service = AnalysisService()
    if disable_interaction:
        service.interaction_simulator.enabled = False

    if dataset.empty:
        return pd.DataFrame(), {
            "run_utc": datetime.now(timezone.utc).isoformat(),
            "sample_count": 0,
            "success_count": 0,
            "failure_count": 0,
            "timeout_exceeded_count": 0,
            "total_runtime_seconds": 0.0,
            "average_runtime_seconds": 0.0,
            "batch_size": batch_size,
            "threshold": threshold,
        }

    records: list[EvaluationRecord] = []
    started = time.perf_counter()
    timeout_exceeded_count = 0
    success_count = 0
    failure_count = 0

    # Iterate in batches for predictable progress and controllable pacing.
    for batch_start in range(0, len(dataset), max(1, batch_size)):
        batch = dataset.iloc[batch_start : batch_start + batch_size]
        for row in _iter_rows(batch, show_progress=show_progress):
            row_started = time.perf_counter()
            status = "ok"
            error: str | None = None
            risk_score: int | None = None
            classification: str | None = None
            confidence: float | None = None
            attack_patterns: list[str] = []
            evidence_codes: list[str] = []
            suppressed_detection_count = 0
            reasoning_chain: list[str] = []
            explanation: str | None = None

            try:
                response = service.scan_url(row.url)
                risk_score = int(response.risk_score)
                classification = response.classification
                confidence = float(response.confidence)
                explanation = response.explanation.explanation
                if response.threat_report:
                    attack_patterns = [pattern.code for pattern in response.threat_report.attack_patterns]
                    evidence_codes = [item.code for item in response.threat_report.evidence]
                    reasoning_chain = list(response.threat_report.reasoning_chain)
                if response.technical_findings:
                    suppressed = response.technical_findings.metadata.get("suppressed_detections", [])
                    suppressed_detection_count = len(suppressed) if isinstance(suppressed, list) else 0
                success_count += 1
            except Exception as exc:  # pragma: no cover - network/runtime failures are expected during evaluation
                status = "error"
                error = str(exc)
                failure_count += 1
                logger.warning("Evaluation error for URL '%s': %s", row.url, exc)

            duration_seconds = round(time.perf_counter() - row_started, 4)
            timeout_exceeded = duration_seconds > timeout_seconds
            if timeout_exceeded:
                timeout_exceeded_count += 1
                if status == "ok":
                    status = "timeout_exceeded"

            predicted_label = _predict_binary(classification, risk_score, threshold)
            record = EvaluationRecord(
                index=int(getattr(row, "Index", len(records))),
                url=row.url,
                true_label=int(row.label),
                source=row.source,
                status=status,
                error=error,
                duration_seconds=duration_seconds,
                timeout_exceeded=timeout_exceeded,
                risk_score=risk_score,
                predicted_classification=classification,
                predicted_label=predicted_label,
                confidence=confidence,
                attack_patterns=attack_patterns,
                evidence_codes=evidence_codes,
                suppressed_detection_count=suppressed_detection_count,
                reasoning_chain=reasoning_chain,
                explanation=explanation,
            )
            records.append(record)

    total_runtime_seconds = round(time.perf_counter() - started, 3)
    frame = pd.DataFrame([asdict(record) for record in records])
    summary = {
        "run_utc": datetime.now(timezone.utc).isoformat(),
        "sample_count": int(len(records)),
        "success_count": int(success_count),
        "failure_count": int(failure_count),
        "timeout_exceeded_count": int(timeout_exceeded_count),
        "total_runtime_seconds": total_runtime_seconds,
        "average_runtime_seconds": round(total_runtime_seconds / max(1, len(records)), 4),
        "batch_size": int(batch_size),
        "threshold": int(threshold),
    }
    return frame, summary

