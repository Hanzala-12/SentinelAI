from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.services.analysis_service import AnalysisService


CLASS_ORDER = {"Safe": 0, "Suspicious": 1, "Dangerous": 2, "Critical": 3}


@dataclass(slots=True)
class CorpusItem:
    id: str
    label: str
    category: str
    url: str
    text: str
    html: str
    expected_patterns: list[str]
    expected_classification_min: str | None = None
    expected_classification_max: str | None = None


def load_corpus(path: Path) -> list[CorpusItem]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [
        CorpusItem(
            id=item["id"],
            label=item["label"],
            category=item["category"],
            url=item.get("url", ""),
            text=item.get("text", ""),
            html=item.get("html", ""),
            expected_patterns=item.get("expected_patterns", []),
            expected_classification_min=item.get("expected_classification_min"),
            expected_classification_max=item.get("expected_classification_max"),
        )
        for item in payload
    ]


def evaluate(corpus: list[CorpusItem], *, disable_interaction: bool = False) -> dict[str, Any]:
    service = AnalysisService()
    if disable_interaction:
        service.interaction_simulator.enabled = False
    rows: list[dict[str, Any]] = []
    noisy_signal_counter: Counter[str] = Counter()
    benign_high_signals: Counter[str] = Counter()
    pattern_match_counter: Counter[str] = Counter()
    confusion = Counter({"tp": 0, "tn": 0, "fp": 0, "fn": 0})

    for item in corpus:
        result = service.scan_text(
            text=item.text,
            url=item.url or None,
            page_html=item.html or None,
        )
        classification = result.classification
        predicted_malicious = CLASS_ORDER.get(classification, 0) >= CLASS_ORDER["Suspicious"]
        is_malicious = item.label == "malicious"
        if is_malicious and predicted_malicious:
            confusion["tp"] += 1
        elif is_malicious and not predicted_malicious:
            confusion["fn"] += 1
        elif not is_malicious and predicted_malicious:
            confusion["fp"] += 1
        else:
            confusion["tn"] += 1

        evidence_codes = [signal.code for signal in (result.threat_report.evidence if result.threat_report else [])]
        for signal in (result.threat_report.evidence if result.threat_report else []):
            if item.label == "benign" and signal.severity in {"high", "critical"}:
                benign_high_signals[signal.code] += 1
            if item.label != "malicious" and signal.score_impact <= 10:
                noisy_signal_counter[signal.code] += 1

        predicted_patterns = [pattern.code for pattern in (result.threat_report.attack_patterns if result.threat_report else [])]
        expected_patterns = set(item.expected_patterns)
        matched_patterns = sorted(expected_patterns & set(predicted_patterns))
        for code in matched_patterns:
            pattern_match_counter[code] += 1

        min_ok = True
        max_ok = True
        if item.expected_classification_min:
            min_ok = CLASS_ORDER.get(classification, 0) >= CLASS_ORDER.get(item.expected_classification_min, 0)
        if item.expected_classification_max:
            max_ok = CLASS_ORDER.get(classification, 0) <= CLASS_ORDER.get(item.expected_classification_max, 0)

        suppression_records = []
        if result.technical_findings:
            suppression_records = result.technical_findings.metadata.get("suppressed_detections", [])

        rows.append(
            {
                "id": item.id,
                "label": item.label,
                "category": item.category,
                "risk_score": result.risk_score,
                "classification": classification,
                "confidence": result.confidence,
                "expected_patterns": item.expected_patterns,
                "predicted_patterns": predicted_patterns,
                "matched_patterns": matched_patterns,
                "classification_expectation_met": bool(min_ok and max_ok),
                "evidence_codes": evidence_codes,
                "suppressed_detections": suppression_records,
                "interaction_event_count": len(result.technical_findings.interaction_events) if result.technical_findings else 0,
                "narrative_coercion_score": (
                    result.threat_report.social_engineering_analysis.get("coercion_score")
                    if result.threat_report
                    else None
                ),
            }
        )

    by_label_scores: dict[str, list[int]] = defaultdict(list)
    by_label_conf: dict[str, list[float]] = defaultdict(list)
    expectation_pass = 0
    for row in rows:
        by_label_scores[row["label"]].append(row["risk_score"])
        by_label_conf[row["label"]].append(row["confidence"])
        if row["classification_expectation_met"]:
            expectation_pass += 1

    def avg(values: list[float]) -> float:
        if not values:
            return 0.0
        return round(sum(values) / len(values), 3)

    threshold_grid = [25, 35, 45, 55, 65, 75]
    threshold_metrics = []
    for threshold in threshold_grid:
        grid_confusion = Counter({"tp": 0, "tn": 0, "fp": 0, "fn": 0})
        for row in rows:
            pred_malicious = row["risk_score"] >= threshold
            truth_malicious = row["label"] == "malicious"
            if truth_malicious and pred_malicious:
                grid_confusion["tp"] += 1
            elif truth_malicious and not pred_malicious:
                grid_confusion["fn"] += 1
            elif not truth_malicious and pred_malicious:
                grid_confusion["fp"] += 1
            else:
                grid_confusion["tn"] += 1
        precision = grid_confusion["tp"] / max(1, grid_confusion["tp"] + grid_confusion["fp"])
        recall = grid_confusion["tp"] / max(1, grid_confusion["tp"] + grid_confusion["fn"])
        threshold_metrics.append(
            {
                "threshold": threshold,
                "tp": grid_confusion["tp"],
                "fp": grid_confusion["fp"],
                "tn": grid_confusion["tn"],
                "fn": grid_confusion["fn"],
                "precision": round(precision, 3),
                "recall": round(recall, 3),
            }
        )

    summary = {
        "run_utc": datetime.now(timezone.utc).isoformat(),
        "sample_count": len(rows),
        "confusion_matrix": dict(confusion),
        "expectation_pass_rate": round(expectation_pass / max(1, len(rows)), 3),
        "average_risk_by_label": {label: avg(scores) for label, scores in by_label_scores.items()},
        "average_confidence_by_label": {label: avg(confs) for label, confs in by_label_conf.items()},
        "top_benign_high_severity_signals": benign_high_signals.most_common(10),
        "top_noisy_low_impact_signals": noisy_signal_counter.most_common(10),
        "pattern_match_coverage": dict(pattern_match_counter),
        "threshold_metrics": threshold_metrics,
        "interaction_relevance": {
            "malicious_with_interaction_findings": sum(
                1
                for row in rows
                if row["label"] == "malicious" and row["interaction_event_count"] > 0
            ),
            "benign_with_interaction_findings": sum(
                1
                for row in rows
                if row["label"] == "benign" and row["interaction_event_count"] > 0
            ),
        },
        "escalation_quality": {
            "malicious_avg_class_rank": avg(
                [CLASS_ORDER.get(row["classification"], 0) for row in rows if row["label"] == "malicious"]
            ),
            "benign_avg_class_rank": avg(
                [CLASS_ORDER.get(row["classification"], 0) for row in rows if row["label"] == "benign"]
            ),
            "ambiguous_avg_class_rank": avg(
                [CLASS_ORDER.get(row["classification"], 0) for row in rows if row["label"] == "ambiguous"]
            ),
        },
    }

    return {"summary": summary, "rows": rows}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PhishLens corpus calibration evaluation.")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("backend/intelligence/calibration/corpus_v1.json"),
        help="Path to corpus JSON file.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("backend/intelligence/calibration/reports/evaluation_report.json"),
        help="Path to write structured evaluation output.",
    )
    parser.add_argument(
        "--disable-interaction",
        action="store_true",
        help="Disable interaction simulation during evaluation.",
    )
    args = parser.parse_args()

    corpus = load_corpus(args.corpus)
    report = evaluate(corpus, disable_interaction=args.disable_interaction)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote evaluation report to {args.out}")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
