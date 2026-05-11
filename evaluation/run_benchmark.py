from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from evaluation.utils.unified_loader import load_all_datasets
from evaluation.utils.metrics import (
    confusion_matrix_at_threshold,
    false_negative_rows,
    false_positive_rows,
    metrics_at_threshold,
    threshold_sweep,
)
from evaluation.utils.pipeline_runner import evaluate_dataset
from evaluation.utils.plots import (
    plot_attack_pattern_frequency,
    plot_confusion_matrix,
    plot_score_distribution,
    plot_threshold_analysis,
)


logger = logging.getLogger("evaluation")


def parse_thresholds(raw: str) -> list[int]:
    values = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        values.append(int(token))
    if not values:
        raise ValueError("Threshold list is empty.")
    return values


def _frame_stats(frame: pd.DataFrame) -> dict[str, Any]:
    return {
        "rows": int(len(frame)),
        "label_distribution": {
            "benign_0": int((frame["label"] == 0).sum()) if "label" in frame else 0,
            "phishing_1": int((frame["label"] == 1).sum()) if "label" in frame else 0,
        },
        "source_distribution": frame["source"].value_counts().to_dict() if "source" in frame else {},
    }


def _serialize_record_preview(frame: pd.DataFrame, limit: int = 25) -> list[dict[str, Any]]:
    if frame.empty:
        return []
    subset = frame.head(limit).copy()
    for column in ("attack_patterns", "evidence_codes", "reasoning_chain"):
        if column in subset.columns:
            subset[column] = subset[column].apply(lambda x: x if isinstance(x, list) else [])
    return subset.to_dict(orient="records")


def run(args: argparse.Namespace) -> dict[str, Any]:
    os.environ.setdefault("SENTINELAI_OFFLINE_EVAL", "1")

    merged, summaries = load_all_datasets(Path(args.datasets_dir))
    if merged.empty:
        raise ValueError(f"No datasets loaded from {args.datasets_dir}")

    if args.max_samples_per_source > 0:
        merged = (
            merged.groupby("source_dataset", group_keys=False)
            .head(args.max_samples_per_source)
            .reset_index(drop=True)
        )

    logger.info("Evaluation dataset prepared with %d rows.", len(merged))
    if "source" not in merged.columns:
        merged["source"] = merged["source_dataset"]

    records, runtime_summary = evaluate_dataset(
        merged,
        threshold=args.threshold,
        timeout_seconds=args.timeout_seconds,
        batch_size=args.batch_size,
        disable_interaction=args.disable_interaction,
        show_progress=not args.no_progress,
    )

    metrics = metrics_at_threshold(records, args.threshold)
    thresholds = parse_thresholds(args.thresholds)
    threshold_df = threshold_sweep(records, thresholds)
    confusion = confusion_matrix_at_threshold(records, args.threshold)
    fp_rows = false_positive_rows(records, args.threshold)
    fn_rows = false_negative_rows(records, args.threshold)

    reports_dir = Path(args.reports_dir)
    results_dir = Path(args.results_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    records.to_csv(results_dir / "evaluation_records.csv", index=False)
    records.to_json(results_dir / "evaluation_records.jsonl", orient="records", lines=True)

    threshold_df.to_csv(results_dir / "threshold_metrics.csv", index=False)
    fp_rows.to_csv(results_dir / "false_positives.csv", index=False)
    fn_rows.to_csv(results_dir / "false_negatives.csv", index=False)

    plot_confusion_matrix(confusion, reports_dir / "confusion_matrix.png")
    plot_threshold_analysis(threshold_df, reports_dir / "threshold_analysis.png")
    plot_score_distribution(records, reports_dir / "score_distribution.png")
    plot_attack_pattern_frequency(records, reports_dir / "attack_pattern_frequency.png")

    summary_row = {
        "run_utc": datetime.now(timezone.utc).isoformat(),
        "threshold": args.threshold,
        **metrics.to_dict(),
        **runtime_summary,
        "evaluated_rows": int(len(records)),
        "valid_metric_rows": int(records["risk_score"].notna().sum()),
        "false_positive_count": int(len(fp_rows)),
        "false_negative_count": int(len(fn_rows)),
    }
    pd.DataFrame([summary_row]).to_csv(reports_dir / "evaluation_summary.csv", index=False)

    report = {
        "run_metadata": {
            "run_utc": datetime.now(timezone.utc).isoformat(),
            "threshold": args.threshold,
            "threshold_grid": thresholds,
            "batch_size": args.batch_size,
            "timeout_seconds": args.timeout_seconds,
            "disable_interaction": args.disable_interaction,
            "random_seed": args.random_seed,
        },
        "dataset_overview": _frame_stats(merged),
        "dataset_inventory": [
            {
                "dataset_name": s.dataset_name,
                "source_file": s.source_file,
                "rows": s.rows,
                "invalid_rows": s.invalid_rows,
                "duplicate_rows": s.duplicate_rows,
            }
            for s in summaries
        ],
        "dataset_quality": {
            "total_input_rows": sum(s.rows for s in summaries),
            "total_invalid": sum(s.invalid_rows for s in summaries),
            "total_duplicates": sum(s.duplicate_rows for s in summaries),
        },
        "runtime_summary": runtime_summary,
        "metrics": metrics.to_dict(),
        "threshold_metrics": threshold_df.to_dict(orient="records"),
        "false_positive_samples": _serialize_record_preview(fp_rows, limit=30),
        "false_negative_samples": _serialize_record_preview(fn_rows, limit=30),
    }
    (reports_dir / "evaluation_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run SentinelAI system-level phishing benchmark evaluation.")
    parser.add_argument("--datasets-dir", type=str, default="evaluation/datasets")
    parser.add_argument("--results-dir", type=str, default="evaluation/results")
    parser.add_argument("--reports-dir", type=str, default="evaluation/reports")
    parser.add_argument("--threshold", type=int, default=40)
    parser.add_argument("--thresholds", type=str, default="20,30,40,50,60")
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    parser.add_argument("--max-samples-per-source", type=int, default=0)
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--disable-interaction", action="store_true")
    parser.add_argument("--no-progress", action="store_true")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    report = run(args)
    logger.info("Benchmark completed. Samples evaluated: %s", report["dataset_overview"]["rows"])
    logger.info("Primary metrics: %s", report["metrics"])
    logger.info("Reports written to: %s", args.reports_dir)


if __name__ == "__main__":
    main()

