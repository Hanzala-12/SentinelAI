from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score


@dataclass(slots=True)
class EvaluationMetrics:
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    tp: int
    fp: int
    tn: int
    fn: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
        }


def _valid_rows(results: pd.DataFrame) -> pd.DataFrame:
    return results[(results["true_label"].isin([0, 1])) & (results["risk_score"].notna())].copy()


def metrics_at_threshold(results: pd.DataFrame, threshold: int) -> EvaluationMetrics:
    valid = _valid_rows(results)
    if valid.empty:
        return EvaluationMetrics(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    y_true = valid["true_label"].astype(int).to_numpy()
    y_pred = (valid["risk_score"].astype(float).to_numpy() >= float(threshold)).astype(int)

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    accuracy = accuracy_score(y_true, y_pred)
    fpr = fp / max(1, fp + tn)
    fnr = fn / max(1, fn + tp)

    return EvaluationMetrics(
        accuracy=round(float(accuracy), 4),
        precision=round(float(precision), 4),
        recall=round(float(recall), 4),
        f1_score=round(float(f1), 4),
        false_positive_rate=round(float(fpr), 4),
        false_negative_rate=round(float(fnr), 4),
        tp=int(tp),
        fp=int(fp),
        tn=int(tn),
        fn=int(fn),
    )


def threshold_sweep(results: pd.DataFrame, thresholds: list[int]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for threshold in thresholds:
        metrics = metrics_at_threshold(results, threshold)
        rows.append(
            {
                "threshold": int(threshold),
                **metrics.to_dict(),
            }
        )
    return pd.DataFrame(rows)


def confusion_matrix_at_threshold(results: pd.DataFrame, threshold: int) -> np.ndarray:
    valid = _valid_rows(results)
    if valid.empty:
        return np.array([[0, 0], [0, 0]], dtype=int)
    y_true = valid["true_label"].astype(int).to_numpy()
    y_pred = (valid["risk_score"].astype(float).to_numpy() >= float(threshold)).astype(int)
    return confusion_matrix(y_true, y_pred, labels=[0, 1])


def false_positive_rows(results: pd.DataFrame, threshold: int) -> pd.DataFrame:
    valid = _valid_rows(results)
    return valid[(valid["true_label"] == 0) & (valid["risk_score"] >= threshold)].copy()


def false_negative_rows(results: pd.DataFrame, threshold: int) -> pd.DataFrame:
    valid = _valid_rows(results)
    return valid[(valid["true_label"] == 1) & (valid["risk_score"] < threshold)].copy()

