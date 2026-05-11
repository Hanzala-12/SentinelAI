from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


sns.set_theme(style="whitegrid", context="notebook")


def plot_confusion_matrix(confusion, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(5.2, 4.3))
    sns.heatmap(
        confusion,
        annot=True,
        fmt="d",
        cmap="Blues",
        cbar=False,
        xticklabels=["Predicted Benign", "Predicted Phishing"],
        yticklabels=["Actual Benign", "Actual Phishing"],
        ax=ax,
    )
    ax.set_title("PhishLens Confusion Matrix")
    plt.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def plot_threshold_analysis(threshold_df: pd.DataFrame, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(7.4, 4.4))
    ax.plot(threshold_df["threshold"], threshold_df["precision"], marker="o", label="Precision")
    ax.plot(threshold_df["threshold"], threshold_df["recall"], marker="o", label="Recall")
    ax.plot(threshold_df["threshold"], threshold_df["f1_score"], marker="o", label="F1")
    ax.set_xlabel("Risk Threshold")
    ax.set_ylabel("Score")
    ax.set_title("Threshold Performance Analysis")
    ax.set_ylim(0.0, 1.02)
    ax.legend()
    plt.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def plot_score_distribution(results: pd.DataFrame, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    frame = results[results["risk_score"].notna()].copy()
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    if frame.empty:
        ax.text(0.5, 0.5, "No valid risk scores available.", ha="center", va="center", fontsize=11)
        ax.set_axis_off()
    else:
        frame["label_name"] = frame["true_label"].map({0: "Benign", 1: "Phishing"})
        sns.histplot(
            data=frame,
            x="risk_score",
            hue="label_name",
            kde=True,
            bins=24,
            element="step",
            stat="count",
            common_norm=False,
            ax=ax,
        )
        ax.set_xlabel("Risk Score")
        ax.set_ylabel("Count")
        ax.set_title("Risk Score Distribution by Ground Truth Label")
    plt.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def plot_attack_pattern_frequency(results: pd.DataFrame, output_path: str | Path, *, top_n: int = 12) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    expanded: list[str] = []
    for row in results["attack_patterns"].tolist():
        if isinstance(row, list):
            expanded.extend([item for item in row if isinstance(item, str) and item.strip()])
    fig, ax = plt.subplots(figsize=(7.6, 4.8))
    if not expanded:
        ax.text(0.5, 0.5, "No attack pattern detections available.", ha="center", va="center", fontsize=11)
        ax.set_axis_off()
    else:
        counts = (
            pd.Series(expanded)
            .value_counts()
            .head(top_n)
            .sort_values(ascending=True)
        )
        counts.plot(kind="barh", ax=ax, color="#2563eb")
        ax.set_xlabel("Frequency")
        ax.set_ylabel("Attack Pattern Code")
        ax.set_title("Top Attack Pattern Frequencies")
    plt.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)
