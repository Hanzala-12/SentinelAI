from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
import json

import pandas as pd


STANDARD_COLUMNS = [
    "url",
    "domain",
    "label",
    "label_text",
    "source_dataset",
    "raw_value",
]

PHISH_HINTS = ("phish", "openphish", "malicious", "scam", "attack")
BENIGN_HINTS = ("benign", "top", "tranco", "alexa", "safe", "top-1m")


@dataclass(slots=True)
class LoadSummary:
    dataset_name: str
    source_file: str
    rows: int
    invalid_rows: int = 0
    duplicate_rows: int = 0


def normalize_url(raw: str | None) -> str | None:
    text = (raw or "").strip()
    if not text:
        return None
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    try:
        parsed = urlparse(text)
        if not parsed.netloc:
            return None
        return text
    except Exception:
        return None


def extract_domain(url: str | None) -> str | None:
    if not url:
        return None
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        return domain.split(":")[0] if domain else None
    except Exception:
        return None


def infer_binary_label(path: Path, explicit: int | None = None) -> int:
    if explicit is not None:
        return int(explicit)

    name = path.name.lower()
    if any(token in name for token in PHISH_HINTS):
        return 1
    if any(token in name for token in BENIGN_HINTS):
        return 0
    return 0


def _records_frame(
    records: list[dict],
    *,
    dataset_name: str,
    source_file: Path,
) -> tuple[pd.DataFrame, LoadSummary]:
    if not records:
        empty = pd.DataFrame(columns=STANDARD_COLUMNS)
        summary = LoadSummary(
            dataset_name=dataset_name,
            source_file=str(source_file),
            rows=0,
            invalid_rows=0,
            duplicate_rows=0,
        )
        return empty, summary

    frame = pd.DataFrame.from_records(records)

    before_invalid = len(frame)
    frame = frame.dropna(subset=["url"]).copy()
    invalid_count = before_invalid - len(frame)

    before_dup = len(frame)
    frame = frame.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    duplicate_count = before_dup - len(frame)

    for column in STANDARD_COLUMNS:
        if column not in frame.columns:
            frame[column] = None

    frame = frame[STANDARD_COLUMNS]

    summary = LoadSummary(
        dataset_name=dataset_name,
        source_file=str(source_file),
        rows=len(frame),
        invalid_rows=invalid_count,
        duplicate_rows=duplicate_count,
    )
    return frame, summary


def load_txt(path: Path) -> tuple[pd.DataFrame, LoadSummary]:
    """Load headerless TXT files (one URL/domain per line)."""
    dataset_name = path.stem
    label = infer_binary_label(path)
    records = []

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        content = path.read_text(encoding="latin-1")

    for line in content.splitlines():
        value = line.strip()
        if not value:
            continue
        normalized = normalize_url(value)
        if normalized:
            domain = extract_domain(normalized)
            records.append(
                {
                    "raw_value": value,
                    "url": normalized,
                    "domain": domain,
                    "label": label,
                    "label_text": "malicious" if label == 1 else "benign",
                    "source_dataset": dataset_name,
                }
            )

    return _records_frame(records, dataset_name=dataset_name, source_file=path)


def load_csv(path: Path) -> tuple[pd.DataFrame, LoadSummary]:
    """Load CSV files, auto-detecting URL and domain columns."""
    dataset_name = path.stem
    try:
        frame = pd.read_csv(path)
    except Exception:
        frame = pd.read_csv(path, sep=None, engine="python")

    columns_lower = {col.lower(): col for col in frame.columns}
    url_column = None
    domain_column = None

    for candidate in ("url", "phish_url", "phish_detail_url", "indicator"):
        if candidate in columns_lower:
            url_column = columns_lower[candidate]
            break

    for candidate in ("domain", "hostname", "site"):
        if candidate in columns_lower:
            domain_column = columns_lower[candidate]
            break

    if url_column is None and domain_column is None:
        if len(frame.columns) >= 2:
            first, second = list(frame.columns)[:2]
            if pd.api.types.is_numeric_dtype(frame[first]):
                domain_column = second
            else:
                url_column = first

    if url_column is None and domain_column is None:
        url_column = frame.columns[0] if len(frame.columns) > 0 else None

    label = infer_binary_label(path)
    records = []

    if url_column is not None:
        for raw_value in frame[url_column].astype(str).tolist():
            normalized = normalize_url(raw_value)
            if normalized:
                domain = extract_domain(normalized)
                records.append(
                    {
                        "raw_value": raw_value,
                        "url": normalized,
                        "domain": domain,
                        "label": label,
                        "label_text": "malicious" if label == 1 else "benign",
                        "source_dataset": dataset_name,
                    }
                )
    elif domain_column is not None:
        for raw_value in frame[domain_column].astype(str).tolist():
            normalized = normalize_url(raw_value)
            if normalized:
                domain = extract_domain(normalized)
                records.append(
                    {
                        "raw_value": raw_value,
                        "url": normalized,
                        "domain": domain,
                        "label": label,
                        "label_text": "malicious" if label == 1 else "benign",
                        "source_dataset": dataset_name,
                    }
                )

    return _records_frame(records, dataset_name=dataset_name, source_file=path)


def load_json_corpus(path: Path) -> tuple[pd.DataFrame, LoadSummary]:
    """Load JSON corpus (calibration format)."""
    dataset_name = path.stem
    payload = json.loads(path.read_text(encoding="utf-8"))
    records = []

    for item in payload:
        label_text = item.get("label", "unknown")
        label = 1 if label_text == "malicious" else 0 if label_text == "benign" else -1
        url = item.get("url", "")
        normalized = normalize_url(url) if url else None

        if normalized:
            domain = extract_domain(normalized)
            records.append(
                {
                    "raw_value": url,
                    "url": normalized,
                    "domain": domain,
                    "label": label,
                    "label_text": label_text,
                    "source_dataset": dataset_name,
                }
            )

    return _records_frame(records, dataset_name=dataset_name, source_file=path)


def load_dataset(path: Path) -> tuple[pd.DataFrame, LoadSummary]:
    """Load a single dataset file."""
    suffix = path.suffix.lower()
    if suffix == ".txt":
        return load_txt(path)
    elif suffix == ".csv":
        return load_csv(path)
    elif suffix == ".json":
        return load_json_corpus(path)
    else:
        raise ValueError(f"Unsupported dataset type: {path}")


def load_all_datasets(root: Path) -> tuple[pd.DataFrame, list[LoadSummary]]:
    """Load all dataset files from a directory."""
    candidates = [
        path for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".txt", ".csv", ".json"}
        and "results" not in path.parts
        and "reports" not in path.parts
        and "__pycache__" not in path.parts
    ]

    frames: list[pd.DataFrame] = []
    summaries: list[LoadSummary] = []

    for path in sorted(candidates):
        try:
            frame, summary = load_dataset(path)
            frames.append(frame)
            summaries.append(summary)
        except Exception as exc:
            print(f"[WARN] Failed to load {path}: {exc}")

    if not frames:
        return pd.DataFrame(columns=STANDARD_COLUMNS), summaries

    merged = pd.concat(frames, ignore_index=True)
    merged = merged.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    return merged, summaries
