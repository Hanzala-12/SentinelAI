from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd


STANDARD_COLUMNS = ["url", "label", "source"]


@dataclass(slots=True)
class DatasetLoadResult:
    frame: pd.DataFrame
    invalid_count: int
    duplicate_count: int


def _pick_url_column(frame: pd.DataFrame, candidates: list[str]) -> str | None:
    existing = {column.lower(): column for column in frame.columns}
    for candidate in candidates:
        if candidate.lower() in existing:
            return existing[candidate.lower()]
    return None


def normalize_url(raw: str) -> str | None:
    text = (raw or "").strip()
    if not text:
        return None
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.netloc:
        return None
    return text


def _build_standard_frame(
    frame: pd.DataFrame,
    *,
    label: int,
    source: str,
    url_column_candidates: list[str],
) -> DatasetLoadResult:
    url_column = _pick_url_column(frame, url_column_candidates)
    if url_column is None:
        raise ValueError(f"Unable to locate a URL column in source '{source}'. Columns: {list(frame.columns)}")

    subset = frame[[url_column]].copy()
    subset.rename(columns={url_column: "url"}, inplace=True)
    subset["url"] = subset["url"].astype(str).map(normalize_url)

    invalid_count = int(subset["url"].isna().sum())
    subset = subset.dropna(subset=["url"])
    subset["label"] = int(label)
    subset["source"] = source

    before = len(subset)
    subset = subset.drop_duplicates(subset=["url"], keep="first")
    duplicate_count = before - len(subset)
    subset = subset[STANDARD_COLUMNS].reset_index(drop=True)
    return DatasetLoadResult(frame=subset, invalid_count=invalid_count, duplicate_count=duplicate_count)


def _read_csv(path: Path) -> pd.DataFrame:
    # Most phishing feeds are distributed as comma-separated files with header.
    # Delimiter sniffing can mis-detect ':' in URLs as a separator, so we parse CSV first.
    try:
        frame = pd.read_csv(path)
        if len(frame.columns) >= 1:
            return frame
    except Exception:
        pass
    return pd.read_csv(path, sep=None, engine="python")


def load_phishtank(path: str | Path) -> DatasetLoadResult:
    """
    Load a PhishTank-style CSV and standardize to [url,label,source].
    """
    csv_path = Path(path)
    frame = _read_csv(csv_path)
    return _build_standard_frame(
        frame,
        label=1,
        source="phishtank",
        url_column_candidates=["url", "phish_url", "phish_detail_url"],
    )


def load_openphish(path: str | Path) -> DatasetLoadResult:
    """
    Load an OpenPhish-style CSV and standardize to [url,label,source].
    """
    csv_path = Path(path)
    frame = _read_csv(csv_path)
    return _build_standard_frame(
        frame,
        label=1,
        source="openphish",
        url_column_candidates=["url", "phish_url", "indicator"],
    )


def load_benign(path: str | Path) -> DatasetLoadResult:
    """
    Load benign domain/URL dataset (Tranco/Alexa style) and standardize to [url,label,source].
    """
    csv_path = Path(path)
    frame = _read_csv(csv_path)
    return _build_standard_frame(
        frame,
        label=0,
        source="benign",
        url_column_candidates=["url", "domain", "hostname", "site"],
    )


def combine_datasets(results: list[DatasetLoadResult], *, shuffle: bool = True, random_state: int = 42) -> pd.DataFrame:
    """
    Merge standardized frames, deduplicate globally, and optionally shuffle.
    """
    frames = [result.frame for result in results if not result.frame.empty]
    if not frames:
        return pd.DataFrame(columns=STANDARD_COLUMNS)

    merged = pd.concat(frames, ignore_index=True)
    merged = merged.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    if shuffle:
        merged = merged.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    return merged
