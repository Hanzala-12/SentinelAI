from pathlib import Path
from evaluation.utils.unified_loader import load_all_datasets

datasets_dir = Path('evaluation/datasets')
print(f"Loading datasets from: {datasets_dir}")
print(f"Directory exists: {datasets_dir.exists()}")

merged, summaries = load_all_datasets(datasets_dir)

print('\n=== LOADER TEST RESULTS ===')
print(f'Total rows merged: {len(merged)}')
print(f'Datasets loaded: {len(summaries)}')
for s in summaries:
    print(f'  - {s.dataset_name}: {s.rows} rows (invalid={s.invalid_rows}, dup={s.duplicate_rows})')

if not merged.empty:
    print(f'\nColumns: {list(merged.columns)}')
    print(f'\nLabel distribution:')
    print(merged['label'].value_counts().to_dict())
    print(f'\nSource distribution:')
    print(merged['source_dataset'].value_counts().to_dict())
    print(f'\nFirst 3 samples:')
    for i, row in merged.head(3).iterrows():
        print(f'  [{i}] {row["url"]} ({row["label_text"]}) from {row["source_dataset"]}')
else:
    print('ERROR: No data loaded!')
