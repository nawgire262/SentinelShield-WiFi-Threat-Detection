# SentinelShield research dataset workflow

## What was prepared

- `training_dataset_backup.csv` is a byte-for-byte backup of the original labeled CSV.
- `data/raw/` is the destination for untouched passive scan captures.
- `data/processed/legacy_dataset_for_review.csv` preserves the legacy rows with explicit `Frequency_MHz`, derived `Channel`, provenance, and placeholder flags.
- `data/processed/clean_wifi_dataset.csv` contains only rows that pass structural checks, have `label_source=field_verified`, and do not use placeholder BSSIDs.
- `data/reports/dataset_quality_report.json` records the audit and blocks training when no verified observations are available.
- `collect_wifi_observations.py` passively captures visible Wi-Fi metadata and leaves labels unassigned.
- `clean_research_dataset.py` migrates the legacy schema and includes `data/raw/wifi_observations.csv` when present.
- `split_research_dataset.py` refuses to split unverified or insufficient data and, when eligible, creates grouped train/validation/test partitions.

## Schema

`Frequency_MHz` is the operating frequency. `Channel` is the channel number. The legacy file used the `Channel` column for frequency values (some in kHz), so the migration derives a channel only when the frequency maps to a known Wi-Fi channel. The original CSV is not overwritten.

## Collect observations

Run from this project directory on the Windows laptop, after the project's Wi-Fi dependencies are installed:

```powershell
python collect_wifi_observations.py --session L01 --scans 5 --delay 2.5
```

The collector writes to `data/raw/wifi_observations.csv`. It is passive: it does not connect to APs or assign ground truth. Only collect on networks and equipment you own or are authorized to assess.

After each controlled experiment, verify the source AP identity from the experiment log. Edit `Label` to `Legit` or `Fake` and set `label_source` to `field_verified` only for observations whose ground truth is documented. Keep uncertain rows unverified. Never infer `Fake` merely from unfamiliar BSSID, signal strength, SSID, or an anomaly score.

## Clean and audit

```powershell
python clean_research_dataset.py
```

Review `data/reports/dataset_quality_report.json`, `data/processed/legacy_dataset_for_review.csv`, and `data/processed/clean_wifi_dataset.csv`.

## Split and evaluate

```powershell
python split_research_dataset.py
python evaluation.py data/processed/clean_wifi_dataset.csv
```

The split script groups by `Session_ID + BSSID` to reduce leakage. Small datasets can yield class-imbalanced partitions; inspect the split report before use. Training/evaluation remain blocked until there are enough verified, non-placeholder examples of both classes. Do not bypass this gate or report metrics from synthetic placeholder rows.

## Current audit status

The legacy source contains 151 rows, but none are marked as field-verified. Therefore the clean training set is intentionally empty, the leakage-resistant split is blocked, and final model retraining/evaluation must wait for real authorized captures. No live Wi-Fi observations can be collected in this offline project-file execution environment.
