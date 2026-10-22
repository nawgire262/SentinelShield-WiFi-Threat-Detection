# Hybrid Detection Pipeline: Implementation and Validation

## Pipeline contract

`Wi-Fi scanner -> normalized observation -> feature contract -> RF/KNN/Isolation Forest -> stacked meta-model -> evidence/risk result -> explanation -> caller-owned alert/database/report handling`

The model feature order is fixed by `ensemble_contract.FEATURES`:

1. `RSSI`
2. `Channel` (the existing model's training/inference convention is frequency in MHz)
3. `Security_enc`
4. `AP_Count`
5. `Signal_Var`

The meta-model receives exactly three features in this order: RF probability of `Fake`, KNN probability of `Fake`, and the negated Isolation Forest decision function. `meta_scaler.pkl` must transform those three features at inference time; it is not interchangeable with `scaler.pkl`.

## Leakage correction

`HybridEnsembleDetector.train_frame()` now creates out-of-fold RF, KNN and Isolation Forest evidence using a separate `StandardScaler` fitted only on each fold's training partition. The Isolation Forest in each fold sees only `Legit` training rows. The final production scaler and base models are fitted after out-of-fold meta-features have been created. This avoids fitting preprocessing statistics on validation-fold rows during meta-feature generation.

The held-out evaluation in `evaluation.py` remains a separate train/test split. Do not use held-out test rows for model selection, threshold tuning, or feature engineering.

## Tests

Run from the project root:

```powershell
python -m unittest tests.test_ensemble_integrity tests.test_hybrid_pipeline_validation -v
```

The tests check base model outputs, meta-model inference, scaler dimensions, Isolation Forest training constraints, model artifact round-tripping, and compatibility with the live evidence adapter.

## Important research limitation

Passing these tests demonstrates software-path consistency on a controlled synthetic fixture. It does **not** establish real-world detection performance. The current legacy dataset audit reported zero verified, non-placeholder rows eligible for training. Do not publish precision, recall, F1, false-positive rate, or accuracy as research results until the quality gate accepts real, ground-truth-labelled observations and evaluation is run on a held-out set.

## Downstream integration

`ExistingModelEvidence` returns per-model evidence and a combined meta-model probability with a feature explanation. The scanner/controller integration should preserve these fields in the scan result. Risk-based alerting, persistence, and PDF reporting should consume the same scan result and must not independently invent or relabel ground truth.
