# Temporal and Fingerprint-Based Novelty Detection

## Implemented behaviour

- `TemporalAnalyzer` keeps a bounded RSSI history per canonical BSSID and reports sample count, mean, variance, standard deviation, last-sample delta, short/long range, observation frequency, and an explainable temporal score.
- `WiFiFingerprintStore` persists AP observations, channel/security history, RSSI history, and a fingerprint hash. APs are not automatically trusted when first observed.
- `ScanController` compares the current SSID, channel, and security with the pre-update baseline and emits `fingerprint_changed` plus explanatory reasons. A new channel/security value is treated as change evidence, not proof of maliciousness.
- Density evidence records multiple BSSIDs for one SSID and one BSSID associated with multiple SSIDs. This is a weak signal because roaming, mesh systems, and legitimate multi-radio networks can produce similar patterns.
- `novelty_alert_engine.py` consumes temporal scores, density scores, fingerprint mismatch/change evidence, and existing strong indicators. Weak evidence needs corroboration; a newly seen AP alone does not trigger a malicious alert.
- Dashboard rows now carry baseline-exists, fingerprint-change reasons, temporal score, and density score into novelty evaluation.

## Validation

Run from the project root:

```powershell
python -m unittest test_novelty_alert_engine test_temporal_fingerprint_novelty -v
python -m py_compile novelty_alert_engine.py scan_controller.py dashboard.py temporal_analyzer.py wifi_fingerprint.py
```

Tests cover RSSI variance/delta, preview without history mutation, non-automatic trust enrollment, fingerprint mismatch in percentage units, corroboration, and the rule that a new AP alone is not labelled malicious.

## Research cautions

- Fingerprint mismatch and novelty mean “different from baseline,” not “confirmed Evil Twin.”
- BSSID/SSID density alone is not proof of spoofing.
- Thresholds are heuristics and must be evaluated against labelled benign and controlled attack observations.
- The legacy dataset audit previously found no verified rows eligible for training. Do not report model performance until a ground-truth-labelled held-out dataset is available.
