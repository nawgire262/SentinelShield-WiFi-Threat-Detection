# SentinelShield cumulative novelty audit — 19 October 2026

## Scope and evidence

This audit reviews the cumulative project ZIP containing the continuous-scanning, hybrid-pipeline, temporal/fingerprint novelty, and first-observation-session changes. It distinguishes code presence and targeted software tests from real-world research validation. A module existing does not prove that its feature has been validated on field data.

## Changes accumulated in this version

- Continuous scanning controls and controller scheduler (`start_continuous` / `stop_continuous`) with target interval, cycle count, timestamps, and error display.
- Hybrid RF/KNN/Isolation Forest + meta-model contract and dedicated integration tests.
- Temporal RSSI history, variance/delta, fingerprint baseline comparison, density evidence, and novelty corroboration rules.
- Passive observation collector, manual evidence-based ground-truth annotation, dataset quality gate, research evaluation and grouped-split tooling.
- Documentation for continuous scanning, hybrid pipeline, novelty detection, and first observation sessions.

## Current status matrix

| Novelty / capability | Code evidence in project | Status | Remaining work |
|---|---|---|---|
| Continuous scanning at configurable target interval | `scan_controller.py`, `dashboard.py`, `CONTINUOUS_SCANNING.md` | Implemented in code; needs device validation | Test actual Windows adapter, scan duration, stop while driver call is active, error recovery, and whether the 5-second target is achievable. It is a target interval, not a completion guarantee. |
| RSSI fluctuation / temporal history | `temporal_analyzer.py`, `rssi_raim.py`, `test_temporal_fingerprint_novelty.py` | Implemented; synthetic/unit-tested | Validate repeated measurements from real captures, minimum history requirements, thresholds, and false alarms across locations/adapters. Collector consolidates repeated scan observations, so retain detailed per-pass history if required. |
| Temporal network behaviour | `temporal_analyzer.py`, `scan_controller.py` | Partial / field validation pending | Verify which fields are tracked over time, ensure baseline state persists across app restarts if claimed, and replay documented sequences of benign changes and controlled attack changes. |
| Fingerprint mismatch | `wifi_fingerprint.py`, `fingerprinting/`, `scan_controller.py` | Implemented; unit-tested | Validate fingerprint persistence, trusted-baseline enrolment policy, MAC randomization, legitimate roaming/mesh cases, and false-positive rate on real APs. |
| Multi-AP spoofing density | `novelty_alert_engine.py`, controller/dashboard evidence | Heuristic evidence implemented | Validate density calculations on ordinary multi-radio/mesh/roaming networks and controlled lab cases. Density alone must never be presented as proof of spoofing. |
| Novelty alerts and corroboration | `novelty_alert_engine.py`, `test_novelty_alert_engine.py` | Implemented; unit-tested | Validate alert deduplication/cooldowns, event persistence, repeated observations, new-but-benign APs, changed APs, and false alarms in real sessions. |
| Hybrid model pipeline | `ml_ensemble.py`, `ensemble_contract.py`, `ml_evidence.py`, `tests/test_hybrid_pipeline_validation.py` | Integration tests pass on controlled fixtures | Verify live scan feature mapping and units end-to-end; confirm model artifact versions match; then evaluate against ground-truth-labelled held-out sessions. |
| Model training leakage/scaling | `ml_ensemble.py`, `meta_scaler.pkl`, `tests/test_ensemble_integrity.py` | Targeted tests pass | Review the final training/evaluation path whenever data or models change. Never tune thresholds using held-out test data. |
| XAI | `xai_explain.py`, `ml_evidence.py`, dashboard explanation functions | Code present; end-to-end explanation validity not established | Verify explanations correspond to the actual per-AP prediction and model features; compare explanation output against controlled perturbations and save it with the alert evidence. |
| Dataset collection | `collect_wifi_observations.py` | Collector implemented; no user-captured data verified here | Run on the actual Windows laptop; preserve raw captures and unique session IDs. Check scan freshness and duplicate consolidation. |
| Ground-truth labelling | `annotate_wifi_ground_truth.py`, `RESEARCH_GROUND_TRUTH_PROTOCOL.md` | Workflow implemented; labels require researcher input | Label only independently verified legitimate APs and controlled, authorised attack APs. Keep uncertain records out of binary evaluation. Do not infer truth from model output. |
| Dataset quality and splits | `clean_research_dataset.py`, `split_research_dataset.py` | Gate/split tools present; actual data still blocks evaluation | Previous audit had 151 legacy rows and zero verified eligible rows. After annotation, check class counts and ensure the split prevents same AP/session leakage. Current split grouping uses `Session_ID + BSSID`; a BSSID observed across multiple sessions may land in separate partitions, so use a stricter AP grouping or justify the protocol before publishing. |
| Research metrics | `research_eval.py`, `evaluation.py` | Evaluation code present; no valid real-world result established | Run on accepted field-verified data and a held-out test set. Report precision, recall, F1, false-positive rate, confusion matrix, class counts, and per-environment results if available. |
| PDF reporting | `report_generator.py`, `test_report.py` | Code present; full integration needs verification | Confirm the report uses saved scan evidence and real metrics, handles empty data, and does not claim unmeasured accuracy. |
| Cloud threat intelligence | `threat_intelligence.py`, `cloud_providers.py`, cache files | Integration scope needs live/provider verification | Test with provider credentials and documented safe fixtures; record source, timestamp, timeout/error, and ensure provider failure does not silently mean “safe.” |
| Adaptive thresholds | `adaptive_thresholds.py` | Code present; scientific validity pending | Verify adaptation is bounded, explainable, stable under benign drift, and cannot learn attacker behaviour as a new normal. Freeze thresholds before held-out evaluation. |
| Federated learning | `federated_node.py`, `federated_server.py` | Optional / not part of validated core path | Do not claim as an implemented research contribution until multi-node training, aggregation, privacy/security assumptions, and comparative tests are demonstrated. |
| BLE/location sensor fusion | `bluetooth_context.py`, `location_context.py`, `sensor_fusion.py` | Optional / integration and validation pending | Define scope and verify actual data source, consent/privacy handling, time alignment, and effect on decisions before claiming contribution. |

## Test evidence run for this audit

Executed from the project root:

```powershell
python -m unittest tests.test_ensemble_integrity tests.test_hybrid_pipeline_validation test_novelty_alert_engine test_temporal_fingerprint_novelty -v
```

Result: **17 tests passed** in the current audit environment. These are targeted unit/integration tests using controlled fixtures. They are not a real-world accuracy evaluation and do not validate actual Windows WLAN hardware behaviour.

## Research readiness conclusion

**Software readiness:** core modules and targeted tests exist for continuous scanning, hybrid model inference, temporal features, fingerprints, and novelty corroboration.

**Research readiness:** not yet established. The prior dataset audit found 151 legacy rows but **0 verified, non-placeholder rows eligible for training**. The immediate blockers are collecting real captures, independently documenting ground truth, correcting/confirming leakage-resistant splits, and evaluating on held-out sessions.

## Next steps in order

1. Run the collector on the actual Windows laptop and preserve raw CSV plus a session log.
2. Capture repeated benign sessions across different times/conditions.
3. If authorised, collect controlled lab attack observations with independently known ground truth; never impersonate third-party networks.
4. Annotate only after documenting evidence; keep uncertain rows separate.
5. Run the dataset quality gate and inspect all label/session counts.
6. Fix or justify split grouping so the same AP cannot leak across partitions; check each partition contains the required classes.
7. Run per-model and full-hybrid evaluation on held-out data; record precision, recall, F1, false-positive rate and confusion matrix.
8. Replay benign and controlled attack sequences to validate temporal/fingerprint/density alert thresholds.
9. Verify an alert's evidence survives database persistence and appears correctly in a PDF report.
10. Report limitations and avoid accuracy/novelty-improvement claims until supported by results.
