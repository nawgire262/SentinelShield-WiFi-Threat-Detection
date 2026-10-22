# Ground-truth data collection and evaluation protocol

## Purpose
Create auditable, field-verified observations for SentinelShield. This protocol does not assume an unfamiliar AP, a repeated SSID, a weak signal, or a changed fingerprint is malicious.

## A. Collect observations
1. Use a laptop/network adapter you are authorized to scan. Passive scanning records broadcast network metadata only; do not capture user traffic or connect to networks without permission.
2. Collect ordinary baseline sessions at multiple times and locations where you have permission. Keep each capture session ID unique (for example `LEGIT_20261020_A1`).
3. For attack data, use only a controlled lab you own or are explicitly authorized to test. Document the legitimate AP, the controlled test AP, the configuration changes, the start/end time, and the observer. Do not conduct impersonation against public or third-party networks.
4. Capture multiple independent sessions per condition. Do not count repeated rows from one session as independent sessions.
5. Keep the original raw CSV immutable. Make annotations in a separate output file and retain evidence notes.

## B. Ground-truth labels
Use `Legit` only when the AP is known/authorized for that experiment or baseline. Use `Fake` only for the controlled, documented rogue/Evil Twin test AP. Use `Uncertain` when evidence is insufficient. `Uncertain` rows are retained for review but excluded from binary model training/evaluation.

For every labelled observation, `label_source` must be `field_verified`, and provide `experiment_id` and `ground_truth_notes`. A model prediction is not ground truth. Do not label an AP as Fake merely because the SSID matches another AP, its BSSID differs, RSSI changes, or the fingerprint changes.

## C. Dataset split and leakage controls
- Run `python clean_research_dataset.py` after reviewing the annotated file and integrating it into the project's raw-data workflow.
- Ensure each row has a `session_id` (lowercase) and all rows in a capture session share that value.
- Split by session, not by random row. Keep all observations from one session in only one split.
- Keep test sessions untouched until model choices and thresholds are fixed.
- Fit scalers, feature selection, anomaly thresholds, and meta-models on training data only. If tuning thresholds, use validation data only.
- Do not use synthetic/demo rows in research metrics.

## D. Required metrics
Treat `Fake` as the positive class. Report confusion matrix (TP, FP, TN, FN), precision, recall, F1, false-positive rate `FP/(FP+TN)`, and preferably ROC-AUC and PR-AUC when both classes are present. Report sample counts and the number of independent sessions per class. Include per-environment FPR where possible and confidence intervals or repeated session-level splits if sample size permits.

## E. Novelty-specific experiments
1. **RSSI fluctuation:** capture a sequence per AP across time; compare recorded RSSI values with computed variance/std dev. Do not infer maliciousness from fluctuation alone.
2. **Temporal behaviour:** replay known baseline sequences and controlled change sequences; check that change evidence is emitted with timestamps and does not itself force a Fake label.
3. **Fingerprint mismatch:** compare baseline and changed SSID/BSSID/channel/security fingerprints; test unchanged matches and one-feature-at-a-time changes.
4. **Multi-AP density:** test legitimate mesh/roaming APs sharing an SSID as negative controls, plus controlled lab clones as positive controls. SSID/BSSID density is supporting evidence only.
5. **Novelty alerts:** test new-but-legitimate APs, changed legitimate APs, controlled attack APs, and repeated observations. Check duplicate suppression, explanations, and false alarms.

## F. Acceptance checklist
- [ ] Raw data preserved and capture metadata documented.
- [ ] Each `Legit`/`Fake` label has an independent evidence note.
- [ ] `Uncertain` records are excluded from binary evaluation.
- [ ] Both classes occur across enough independent sessions for the chosen split.
- [ ] No session overlap between training and test.
- [ ] Individual RF, KNN, Isolation Forest, and combined model are evaluated on the same held-out sessions.
- [ ] Precision, recall, F1, FPR, confusion matrix, counts, and limitations are reported.
- [ ] No real-world performance claim is made from synthetic self-tests.
