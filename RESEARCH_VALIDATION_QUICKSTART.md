# Research validation quick start (Windows PowerShell)

Run commands from the inner `SentinelShield-WiFi-Threat-Detection-main` folder.

## 1. Capture a baseline session
```powershell
python collect_wifi_observations.py --session LEGIT_20261020_A1 --scans 10 --delay 3 --output data/raw/wifi_observations.csv
```
Repeat with a new session ID at different times. Collector output is unlabelled by design.

## 2. Controlled lab observations
Run the same collector only in an authorized test environment. Capture ordinary baseline and controlled test-AP sessions separately. Record experiment details in your lab notes. Do not impersonate third-party networks.

## 3. Annotate evidence-backed labels
```powershell
python annotate_wifi_ground_truth.py data/raw/wifi_observations.csv --output data/raw/wifi_observations_annotated.csv
```
The annotator asks for a label and evidence note per session/AP group. It does not infer labels. Keep the raw file untouched.

## 4. Prepare the canonical training dataset
Manually review the annotated CSV, then integrate verified records into the input file expected by `clean_research_dataset.py` (the script currently reads `training_dataset.csv` and optionally `data/raw/wifi_observations.csv`). Keep a copy of the original files. If using the cleaner's raw-data input, copy only the reviewed/annotated data to `data/raw/wifi_observations.csv` after preserving the original raw capture elsewhere.

The cleaner requires columns such as `AP_Count`, `Signal_Var`, `Channel`, `Label`, and `label_source=field_verified`. Rows labelled `Uncertain` should be excluded from binary evaluation. Confirm `session_id` exists for all rows; the collector uses `Session_ID`, so keep both names if required by the evaluation script.

## 5. Run quality gate and evaluation
```powershell
python clean_research_dataset.py
python research_eval.py --help
```
Read `data/reports/dataset_quality_report.json`. If status is `BLOCKED_NO_VERIFIED_DATA`, do not report performance metrics. Once the clean dataset passes the project's session/class gates, use the input path/options shown by `python research_eval.py --help` and save results to a new results folder.

## 6. Report responsibly
Report independent session counts, confusion matrix, precision, recall, F1, FPR, and the exact split strategy. A simulated self-test checks code paths only; it is not evidence of real-world accuracy. See `RESEARCH_GROUND_TRUTH_PROTOCOL.md` for full controls.
