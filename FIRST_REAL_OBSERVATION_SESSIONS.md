# First real Wi-Fi observation sessions (Windows)

This pack does **not** contain fabricated observations. You must run the collector on your own laptop so the records come from your Wi-Fi adapter.

## Before you start
- Use a laptop with Wi-Fi enabled and the project's virtual environment activated.
- Run only passive scans of networks you are authorized to observe. Do not connect to, disrupt, or impersonate third-party networks.
- Check the system clock and keep the original raw CSV unchanged after capture.
- Each session ID must be unique. Record the location/environment in the lab log without recording private details you do not need.

## Session A: ordinary baseline
From the inner `SentinelShield-WiFi-Threat-Detection-main` project folder:

```powershell
python collect_wifi_observations.py --session LEGIT_20261019_A1 --scans 10 --delay 3 --output data/raw/wifi_observations.csv
```

This captures visible Wi-Fi scan metadata. `--delay 3` is a wait between scan requests, not a guarantee of an exact scan duration. The collector may consolidate repeated observations for the same SSID/BSSID within a session, so retain any detailed scan-history file produced by the live scanner if you need per-pass temporal measurements.

Repeat the baseline at a different time with a unique ID, for example:

```powershell
python collect_wifi_observations.py --session LEGIT_20261019_A2 --scans 10 --delay 3 --output data/raw/wifi_observations.csv
```

Do not use `LEGIT` in the ID as proof of the label. The label must still be verified independently.

## Session B: controlled lab test (optional; authorized equipment only)
Only conduct this if you own or have explicit permission to configure the test AP and all involved devices. Do not clone a campus, business, or public network. Keep the test network isolated and clearly documented.

1. Record the real test configuration in `data/reports/observation_session_log.csv`.
2. Capture the known legitimate AP in a baseline session.
3. If an authorized controlled test AP is used, capture it in a separate session with an ID such as `LAB_TEST_20261019_B1`.
4. Record exactly which device/configuration you controlled and what evidence establishes its role. A matching SSID, unusual BSSID, or RSSI change alone is not ground truth.

## Label only after capture
Run the interactive annotator on the captured file:

```powershell
python annotate_wifi_ground_truth.py data/raw/wifi_observations.csv --output data/raw/wifi_observations_annotated.csv
```

For each session/AP group, choose:
- `l` only when the AP's legitimate identity is independently verified;
- `f` only when it is the known controlled attack AP from your documented lab experiment;
- `u` when evidence is insufficient;
- `s` to skip for now.

Enter a meaningful experiment ID and evidence note. Never infer labels from the model's prediction. Keep `Uncertain` rows out of binary evaluation.

## Verify outputs

```powershell
python clean_research_dataset.py
```

Inspect `data/reports/dataset_quality_report.json` and the console output. If the result is `BLOCKED_NO_VERIFIED_DATA`, stop: the project is not yet ready to report research metrics. Do not hand-edit the quality report to bypass the gate.

## Important limitations
- This collector records visible scan metadata, not packet contents or proof of ownership.
- The `Signal_Var` produced by the collector is a session-level variance estimate; inspect the raw/history implementation before claiming per-scan temporal validation.
- Avoid train/test leakage: observations from one capture session should not be split across training and test sets.
- Preserve raw capture files and the session log so another researcher can audit the procedure.
