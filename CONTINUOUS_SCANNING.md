# Continuous Wi-Fi Scanning

The Live Scan page now provides **Start Continuous Scan** and **Stop Continuous Scan** controls.

- The default target interval is 5 seconds between scan starts; users can choose 1–3600 seconds.
- Continuous scanning reuses `ScanController.start()` and the existing scanner, verification, evidence fusion, persistence, novelty alerts, and report pipeline.
- The scheduler never intentionally overlaps scan workers. If a scan takes longer than the configured interval, the next scan starts after the current scan completes.
- Stop Continuous Scan disables future cycles and requests cancellation of the in-flight scan. A Windows WLAN driver call already in progress may need to return before cancellation completes.
- Dashboard polling is separate from scan scheduling. Its fast refresh only updates the display and does not itself trigger a scan.
- Status includes completed cycle count, last scan start/finish timestamps, and the latest scheduler error.

## Validation

Run the focused tests:

```powershell
python -m unittest tests.test_fast_scanning_subsystem -v
```

Run the broader non-notification suite:

```powershell
python -m unittest tests.test_fast_scanning_subsystem tests.test_adaptive_thresholds tests.test_dataset_and_evaluation tests.test_ensemble_integrity tests.test_fingerprinting tests.test_innovation_phases tests.test_wifi_interface_selection tests.test_wifi_scan_persistence -v
```
