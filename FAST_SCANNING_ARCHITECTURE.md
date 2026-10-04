# Fast Adaptive Wi-Fi Scanning Architecture

## 1. Audited architecture

`dashboard.py` is the single Streamlit entrypoint. Before this work it invoked the synchronous `scanner.scan_wifi(rounds=...)` path. The legacy scanner selected one PyWiFi adapter, slept three seconds per pass, grouped measurements by SSID, and returned one representative BSSID per SSID. Its output used lowercase fields and passed backend frequency values through an ambiguous `channel` field.

The project also contains `fast_scan.py` and `background_scanner.py`; the former imports a missing `ScanStatus`, and the latter referenced an undefined `row` during conversion. They were not suitable integration points. `live_scan.py` expects uppercase keys not returned by `scanner.py`. The dashboard now uses the new controller and keeps `scanner.scan_wifi()` unchanged for compatibility and benchmarking.

Other relevant existing modules:

- `adaptive_thresholds.py`: EWMA risk baseline persisted to JSON; dashboard still applies its adaptive classifications.
- `database_manager.py`: existing SQLite tables/APIs; this work adds scan-run and radio-observation tables and APIs.
- `train_model.py` / `rf_model.pkl`, `knn_model.pkl`, `iso_model.pkl`, `meta_model.pkl`: model training contract is five unscaled inputs: RSSI, frequency in MHz under the historical column name `Channel`, encoded security, AP count and RSSI variance.
- `wifi_fingerprint.py` is the new persistent baseline. Unlike the legacy `fingerprints.json`, new AP observations remain OBSERVED/ESTABLISHED until an analyst explicitly trusts them.
- Existing Windows-specific scanning remains based on PyWiFi/COM and `netsh`; no Linux wireless utility is assumed.

## 2. Scan flow

`dashboard.py` starts `ScanController` on a worker thread. `FastWiFiScanner` discovers PyWiFi interfaces, reports adapter ID/name/MAC/state/capabilities when available, normalizes frequency units to MHz and channel number, and timestamps per-BSSID observations. Distinct adapters scan concurrently in a bounded `ThreadPoolExecutor`; a shared lock serializes access to the same adapter ID. If one radio fails, other radios' observations are retained.

The four selectable modes are:

- **Fast**: one short-settle scan per detected adapter.
- **Balanced**: one normal-settle scan per adapter.
- **Deep**: configured repeated deep scans for confirmation.
- **Auto**: balanced discovery before a baseline exists, fast polling afterward, and deep verification when a new BSSID or changed evidence appears.

A stop request is cooperative. A Windows WLAN driver call already in flight is allowed to return; the controller then prevents later verification/persistence work. Python cannot safely terminate a thread blocked inside a native driver call.

PyWiFi exposes a full scan, not a portable channel-targeting API. Therefore this implementation does **not** claim it can assign channel groups to radios. When distinct adapters exist, it runs one full scan on each concurrently and keeps adapter provenance. Single-adapter operation is the automatic fallback.

## 3. Fingerprints and trust

`wifi_fingerprint.py` stores a bounded, atomic JSON baseline keyed by canonical BSSID. Each record includes SSID, OUI vendor where locally known, channel/security histories, RSSI samples and summary statistics, observation count/frequency, first/last-seen timestamps, confidence, trust state and a deterministic hash. History length is configured and bounded.

Confidence advances from UNKNOWN to OBSERVED to ESTABLISHED. TRUSTED is set only through the dashboard's explicit confirmation control. An observation never becomes trusted simply because the scanner saw it. High-risk evidence may mark a profile SUSPICIOUS; that is a triage state, not proof of an Evil Twin.

## 4. Temporal and evidence analysis

`temporal_analyzer.py` tracks bounded per-BSSID RSSI history, calculating mean, variance, standard deviation, delta, short/long range and observation frequency. The minimum sample count and thresholds are read from `runtime_config.py`; new/sparse APs are reported as insufficient temporal evidence rather than automatically suspicious.

`evidence_fusion.py` combines identity, security, channel, fingerprint/RSSI deviation, temporal behavior, BSSID density, optional context and optional existing-model scores. Weights, score bands and detector thresholds live in runtime configuration. A changed/new BSSID alone does not yield a critical verdict. A same-SSID unknown BSSID combined with security/channel/RSSI conflicts can raise the score. The result is a risk prioritization and explanation—not definitive attribution.

The old RF/KNN/Isolation Forest/meta artifacts are loaded lazily by `ml_evidence.py`; no training occurs at dashboard startup. Inputs are converted to the legacy model's documented feature units. If artifacts fail to load or inference fails, local rule evidence continues without ML. The checked-in artifacts were serialized under scikit-learn 1.9.0 while this environment has 1.9.1; inspect the warnings and retrain deliberately with `train_model.py` if reproducibility is required.

## 5. Optional radios and location

Bluetooth/BLE is only an optional presence/context source in `bluetooth_context.py`; it does not scan Wi-Fi and its detections are not attributed to an AP. BLE is disabled by default and the optional `bleak` package is not required for the core app. Missing package, adapter, or permission is reported as unavailable evidence.

`location_context.py` is optional and disabled by default. It attempts the Windows Runtime geolocation API only when explicitly enabled and available. GPS/location is never needed to discover or analyze Wi-Fi. Location is contextual only, not Wi-Fi evidence.

## 6. Persistence

`database_manager.py` retains the existing tables and adds:

- `scan_runs`: scan ID, start/completion, scan/processing/detection latency, mode, adapters and AP counts.
- `wifi_observations`: per-radio BSSID observation, normalized channel/frequency/RSSI/security, fingerprint hash, fused score/level/reason and timing.

Writes are grouped transactionally. Retention defaults to 30 days and is configurable. Database failures are logged and do not terminate scans; CSV remains the dashboard compatibility/export path. SQLite data is written under the project directory.

## 7. Performance measurement

Run the controlled, sequential old-vs-new benchmark with:

`python performance_benchmark.py --runs 3 --old-rounds 1 --output performance_benchmark.json`

It reports average/median/P95 wall time, CPU time, Python heap peak, APs per second and paired BSSID Jaccard overlap. The comparison alternates old and fast scans to reduce time-of-day bias. A percentage improvement is only reported when both find APs and mean paired BSSID overlap is at least 0.5. The legacy scanner emits one representative BSSID per SSID whereas the new scanner preserves per-BSSID observations; this limitation can make comparisons non-comparable.

The latest three-pair run on this Windows host detected one Wi-Fi adapter. It measured old scanner **3,452.42 ms average** (median 3,428.92 ms, P95 3,539.65 ms) and fast scanner **1,661.33 ms average** (median 1,679.62 ms, P95 1,687.71 ms). Mean paired BSSID Jaccard overlap was **0.626**, so this run passes the benchmark's comparability gate and reports a **51.88% shorter measured scan time**. The observed AP counts were **9.33 old vs 7 fast** and AP throughput **2.70 vs 4.21 per second**; legacy results are grouped per SSID while the new path retains per-BSSID observations, so discovery counts are not exactly like-for-like. This establishes a scan-time measurement on this host, not a controlled time-from-new-AP-appearance-to-alert measurement. A rogue AP was not introduced; detection latency for a new rogue AP remains unmeasured. The raw report is `performance_benchmark.json`.

CPU time is process CPU time; memory is Python `tracemalloc` heap, not total process RSS. Multi-adapter speedup was not measured because only one adapter was available on the test machine.

## 8. Installation and Windows requirements

Core scanning uses existing `pywifi` and `comtypes` requirements. Windows Wi-Fi discovery still depends on the WLAN service, enabled adapter, Location permission where required by Windows, and sufficient access rights. BLE and WinRT location packages are optional and are not added to required dependencies.

Start the application from the project directory:

```powershell
.\.venv\Scripts\Activate.ps1
python -m streamlit run dashboard.py
```

## 9. Troubleshooting and limits

## 10. Innovation extensions

### Phase 1 — wired correlation and analyst feedback

`wired_correlation.py` reads only an administrator-exported JSON inventory
(`[{"bssid": "AA:...", "ssid": "...", "authorized": true}]`). It never
connects to a switch, endpoint, DHCP server, or NAC. A match marked
unauthorized contributes evidence; a missing match is explicitly non-decisive.
`analyst_feedback.py` records append-only LEGITIMATE, ROGUE, or INVESTIGATE
verdicts. Feedback does not automatically trust an AP or retrain a model.

### Phase 2 — sensor mesh and Wi-Fi 6E/7 readiness

`sensor_mesh.py` aggregates recent local JSON exports from authorized sensors;
it starts no network service. Normalized observations now reserve optional
Wi-Fi 6E/7 fields for standard, channel width, PMF, MLO link ID, and BSS color.
Classic PyWiFi commonly leaves these blank, which is represented as unavailable
rather than guessed.

### Phase 3 — explainability, evidence integrity, supply chain

`incident_assistant.py` is deterministic and local: it turns retained evidence
into an investigation narrative and never recommends automatic blocking.
`evidence_integrity.py` hashes result batches with SHA-256; setting the
`SENTINELSHIELD_EVIDENCE_KEY` environment variable upgrades receipts to
HMAC-SHA-256. The interface is algorithm-labelled so a future approved PQC
signer can be added without changing persisted evidence semantics. Run
`python -c "from supply_chain import generate; generate()"` to generate the
SBOM-style `sentinelshield_sbom.json` inventory.

### Phase 4 — privacy-reviewed sensing research

`wifi_sensing.py` accepts only consented, pre-aggregated sensing metrics. It
does not capture RF frames, identify people, or treat sensing as evidence that
an AP is malicious. It remains disabled by default.

- If no radio is found, inspect the adapter in Windows Settings and `netsh wlan show interfaces`.
- If scanning is denied, enable Windows Location services and use an appropriately privileged process where required.
- If an adapter fails, check `Scanner Status` and the partial-radio errors; one radio failure does not invalidate successful results from other radios.
- PyWiFi may expose cached scan results and does not provide a portable scan-completion event or channel partition API; very short waits may trade freshness for speed. Compare AP overlap in the benchmark before drawing conclusions.
- MAC vendor mapping is a small local OUI map, not a complete vendor registry.
- BLE and geolocation were not hardware-tested in this run. Multi-adapter operation was unit-tested with simulated radios but **not tested on physical multi-adapter hardware**.
- A result marked HIGH/CRITICAL is a detection lead, not proof of malicious intent. Enterprise, mesh, roaming, and dual-band deployments legitimately use multiple BSSIDs.
- Existing legacy async scanner modules remain present for compatibility/audit purposes but the canonical dashboard does not call them.
