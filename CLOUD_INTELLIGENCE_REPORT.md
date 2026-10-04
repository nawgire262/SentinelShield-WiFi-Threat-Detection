# Cloud Threat Intelligence Integration

## Dependency map

```text
dashboard.py ──> background_scanner.py ──> CloudIntelligenceEngine
       │                    │                     ├─ LocalReputation (data/bssid_reputation.csv)
       │                    │                     ├─ VirusTotalChecker (optional API key)
       │                    │                     ├─ AbuseIPDBChecker (optional API key)
       │                    │                     └─ OpenPhishChecker (local cached feed)
       │                    ├─ AlertLogger ──> alert_history.csv
       │                    ├─ HybridEnsembleDetector
       │                    └─ current_scan.csv / scan_history.csv
       └─ ReportGenerator <── current scan + alert history + cloud score columns
```

## Applied changes

- Added local-first threat datasets under `data/`.
- Added persistent BSSID reputation with automatic update history.
- Added optional, environment-variable-only VirusTotal and AbuseIPDB clients with retries, rate-limit handling, and neutral offline results.
- Added OpenPhish keyword matching and a locally cached feed.
- Added the unified cloud-risk engine:
  `Cloud Risk = (VirusTotal + AbuseIPDB + BSSID reputation + OpenPhish) / 4`.
- Integrated scanner score weighting:
  `ML 40% + rule risk 30% + cloud risk 20% + BSSID reputation 10%`.
- Added cloud score columns to current scan results and cloud visualizations to the dashboard/PDF.
- Added automatic reputation learning for HIGH and CRITICAL detections.

## Configuration

Set these environment variables only when external lookups are desired:

- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `FIREBASE_CREDENTIALS` (existing shared-feed integration)

The system is fully operational offline. No API key is stored in source code or CSV data.

## Validation

- Compiled the new package and all integration files.
- Verified local reputation add/check/update behavior.
- Verified an offline unified score using local reputation and OpenPhish keyword signals.
- Verified demo scanner output includes every cloud risk field.
- Verified a generated PDF remains valid and includes the cloud-summary section when cloud columns exist.

## Remaining deployment work

- Provider APIs need real keys and network egress to yield IP/domain reputation. Wi-Fi scan records do not normally include an IP, domain, or URL, so those provider calls remain intentionally neutral unless enrichment data is supplied.
- Review provider terms, rate limits, and retention requirements before enabling external lookups in production.
