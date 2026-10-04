# SQLite Persistence and Real-Time Monitoring

## Storage dependency map

```text
BackgroundScanner ──> save_scan() ──> scans
        │                  │
        ├─ HIGH/CRITICAL ──> save_threat() ──> threats
        └─ AlertLogger ────> save_alert() ───> alerts
                                               │
                                     update_daily_summary()
                                               │
                                    daily_summary ──> Dashboard metrics/history
```

## Implemented

- Added `database_manager.py` with WAL-mode SQLite, indexes, locking, error handling, and safe connection lifetimes.
- Added `sentinelshield.db` initialization with `scans`, `alerts`, `threats`, and `daily_summary` tables.
- Added one-time legacy CSV import for `current_scan.csv`, `alert_history.csv`, and `threat_history.csv` when present.
- Preserved all CSV writes and exports; SQLite is an additional automatic persistence layer.
- Connected completed scans, detected HIGH/CRITICAL threats, and alerts to database writes.
- Added four live database-backed dashboard cards refreshed every five seconds.
- Added the Historical Analysis navigation page with daily scan/threat/alert trends, detection rate, critical percentage, daily averages, and weekly averages.
- Added Streamlit five-second caching for heavier dashboard database queries.

## SQL schema

```sql
CREATE TABLE scans (id INTEGER PRIMARY KEY, timestamp TEXT, ssid TEXT, bssid TEXT,
  channel REAL, signal_strength REAL, encryption TEXT, threat_score REAL, threat_level TEXT);
CREATE TABLE alerts (id INTEGER PRIMARY KEY, timestamp TEXT, ssid TEXT,
  alert_type TEXT, severity TEXT, description TEXT);
CREATE TABLE threats (id INTEGER PRIMARY KEY, timestamp TEXT, ssid TEXT, bssid TEXT,
  threat_type TEXT, risk_score REAL);
CREATE TABLE daily_summary (id INTEGER PRIMARY KEY, date TEXT UNIQUE,
  networks_found INTEGER, threats_detected INTEGER, alerts_generated INTEGER);
```

`database_manager.py` also creates timestamp, BSSID, and severity indexes and enables SQLite WAL mode.

## Integration and testing

1. Start the dashboard with `streamlit run dashboard.py`.
2. Run a live scan or the automatic demo fallback.
3. Confirm `sentinelshield.db` is created beside the application.
4. Open **Historical Analysis** to view database-backed trends and research metrics.
5. Confirm CSV files remain available for existing exports.

The automated smoke test inserted scan, alert, and threat records; queried every history/summary API; and compiled all modified modules.

## Dashboard appearance

At the top of every page, four responsive cards show total networks found, detected threats, critical alerts, and the latest scan timestamp. The **Historical Analysis** page presents daily scan volume plus a combined threat/alert trend, followed by detection and average-rate metrics.

## Validation

- Database was created successfully.
- Inserted and queried scan, alert, threat, daily-summary, and monitoring-metric records.
- Python compilation passed for all modified modules.

## Operational notes

- SQLite indexes cover scan timestamps/BSSIDs, alert timestamps/severity, and threat timestamps/BSSIDs to support large historical datasets.
- SQLite WAL mode supports concurrent dashboard reads and background scanner writes efficiently on a local disk.
