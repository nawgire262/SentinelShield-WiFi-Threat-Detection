# Multi-Parameter Wi-Fi Detection Framework: physical sensor deployment

SentinelShield now treats every compatible Wi-Fi adapter exposed by Windows and
PyWiFi as an independent physical sensor. Connect two or more supported USB or
internal Wi-Fi adapters, place them at different monitoring locations, and run
the normal scanner. Each adapter scans independently; results are fused by
SSID/BSSID, while preserving sensor ID, RSSI observation, channel, sensor count,
and cross-sensor RSSI agreement.

The dashboard's **Analytics → Physical sensor status** table confirms which
sensors have contributed observations. Per-network fusion values are included
in the scan data and threat vectors. Raw observations are persisted in the
SQLite `sensor_observations` table.

Deployment notes:

- Use adapters that Windows exposes as separate Wi-Fi interfaces and whose
  drivers support scanning through PyWiFi.
- Give adapters physical separation; colocated adapters provide redundancy but
  not meaningful spatial diversity.
- One adapter remains supported, but the dashboard will report one active
  sensor and no cross-sensor agreement measurement.
- A large RSSI disagreement across two or more sensors contributes a bounded
  explainable risk signal; it does not independently classify an AP as rogue.
