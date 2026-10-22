# Automated Novelty-Driven Alert System

SentinelShield now fuses its existing adaptive risk classification with a separate, explainable novelty-alert layer. The novelty layer does not replace the scanner or ML models; it consumes the evidence already emitted in each scan row.

## Research novelty signals used

- **Cloud reputation:** a reputation hit or cloud risk score >= 75 is a strong trigger.
- **RAIM consistency:** an explicit RAIM flag or RAIM score >= 75 is a strong trigger.
- **Layer-2 behavior:** deauthentication/jamming detection or Layer-2 score >= 75 is a strong trigger.
- **Temporal RSSI variation:** RSSI range >= 18 dB or variance >= 36, with at least three observations.
- **Multi-AP/BSSID density:** three or more APs for one SSID is a weak indicator, not proof of an Evil Twin.
- **Fingerprint mismatch:** baseline similarity <= 0.65 is a weak indicator.
- **Isolation Forest:** sklearn prediction `-1` is treated as an anomaly. Other numeric values are intentionally not guessed because model artifacts can emit different score formats.
- **Hybrid model confidence:** fake-network confidence >= 80% is a supporting indicator.

## Alert decision

A strong evidence signal triggers a HIGH alert; two weak signals plus combined risk >= 50, or three weak signals, trigger a HIGH alert. Combined risk >= 85 or two strong indicators with sufficient novelty score raises severity to CRITICAL. The dashboard also preserves the existing adaptive risk threshold behavior. Each alert includes the original reasons plus novelty evidence, is written to `alert_history.csv`, and is sent through the existing in-app/desktop notification manager and any configured email/Telegram/SMS channels. Channel credentials are optional and remain outside source files.

## Run tests

```powershell
python -m unittest test_novelty_alert_engine.py
python -m py_compile dashboard.py novelty_alert_engine.py
```

## Important limitations

A dense SSID, RSSI variation, fingerprint mismatch, or anomaly-model output alone does not prove malicious intent. These are evidence signals for triage. Cloud lookups and remote delivery only work when their providers/credentials are configured. Validate the thresholds against a held-out, labelled dataset before reporting measured detection performance in the research paper.
