"""Thread-safe SQLite persistence for SentinelShield scan intelligence."""

from __future__ import annotations

import csv
import logging
import sqlite3
import threading
from contextlib import contextmanager
import uuid
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from runtime_config import load_runtime_config

LOGGER = logging.getLogger(__name__)
DB_PATH = Path(__file__).resolve().parent / "sentinelshield.db"
_LOCK = threading.RLock()


@contextmanager
def _connection():
    connection = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_database() -> None:
    """Create indexed tables and migrate legacy CSV data once."""
    with _LOCK:
        try:
            with _connection() as connection:
                connection.executescript("""
                    PRAGMA journal_mode=WAL;
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, ssid TEXT,
                        bssid TEXT, channel REAL, signal_strength REAL, encryption TEXT,
                        threat_score REAL, threat_level TEXT);
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, ssid TEXT,
                        alert_type TEXT, severity TEXT, description TEXT);
                    CREATE TABLE IF NOT EXISTS threats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, ssid TEXT,
                        bssid TEXT, threat_type TEXT, risk_score REAL);
                    CREATE TABLE IF NOT EXISTS anomalies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, ssid TEXT,
                        bssid TEXT, anomaly_score REAL, confidence REAL, risk_level TEXT);
                    CREATE TABLE IF NOT EXISTS sensor_observations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, sensor_id TEXT NOT NULL,
                        ssid TEXT, bssid TEXT, rssi REAL, channel REAL);
                    CREATE TABLE IF NOT EXISTS daily_summary (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT NOT NULL UNIQUE,
                        networks_found INTEGER NOT NULL DEFAULT 0, threats_detected INTEGER NOT NULL DEFAULT 0,
                        alerts_generated INTEGER NOT NULL DEFAULT 0);
                    CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS scan_runs (
                        scan_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT NOT NULL,
                        scan_duration_ms REAL NOT NULL DEFAULT 0, processing_time_ms REAL NOT NULL DEFAULT 0,
                        detection_latency_ms REAL NOT NULL DEFAULT 0, scan_mode TEXT NOT NULL DEFAULT 'balanced',
                        adapter_count INTEGER NOT NULL DEFAULT 0, aps_discovered INTEGER NOT NULL DEFAULT 0,
                        unique_bssids INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'completed');
                    CREATE TABLE IF NOT EXISTS wifi_observations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, timestamp TEXT NOT NULL,
                        adapter_id TEXT, adapter_name TEXT, ssid TEXT, bssid TEXT, channel INTEGER,
                        frequency_mhz REAL, rssi_dbm REAL, security TEXT, vendor TEXT,
                        fingerprint_hash TEXT, risk_score REAL, threat_level TEXT, detection_reason TEXT,
                        scan_duration_ms REAL, FOREIGN KEY(scan_id) REFERENCES scan_runs(scan_id) ON DELETE CASCADE);
                    CREATE TABLE IF NOT EXISTS evidence_receipts (
                        scan_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL, digest TEXT NOT NULL,
                        signature TEXT, created_at TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS analyst_feedback (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, bssid TEXT NOT NULL,
                        verdict TEXT NOT NULL, analyst TEXT, note TEXT);
                    CREATE INDEX IF NOT EXISTS idx_wifi_observations_scan ON wifi_observations(scan_id);
                    CREATE INDEX IF NOT EXISTS idx_wifi_observations_bssid_time ON wifi_observations(bssid, timestamp);
                    CREATE INDEX IF NOT EXISTS idx_scan_runs_completed ON scan_runs(completed_at);
                    CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_scans_bssid ON scans(bssid);
                    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                    CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_threats_bssid ON threats(bssid);
                    CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_anomalies_bssid ON anomalies(bssid);
                    CREATE INDEX IF NOT EXISTS idx_sensor_observations_timestamp ON sensor_observations(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_sensor_observations_sensor_id ON sensor_observations(sensor_id);
                """)
                migrated = connection.execute("SELECT 1 FROM schema_migrations WHERE name = 'csv_initial_import'").fetchone()
                if not migrated:
                    _migrate_csv(connection)
                    _rebuild_daily_summaries(connection)
                    connection.execute("INSERT INTO schema_migrations(name, applied_at) VALUES (?, ?)", ("csv_initial_import", _now()))
        except sqlite3.Error:
            LOGGER.exception("Could not initialize SentinelShield SQLite database")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _migrate_csv(connection: sqlite3.Connection) -> None:
    """Import legacy CSV records once; malformed rows are skipped safely."""
    for filename, handler in (("current_scan.csv", _insert_scan), ("alert_history.csv", _insert_alert), ("threat_history.csv", _insert_threat)):
        path = Path(filename)
        if not path.exists():
            continue
        try:
            with path.open(newline="", encoding="utf-8") as source:
                for row in csv.DictReader(source):
                    handler(connection, row, commit=False)
        except (OSError, csv.Error):
            LOGGER.exception("CSV migration skipped for %s", filename)
    connection.commit()


def _rebuild_daily_summaries(connection: sqlite3.Connection) -> None:
    dates = set()
    for table in ("scans", "threats", "alerts"):
        dates.update(row[0] for row in connection.execute(f"SELECT DISTINCT substr(timestamp, 1, 10) FROM {table}") if row[0])
    for target in dates:
        prefix = f"{target}%"
        counts = [connection.execute(f"SELECT COUNT(*) FROM {table} WHERE timestamp LIKE ?", (prefix,)).fetchone()[0] for table in ("scans", "threats", "alerts")]
        connection.execute("INSERT INTO daily_summary(date, networks_found, threats_detected, alerts_generated) VALUES (?, ?, ?, ?) ON CONFLICT(date) DO UPDATE SET networks_found=excluded.networks_found, threats_detected=excluded.threats_detected, alerts_generated=excluded.alerts_generated", (target, *counts))


def _number(value: Any) -> float:
    try: return float(value or 0)
    except (TypeError, ValueError): return 0.0


def _insert_scan(connection: sqlite3.Connection, network: Dict[str, Any], commit=True) -> None:
    connection.execute("INSERT INTO scans(timestamp, ssid, bssid, channel, signal_strength, encryption, threat_score, threat_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (
        network.get("timestamp") or network.get("Timestamp") or _now(), network.get("SSID") or network.get("ssid"), network.get("BSSID") or network.get("bssid"),
        _number(network.get("Channel") or network.get("channel")), _number(network.get("RSSI") or network.get("signal_strength")), network.get("Security") or network.get("encryption"),
        _number(network.get("Combined_Risk") or network.get("threat_score")), network.get("Threat_Level") or network.get("threat_level") or "SAFE"))
    if commit: connection.commit()


def _insert_alert(connection: sqlite3.Connection, alert: Dict[str, Any], commit=True) -> None:
    severity = str(alert.get("severity") or alert.get("Severity") or ("CRITICAL" if _number(alert.get("Risk")) >= 75 else "HIGH")).upper()
    connection.execute("INSERT INTO alerts(timestamp, ssid, alert_type, severity, description) VALUES (?, ?, ?, ?, ?)", (
        alert.get("timestamp") or alert.get("Time") or _now(), alert.get("ssid") or alert.get("SSID"), alert.get("alert_type") or "Threat Detection", severity, alert.get("description") or alert.get("Reason") or "Detected threat"))
    if commit: connection.commit()


def _insert_threat(connection: sqlite3.Connection, threat: Dict[str, Any], commit=True) -> None:
    connection.execute("INSERT INTO threats(timestamp, ssid, bssid, threat_type, risk_score) VALUES (?, ?, ?, ?, ?)", (
        threat.get("timestamp") or threat.get("Time") or _now(), threat.get("ssid") or threat.get("SSID"), threat.get("bssid") or threat.get("BSSID"),
        threat.get("threat_type") or threat.get("Threat_Level") or "Suspected Evil Twin", _number(threat.get("risk_score") or threat.get("Risk") or threat.get("Combined_Risk"))))
    if commit: connection.commit()


def _insert_anomaly(connection: sqlite3.Connection, anomaly: Dict[str, Any], commit=True) -> None:
    connection.execute("INSERT INTO anomalies(timestamp, ssid, bssid, anomaly_score, confidence, risk_level) VALUES (?, ?, ?, ?, ?, ?)", (
        anomaly.get("timestamp") or _now(), anomaly.get("ssid") or anomaly.get("SSID"), anomaly.get("bssid") or anomaly.get("BSSID"),
        _number(anomaly.get("anomaly_score") or anomaly.get("Anomaly_Score")), _number(anomaly.get("confidence") or anomaly.get("Anomaly_Confidence")),
        anomaly.get("risk_level") or anomaly.get("Threat_Level") or "MEDIUM"))
    if commit: connection.commit()


def _insert_sensor_observation(connection: sqlite3.Connection, observation: Dict[str, Any], commit=True) -> None:
    connection.execute("INSERT INTO sensor_observations(timestamp, sensor_id, ssid, bssid, rssi, channel) VALUES (?, ?, ?, ?, ?, ?)", (
        observation.get("timestamp") or _now(), observation.get("sensor_id") or "unknown",
        observation.get("ssid") or observation.get("SSID"), observation.get("bssid") or observation.get("BSSID"),
        _number(observation.get("rssi")), _number(observation.get("channel"))))
    if commit: connection.commit()


def _save(handler, payload: Dict[str, Any]) -> None:
    init_database()
    with _LOCK:
        try:
            with _connection() as connection:
                handler(connection, payload)
            update_daily_summary()
        except sqlite3.Error:
            LOGGER.exception("Database write failed")


def save_scan(network: Dict[str, Any]) -> None: _save(_insert_scan, network)
def save_alert(alert: Dict[str, Any]) -> None: _save(_insert_alert, alert)
def save_threat(threat: Dict[str, Any]) -> None: _save(_insert_threat, threat)
def save_anomaly(anomaly: Dict[str, Any]) -> None: _save(_insert_anomaly, anomaly)
def save_sensor_observation(observation: Dict[str, Any]) -> None: _save(_insert_sensor_observation, observation)


def save_wifi_scan(result: Dict[str, Any]) -> bool:
    """Persist one enriched controller run atomically; retention is bounded."""
    init_database()
    scan_id = str(result.get("scan_id") or uuid.uuid4())
    observations = result.get("results") or []
    config = load_runtime_config()
    cutoff = (datetime.now() - timedelta(days=config["persistence"]["retention_days"])).strftime("%Y-%m-%dT%H:%M:%S")
    try:
        with _LOCK:
            with _connection() as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO scan_runs(scan_id, started_at, completed_at, scan_duration_ms, processing_time_ms, detection_latency_ms, scan_mode, adapter_count, aps_discovered, unique_bssids, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, result.get("started_at") or _now(), result.get("completed_at") or _now(),
                     _number(result.get("scan_duration_ms")), _number(result.get("processing_time_ms")),
                     _number(result.get("detection_latency_ms")), result.get("scan_mode", "balanced"),
                     int(result.get("adapter_count", 0)), int(result.get("aps_discovered", len(observations))),
                     int(result.get("unique_bssids", len({item.get("bssid") for item in observations}))),
                     "completed" if observations else "empty"),
                )
                connection.executemany(
                    "INSERT INTO wifi_observations(scan_id, timestamp, adapter_id, adapter_name, ssid, bssid, channel, frequency_mhz, rssi_dbm, security, vendor, fingerprint_hash, risk_score, threat_level, detection_reason, scan_duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [(
                        scan_id, item.get("timestamp") or _now(), item.get("adapter_id"), item.get("adapter_name"),
                        item.get("ssid"), item.get("bssid"), item.get("channel"), item.get("frequency_mhz"),
                        item.get("rssi_dbm"), item.get("security"), item.get("vendor"), item.get("fingerprint_hash"),
                        _number(item.get("risk_score")), item.get("threat_level"), item.get("detection_reason"),
                        _number(item.get("scan_duration_ms")),
                    ) for item in observations],
                )
                integrity = result.get("integrity_receipt") or {}
                if integrity.get("digest"):
                    connection.execute(
                        "INSERT OR REPLACE INTO evidence_receipts(scan_id, algorithm, digest, signature, created_at) VALUES (?, ?, ?, ?, ?)",
                        (scan_id, integrity.get("algorithm", "SHA-256"), integrity["digest"], integrity.get("signature"), _now()),
                    )
                connection.execute("DELETE FROM wifi_observations WHERE timestamp < ?", (cutoff,))
                connection.execute("DELETE FROM scan_runs WHERE completed_at < ?", (cutoff,))
        return True
    except (sqlite3.Error, TypeError, ValueError):
        LOGGER.exception("Enriched Wi-Fi scan persistence failed")
        return False


def save_analyst_feedback(item: Dict[str, Any]) -> bool:
    """Persist an analyst verdict separately from baseline trust state."""
    init_database()
    try:
        with _LOCK:
            with _connection() as connection:
                connection.execute(
                    "INSERT INTO analyst_feedback(timestamp, bssid, verdict, analyst, note) VALUES (?, ?, ?, ?, ?)",
                    (item.get("timestamp") or _now(), item.get("bssid"), item.get("verdict"), item.get("analyst"), item.get("note")),
                )
        return True
    except sqlite3.Error:
        LOGGER.exception("Analyst feedback persistence failed")
        return False


def get_recent_wifi_observations(limit: int = 500) -> List[Dict[str, Any]]:
    return _query("SELECT * FROM wifi_observations ORDER BY id DESC LIMIT ?", (max(1, min(10000, int(limit))),))


def get_recent_scan_runs(limit: int = 100) -> List[Dict[str, Any]]:
    return _query("SELECT * FROM scan_runs ORDER BY completed_at DESC LIMIT ?", (max(1, min(5000, int(limit))),))


def update_daily_summary(day: Optional[str] = None) -> None:
    target = day or date.today().isoformat()
    with _LOCK:
        try:
            with _connection() as connection:
                prefix = f"{target}%"
                scans = connection.execute("SELECT COUNT(*) FROM scans WHERE timestamp LIKE ?", (prefix,)).fetchone()[0]
                threats = connection.execute("SELECT COUNT(*) FROM threats WHERE timestamp LIKE ?", (prefix,)).fetchone()[0]
                alerts = connection.execute("SELECT COUNT(*) FROM alerts WHERE timestamp LIKE ?", (prefix,)).fetchone()[0]
                connection.execute("INSERT INTO daily_summary(date, networks_found, threats_detected, alerts_generated) VALUES (?, ?, ?, ?) ON CONFLICT(date) DO UPDATE SET networks_found=excluded.networks_found, threats_detected=excluded.threats_detected, alerts_generated=excluded.alerts_generated", (target, scans, threats, alerts))
        except sqlite3.Error: LOGGER.exception("Daily summary update failed")


def _query(sql: str, parameters=()) -> List[Dict[str, Any]]:
    init_database()
    try:
        with _connection() as connection: return [dict(row) for row in connection.execute(sql, parameters).fetchall()]
    except sqlite3.Error:
        LOGGER.exception("Database query failed"); return []

def get_scan_history(limit=1000): return _query("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
def get_alert_history(limit=1000): return _query("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
def get_threat_history(limit=1000): return _query("SELECT * FROM threats ORDER BY id DESC LIMIT ?", (limit,))
def get_anomaly_history(limit=1000): return _query("SELECT * FROM anomalies ORDER BY id DESC LIMIT ?", (limit,))
def get_sensor_statistics() -> List[Dict[str, Any]]:
    return _query("SELECT sensor_id, COUNT(*) AS observations, COUNT(DISTINCT bssid) AS networks_seen, MAX(timestamp) AS last_seen FROM sensor_observations GROUP BY sensor_id ORDER BY sensor_id")
def get_anomaly_analytics() -> Dict[str, Any]:
    """Compact aggregate data for fast dashboard refreshes."""
    init_database()
    try:
        with _connection() as connection:
            total = connection.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
            today = connection.execute("SELECT COUNT(*) FROM anomalies WHERE substr(timestamp, 1, 10) = ?", (date.today().isoformat(),)).fetchone()[0]
            week = connection.execute("SELECT COUNT(*) FROM anomalies WHERE timestamp >= ?", ((datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'),)).fetchone()[0]
            scans = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            daily = [dict(row) for row in connection.execute("SELECT substr(timestamp, 1, 10) AS date, COUNT(*) AS anomalies FROM anomalies GROUP BY substr(timestamp, 1, 10) ORDER BY date")]
            ssids = [dict(row) for row in connection.execute("SELECT ssid, COUNT(*) AS anomalies FROM anomalies GROUP BY ssid ORDER BY anomalies DESC LIMIT 10")]
            bssids = [dict(row) for row in connection.execute("SELECT bssid, COUNT(*) AS anomalies FROM anomalies GROUP BY bssid ORDER BY anomalies DESC LIMIT 10")]
            return {"total": total, "today": today, "week": week, "rate": (total / scans * 100) if scans else 0.0, "daily": daily, "ssids": ssids, "bssids": bssids}
    except sqlite3.Error:
        LOGGER.exception("Anomaly analytics query failed")
        return {"total": 0, "today": 0, "week": 0, "rate": 0.0, "daily": [], "ssids": [], "bssids": []}
def get_daily_statistics(limit=90): return _query("SELECT * FROM daily_summary ORDER BY date DESC LIMIT ?", (limit,))

def get_monitoring_metrics() -> Dict[str, Any]:
    init_database()
    try:
        with _connection() as connection:
            enriched = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_runs'").fetchone()
            if enriched:
                count = connection.execute("SELECT COALESCE(SUM(aps_discovered), 0) FROM scan_runs").fetchone()[0]
                last_scan = (connection.execute("SELECT completed_at FROM scan_runs ORDER BY completed_at DESC LIMIT 1").fetchone() or [None])[0]
            else:
                count = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                last_scan = (connection.execute("SELECT timestamp FROM scans ORDER BY id DESC LIMIT 1").fetchone() or [None])[0]
            return {"networks_found": count, "threats_detected": connection.execute("SELECT COUNT(*) FROM threats").fetchone()[0], "critical_alerts": connection.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'").fetchone()[0], "last_scan": last_scan}
    except sqlite3.Error:
        LOGGER.exception("Monitoring metric query failed"); return {"networks_found": 0, "threats_detected": 0, "critical_alerts": 0, "last_scan": None}
