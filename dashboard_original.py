"""SentinelShield unified Streamlit dashboard. Run with ``streamlit run dashboard.py``."""
from __future__ import annotations

import csv
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from adaptive_thresholds import AdaptiveThresholdEngine
from scan_controller import ScanController
from runtime_config import CONFIG_PATH, load_runtime_config, save_runtime_config
from wifi_fingerprint import WiFiFingerprintStore
from analyst_feedback import record_feedback
from incident_assistant import explain

try:
    from threat_intelligence import get_threat_intelligence
except Exception:
    get_threat_intelligence = None

try:
    from notification_manager import NotificationManager
except Exception:
    NotificationManager = None

try:
    from streamlit_autorefresh import st_autorefresh
except ImportError:
    st_autorefresh = None

ROOT = Path(__file__).resolve().parent
SCAN_FILE = ROOT / "current_scan.csv"
ALERT_FILE = ROOT / "alert_history.csv"
FINGERPRINT_FILE = ROOT / "fingerprints.json"
AP_BASELINE_FILE = ROOT / "wifi_fingerprint_baseline.json"
SETTINGS_FILE = ROOT / "dashboard_settings.json"
THRESHOLD_STATE_FILE = ROOT / "adaptive_threshold_state.json"

st.set_page_config(page_title="SentinelShield", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp {background:#050b14;color:#edf8ff}
[data-testid="stSidebar"] {background:#081522;border-right:1px solid #17344a}
[data-testid="stHeader"] {background:rgba(5,11,20,.96)}
.block-container {padding-top:1.5rem;max-width:1500px}
h1,h2,h3 {color:#27d7ff!important}
.hero,.panel {background:linear-gradient(135deg,#0c2135,#07111d);border:1px solid #1a4c69;border-radius:16px;padding:20px;margin-bottom:14px}
.hero-title {font-size:36px;font-weight:800;color:#27d7ff}
.muted {color:#8da3b5}
[data-testid="stMetric"] {background:#0b1d2e;border:1px solid #1a4560;border-radius:12px;padding:10px}
.alert-banner {background:linear-gradient(90deg,#5c0715,#9e1025,#5c0715);border:2px solid #ff304f;border-radius:14px;padding:18px;text-align:center;color:white;font-weight:800}
</style>
""", unsafe_allow_html=True)


def engine() -> AdaptiveThresholdEngine:
    return AdaptiveThresholdEngine(state_path=THRESHOLD_STATE_FILE)


def read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path, on_bad_lines="skip", engine="python")
    except Exception:
        return pd.DataFrame()


def number(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return result if pd.notna(result) else default
    except (TypeError, ValueError, OverflowError):
        return default


def risk_series(df: pd.DataFrame) -> pd.Series:
    for column in ("Combined_Risk", "Risk_Score", "Threat_Score", "ML_Risk", "Risk", "risk"):
        if column in df.columns:
            return pd.to_numeric(df[column], errors="coerce").fillna(0).clip(0, 100)
    return pd.Series(0.0, index=df.index)


def classify(df: pd.DataFrame, thresholds: dict[str, float] | None = None) -> pd.DataFrame:
    if df.empty:
        return df.copy()
    cuts = thresholds or engine().get_thresholds()[0]
    out = df.copy()
    out["Combined_Risk"] = risk_series(out)
    score = out["Combined_Risk"]
    out["Threat_Level"] = "SAFE"
    out.loc[score >= cuts["medium"], "Threat_Level"] = "MEDIUM"
    out.loc[score >= cuts["high"], "Threat_Level"] = "HIGH"
    out.loc[score >= cuts["critical"], "Threat_Level"] = "CRITICAL"
    return out


def normalise(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df.copy()
    out = df.copy()
    for old, new in (("Signal", "RSSI"), ("Risk_Score", "Combined_Risk"), ("Threat_Score", "Combined_Risk"), ("Risk", "Combined_Risk"), ("risk", "Combined_Risk"), ("Status", "Threat_Level"), ("Reason", "Reasons")):
        if old in out and new not in out:
            out[new] = out[old]
    if "SSID" not in out:
        out["SSID"] = "Unknown"
    return out


def windows_scan_hint() -> str | None:
    if os.name != "nt":
        return None
    try:
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, timeout=8, check=False)
        output = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
    except (OSError, subprocess.TimeoutExpired):
        return None
    location = "location" in output and any(term in output for term in ("permission", "turn on", "services"))
    elevated = "requires elevation" in output or "error 5" in output
    if location or elevated:
        actions = []
        if location:
            actions.append("enable Windows Location services in Settings > Privacy & security > Location")
        if elevated:
            actions.append("restart VS Code/terminal as Administrator")
        return "Windows is blocking WLAN scans. Please " + " and ".join(actions) + ", then restart the dashboard."
    if "no wireless interfaces" in output:
        return "Windows reports no wireless adapter. Enable Wi-Fi and retry."
    return None


def scan_to_frame(findings: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for item in findings:
        signals = item.get("signals", []) or item.get("rssi_samples_dbm", []) or []
        reasons = item.get("reasons", []) or []
        temporal = item.get("temporal", {}) or {}
        scores = item.get("evidence_scores", {}) or {}
        ml = item.get("ml") or {}
        rows.append({
            "SSID": item.get("ssid", item.get("SSID", "Unknown")),
            "BSSID": item.get("bssid", item.get("BSSID", "N/A")),
            "RSSI": item.get("rssi_dbm", item.get("rssi", item.get("RSSI", signals[-1] if signals else "N/A"))),
            "Channel": item.get("channel", "N/A"),
            "Frequency": item.get("frequency_mhz", "N/A"),
            "Security": item.get("security", "Unknown"),
            "Vendor": item.get("vendor", "Unknown"),
            "Fingerprint_Similarity": item.get("fingerprint_similarity") if item.get("fingerprint_similarity") is not None else "N/A",
            "Fingerprint_Hash": item.get("fingerprint_hash", ""),
            "Confidence": item.get("confidence", "UNKNOWN"),
            "RF_Prediction": item.get("RF_Prediction", ml.get("rf_fake_probability")),
            "KNN_Prediction": item.get("KNN_Prediction", ml.get("knn_fake_probability")),
            "Isolation_Forest": item.get("Isolation_Forest", ml.get("isolation_anomaly_score")),
            "Meta_Model": "Fake" if (ml.get("fake_probability") or 0) >= 0.5 else "Legit" if ml else "N/A",
            "Meta_Confidence": round(float(ml.get("fake_probability", 0)) * 100, 1) if ml else "N/A",
            "ML_Risk": item.get("ML_Risk", ml.get("risk_score")),
            "Combined_Risk": item.get("risk_score", item.get("risk", item.get("Combined_Risk", 0))),
            "Threat_Score": item.get("risk_score", item.get("risk", item.get("Combined_Risk", 0))),
            "Threat_Level": item.get("threat_level", item.get("Threat_Level", "LOW")),
            "AP_Count": item.get("ap_count", item.get("density", {}).get("ssid_bssid_count", 1)),
            "Signal_Fluctuation": item.get("signal_fluctuation", temporal.get("long_term_range", 0)),
            "Signal_History": ", ".join(map(str, signals)),
            "Signal_Variance": temporal.get("rssi_variance"),
            "Signal_StdDev": temporal.get("rssi_stddev"),
            "Signal_Delta": temporal.get("rssi_delta"),
            "Observation_Count": temporal.get("sample_count", len(signals)),
            "Adapter_ID": item.get("adapter_id", ",".join(item.get("adapter_ids", []))),
            "Adapter_Name": item.get("adapter_name", ""),
            "Scan_ID": item.get("scan_id", ""),
            "Scan_Duration_ms": item.get("scan_duration_ms", 0),
            "Detection_Latency_ms": item.get("detection_latency_ms", 0),
            "Evidence_JSON": json.dumps(scores, ensure_ascii=False),
            "Context_JSON": json.dumps(item.get("context") or {}, ensure_ascii=False),
            "Reasons": "; ".join(map(str, reasons)) or item.get("detection_reason", "No major anomaly"),
            "Scan_Time": item.get("timestamp", now),
        })
    return pd.DataFrame(rows)


def get_scan_controller() -> ScanController:
    controller = st.session_state.get("scan_controller")
    if controller is None:
        controller = ScanController()
        st.session_state["scan_controller"] = controller
    return controller


def persist_alert(alert: dict[str, Any]) -> None:
    st.session_state["alerts"].insert(0, alert)
    try:
        header_needed = not ALERT_FILE.exists() or ALERT_FILE.stat().st_size == 0
        with ALERT_FILE.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(alert))
            if header_needed:
                writer.writeheader()
            writer.writerow(alert)
    except OSError as exc:
        st.warning(f"Could not save alert history: {exc}")


def notify(alert: dict[str, Any]) -> None:
    if st.session_state.get("sound_enabled") and os.name == "nt":
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass
    if st.session_state.get("desktop_enabled") and NotificationManager:
        try:
            NotificationManager().notify("SentinelShield Wi-Fi Threat Alert", f"{alert['SSID']} — {alert['Risk']:.0f}%\n{alert['Reason'][:150]}", 10)
        except Exception:
            pass


def process_alerts(df: pd.DataFrame) -> None:
    if df.empty or not st.session_state.get("critical_alerts_enabled", True):
        return
    for _, row in df.iterrows():
        if str(row.get("Threat_Level", "")).upper() != "CRITICAL":
            continue
        risk = number(row.get("Combined_Risk"))
        ssid, bssid = str(row.get("SSID", "Unknown")), str(row.get("BSSID", "Unknown"))
        key = (ssid, bssid, round(risk), str(row.get("Scan_Time", "")))
        if key in st.session_state["alert_keys"]:
            continue
        st.session_state["alert_keys"].add(key)
        alert = {"Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "SSID": ssid, "BSSID": bssid, "Risk": round(risk, 1), "Level": "CRITICAL", "Reason": str(row.get("Reasons", "Critical adaptive risk threshold exceeded"))}
        persist_alert(alert)
        notify(alert)


def adaptive_scan_update(df: pd.DataFrame) -> pd.DataFrame:
    learner = engine()
    cuts, mode = learner.get_thresholds()
    result = classify(df, cuts)
    learner.update(risk_series(result).tolist())
    st.session_state["last_scan_thresholds"] = {"thresholds": cuts, "mode": mode}
    return result


def render_table(df: pd.DataFrame, columns: list[str] | None = None, height: int = 430) -> None:
    if df.empty:
        st.info("No data available yet.")
    else:
        visible = [col for col in (columns or list(df.columns)) if col in df.columns]
        display = df[visible].copy()
        for column in display.columns:
            if str(display[column].dtype) in {"object", "str", "string"}:
                def display_value(value: Any) -> str:
                    if value is None:
                        return ""
                    if isinstance(value, (list, tuple, dict, set)):
                        return json.dumps(value, ensure_ascii=False, default=str)
                    try:
                        missing = pd.isna(value)
                        if not hasattr(missing, "__len__") and bool(missing):
                            return ""
                    except (TypeError, ValueError):
                        pass
                    return str(value)

                display[column] = display[column].map(display_value)
        st.dataframe(display, width="stretch", hide_index=True, height=height)


def page_home(df: pd.DataFrame) -> None:
    summary = engine().summary()
    levels = df.get("Threat_Level", pd.Series(index=df.index, dtype=str)).astype(str).str.upper()
    safe, medium, high, critical = (int(levels.eq(label).sum()) for label in ("SAFE", "MEDIUM", "HIGH", "CRITICAL"))
    confidence = df.get("Confidence", pd.Series("UNKNOWN", index=df.index, dtype=str)).fillna("UNKNOWN").astype(str).str.upper()
    st.markdown('<div class="hero"><div class="hero-title">🛡️ SentinelShield</div><div>Wi-Fi Evil Twin Detection & Wireless Threat Intelligence Command Center</div></div>', unsafe_allow_html=True)
    cols = st.columns(4)
    cols[0].metric("Networks discovered", len(df))
    cols[1].metric("High / critical", high + critical, f"High ≥ {summary['thresholds']['high']:.1f}%")
    cols[2].metric("Critical", critical, f"≥ {summary['thresholds']['critical']:.1f}%")
    cols[3].metric("Safe", safe, f"< {summary['thresholds']['medium']:.1f}%")
    cols = st.columns(4)
    cols[0].metric("Known APs", int(confidence.isin(["TRUSTED", "ESTABLISHED"]).sum()))
    cols[1].metric("Unknown / observed", int(confidence.isin(["UNKNOWN", "OBSERVED"]).sum()))
    cols[2].metric("Suspicious baseline", int(confidence.eq("SUSPICIOUS").sum()))
    cols[3].metric("Potential rogue", high + critical, help="High risk is an investigation signal, not a definitive attribution.")
    st.subheader("Scanner health and performance")
    controller = st.session_state.get("scan_controller")
    if controller:
        status = controller.status()
        perf = controller.performance_summary()
        a, b, c, d = st.columns(4)
        a.metric("Scanner", status.get("status", "idle").upper())
        b.metric("Radio mode", status.get("adapter_mode", "not scanned"))
        c.metric("Adapters", status.get("adapter_count", 0))
        d.metric("Last scan duration", f"{status['scan_duration_ms']:.0f} ms" if status.get("scan_duration_ms") is not None else "—")
        if perf["samples"]:
            st.caption(f"Rolling measurements: average {perf['average_scan_ms']:.0f} ms · median {perf['median_scan_ms']:.0f} ms · P95 {perf['p95_scan_ms']:.0f} ms · average detection latency {perf['average_detection_latency_ms']:.0f} ms")
    else:
        st.info("Scanner idle. Open Live Wi-Fi Scan and press Start Scanner.")
    st.subheader("Threat distribution")
    st.bar_chart(pd.Series({"SAFE": safe, "MEDIUM": medium, "HIGH": high, "CRITICAL": critical}))
    st.subheader("Highest-risk networks")
    render_table(df.sort_values("Combined_Risk", ascending=False), ["SSID", "BSSID", "RSSI", "Security", "Combined_Risk", "Threat_Level", "Reasons"], 380)


def page_live_scan() -> None:
    st.header("📡 Live Wi-Fi Scan")
    st.caption("Background scanning with adaptive verification; Stop prevents subsequent work and does not interrupt a driver call in progress.")
    controller = get_scan_controller()
    status = controller.status()
    mode = st.selectbox("Scan mode", ["auto", "fast", "balanced", "deep"], index=0, help="Auto uses a fast pass and starts deep verification when new or changed AP evidence appears.")
    a, b, c, d = st.columns(4)
    start = a.button("▶ Start Scanner", type="primary", disabled=status.get("status") in {"queued", "scanning", "deep-verification", "analyzing", "stopping"}, width="stretch")
    stop = b.button("■ Stop Scanner", disabled=status.get("status") not in {"queued", "scanning", "deep-verification", "analyzing", "stopping"}, width="stretch")
    load_saved = c.button("📂 Load Saved Scan", width="stretch")
    clear = d.button("🧹 Clear Display", width="stretch")

    if start:
        hint = windows_scan_hint()
        if hint:
            st.error(hint)
        elif not controller.start(mode):
            st.warning("A scan is already running.")
        else:
            st.session_state["scan_mode"] = mode
            st.rerun()
    if stop and controller.stop():
        st.info("Stop requested. An in-flight Windows WLAN driver call must finish safely.")
    if load_saved:
        st.session_state["scan"] = classify(normalise(read_csv(SCAN_FILE)))
        st.success("Saved scan loaded.")
    if clear:
        st.session_state["scan"] = pd.DataFrame()
        st.success("Displayed results cleared; scan history and fingerprint baseline were retained.")

    status = controller.status()
    running = status.get("status") in {"queued", "scanning", "deep-verification", "analyzing", "stopping"}
    if running and st_autorefresh is not None:
        st_autorefresh(interval=700, key="scan_controller_poll")
    st.status(f"Scanner: {status.get('status', 'idle').replace('-', ' ').upper()} · {status.get('adapter_mode', 'detecting radios')} · mode {status.get('mode', '—')}", state="running" if running else "complete" if status.get("status") == "completed" else "error" if status.get("status") == "error" else "complete", expanded=running)
    if status.get("error"):
        st.error(status["error"])
    for error in status.get("errors", []):
        st.warning(error)

    if status.get("status") == "completed" and status.get("scan_id") != st.session_state.get("processed_controller_scan_id"):
        result = controller.latest()
        if result:
            found = scan_to_frame(result.get("results", []))
            found["Scan_ID"] = result["scan_id"]
            found["Adapter_Mode"] = result["adapter_mode"]
            found["Adapter_Count"] = result["adapter_count"]
            found["Scan_Duration_ms"] = result["scan_duration_ms"]
            found["Detection_Latency_ms"] = result["detection_latency_ms"]
            found = adaptive_scan_update(found)
            found.to_csv(SCAN_FILE, index=False)
            st.session_state["scan"] = found
            st.session_state["processed_controller_scan_id"] = result["scan_id"]
            st.session_state["last_scan"] = result["completed_at"]
            process_alerts(found)
            st.success(f"Scan completed — {len(found)} AP(s), {result['scan_duration_ms']:.0f} ms scan, {result['detection_latency_ms']:.0f} ms detection latency.")
    elif status.get("status") == "empty":
        st.warning("No AP observations were returned. Check adapter state/permissions; partial adapter failures are listed above.")

    adapters = status.get("adapters", [])
    if adapters:
        st.subheader("Scanner Status")
        st.caption(f"Mode: {status.get('adapter_mode', 'single-adapter')} · Adapters available: {len(adapters)}")
        render_table(pd.DataFrame(adapters), ["name", "mac_address", "interface_state", "capabilities", "backend"], 200)
    metrics = controller.performance_summary()
    if metrics["samples"]:
        st.subheader("Measured performance")
        p = st.columns(4)
        p[0].metric("Average scan", f"{metrics['average_scan_ms']:.0f} ms")
        p[1].metric("Median scan", f"{metrics['median_scan_ms']:.0f} ms")
        p[2].metric("P95 scan", f"{metrics['p95_scan_ms']:.0f} ms")
        p[3].metric("Detection latency", f"{metrics['average_detection_latency_ms']:.0f} ms avg")

    df = st.session_state.get("scan", pd.DataFrame())
    st.caption(f"APs in current result: {len(df)} · Last scan: {st.session_state.get('last_scan', 'not run in this session')}")
    render_table(df, ["SSID", "BSSID", "RSSI", "Channel", "Frequency", "Security", "Vendor", "Confidence", "Combined_Risk", "Threat_Level", "Reasons"], 460)
    if not df.empty:
        st.subheader("Network investigation / evidence")
        for _, row in df.iterrows():
            with st.expander(f"{row.get('SSID', 'Unknown')} · {row.get('Threat_Level', 'LOW')} · {number(row.get('Combined_Risk')):.0f}%"):
                st.write(f"BSSID: {row.get('BSSID', 'N/A')} · Vendor: {row.get('Vendor', 'unknown')} · RSSI: {row.get('RSSI', 'N/A')} dBm · Channel: {row.get('Channel', 'N/A')} · Security: {row.get('Security', 'unknown')}")
                st.write("**Reasons:**", row.get("Reasons", "No high-risk evidence"))
                st.caption(f"Temporal variance: {row.get('Signal_Variance', 'n/a')} dB² · RSSI delta: {row.get('Signal_Delta', 'n/a')} dB · Evidence: {row.get('Evidence_JSON', '{}')}")


def page_threat_analysis(df: pd.DataFrame) -> None:
    st.header("🛡️ Threat Analysis")
    if df.empty:
        st.info("Run a live scan or load saved results first.")
        return
    levels = df["Threat_Level"].astype(str).str.upper()
    cols = st.columns(3)
    cols[0].metric("Critical", int(levels.eq("CRITICAL").sum()))
    cols[1].metric("High", int(levels.eq("HIGH").sum()))
    cols[2].metric("Medium", int(levels.eq("MEDIUM").sum()))
    render_table(df.sort_values("Combined_Risk", ascending=False), height=470)
    st.subheader("Investigation queue")
    render_table(df[levels.isin(["HIGH", "CRITICAL"])], ["SSID", "BSSID", "Combined_Risk", "Threat_Level", "Reasons"])


def page_ai(df: pd.DataFrame) -> None:
    st.header("🤖 AI Detection")
    for name, paths in {"Random Forest": ["rf_model.pkl", "model.pkl"], "KNN": ["knn_model.pkl"], "Isolation Forest": ["iso_model.pkl", "isolation_forest.pkl"], "Meta Model": ["meta_model.pkl"]}.items():
        present = next((name for name in paths if (ROOT / name).exists()), None)
        st.write(f"**{name}:** {'available (' + present + ')' if present else 'not found'}")
    cols = [col for col in ("SSID", "BSSID", "Random_Forest", "RF_Prediction", "KNN", "KNN_Prediction", "Isolation_Forest", "Meta_Model", "Meta_Confidence", "ML_Risk") if col in df.columns]
    if cols:
        render_table(df, cols)
    else:
        st.info("This scan has rule-based and fingerprint results; no model prediction columns were recorded.")
    if not df.empty:
        st.bar_chart(df.set_index("SSID")["Combined_Risk"])


def page_fingerprints(df: pd.DataFrame) -> None:
    st.header("🧬 Wi-Fi Fingerprinting")
    store = WiFiFingerprintStore(path=AP_BASELINE_FILE)
    records = store.all_records()
    trusted_count = sum(bool(record.get("trusted")) for record in records)
    st.metric("Persistent AP profiles", len(records), f"{trusted_count} explicitly trusted")
    st.caption("New APs are recorded as OBSERVED, not trusted. Trust must be granted explicitly after an authorized legitimacy check.")
    render_table(pd.DataFrame(records), ["ssid", "bssid", "vendor", "channels", "security_history", "rssi_mean", "rssi_variance", "observation_count", "confidence", "trusted", "first_seen", "last_seen"])

    if not df.empty:
        st.subheader("Trust an AP after verification")
        index = st.selectbox("AP profile", list(df.index), key="trusted_ap_index", format_func=lambda i: f"{df.loc[i].get('SSID', 'Unknown')} ({df.loc[i].get('BSSID', 'N/A')})")
        confirm = st.checkbox("I independently verified this AP as legitimate.", key="confirm_trusted_ap")
        selected = df.loc[index]
        selected_bssid = str(selected.get("BSSID", ""))
        if st.button("Mark AP as trusted", disabled=not confirm or not selected_bssid):
            if not store.get(selected_bssid):
                store.observe({"bssid": selected_bssid, "ssid": selected.get("SSID"), "rssi_dbm": selected.get("RSSI"), "channel": selected.get("Channel"), "security": selected.get("Security"), "timestamp": datetime.now().astimezone().isoformat()})
            if store.set_trusted(selected_bssid, True):
                st.success("AP marked TRUSTED in the new multi-scan fingerprint baseline.")
                st.rerun()
            else:
                st.error("Could not create a fingerprint; verify that this row has a valid BSSID.")

    st.subheader("Legacy fingerprint file")
    try:
        raw = json.loads(FINGERPRINT_FILE.read_text(encoding="utf-8")) if FINGERPRINT_FILE.exists() else []
    except (OSError, json.JSONDecodeError):
        raw = []
    st.caption("Existing fingerprints.json records are shown for compatibility; they are not automatically imported as trusted APs.")
    render_table(pd.DataFrame(raw if isinstance(raw, list) else []))
    st.subheader("Current fingerprint similarity")
    render_table(df, ["SSID", "BSSID", "Fingerprint_Similarity", "Combined_Risk", "Threat_Level"])


def page_evidence_review(df: pd.DataFrame) -> None:
    """Human review remains separate from automated scoring and AP trust."""
    st.header("Evidence Review")
    if df.empty:
        st.info("Run a scan or load saved scan data first.")
        return
    index = st.selectbox("Finding", list(df.index), format_func=lambda i: f"{df.loc[i].get('SSID', 'Unknown')} ({df.loc[i].get('BSSID', 'N/A')})")
    row = df.loc[index]
    narrative = explain({"ssid": row.get("SSID"), "bssid": row.get("BSSID"), "threat_level": row.get("Threat_Level"), "reasons": str(row.get("Reasons", "")).split("; ")})
    st.info(narrative["summary"])
    st.caption(narrative["recommended_action"])
    verdict = st.selectbox("Analyst verdict", ["LEGITIMATE", "ROGUE", "INVESTIGATE"])
    note = st.text_input("Investigation note (optional)", max_chars=1000)
    if st.button("Save analyst verdict"):
        item = record_feedback(str(row.get("BSSID", "")), verdict, note=note)
        try:
            import database_manager
            database_manager.save_analyst_feedback(item)
        except Exception:
            pass
        st.success("Verdict saved separately from baseline trust; no model or trust state was changed automatically.")


def page_analytics(df: pd.DataFrame) -> None:
    st.header("📊 Analytics")
    if df.empty:
        st.info("Run a scan first.")
        return
    risk = risk_series(df)
    cols = st.columns(4)
    cols[0].metric("Average risk", f"{risk.mean():.1f}%")
    cols[1].metric("Maximum risk", f"{risk.max():.1f}%")
    cols[2].metric("Minimum risk", f"{risk.min():.1f}%")
    cols[3].metric("Networks", len(df))
    levels = df["Threat_Level"].astype(str).str.upper().value_counts().reindex(["SAFE", "MEDIUM", "HIGH", "CRITICAL"], fill_value=0)
    st.bar_chart(levels)
    if "RSSI" in df:
        st.scatter_chart(pd.DataFrame({"RSSI": pd.to_numeric(df["RSSI"], errors="coerce"), "Risk": risk}).dropna(), x="RSSI", y="Risk")
    render_table(df.sort_values("Combined_Risk", ascending=False), ["SSID", "BSSID", "RSSI", "Combined_Risk", "Threat_Level"])


def page_anomaly(df: pd.DataFrame) -> None:
    st.header("🔎 Anomaly Analysis")
    levels = df.get("Threat_Level", pd.Series(index=df.index, dtype=str)).astype(str).str.upper()
    cols = st.columns(3)
    cols[0].metric("Networks", len(df))
    cols[1].metric("High / critical", int(levels.isin(["HIGH", "CRITICAL"]).sum()))
    cols[2].metric("Critical", int(levels.eq("CRITICAL").sum()))
    suspicious = df[levels.isin(["HIGH", "CRITICAL"])] if not df.empty else df
    render_table(suspicious, ["SSID", "BSSID", "Combined_Risk", "Threat_Level", "Reasons"])


def page_alert_center(df: pd.DataFrame) -> None:
    st.header("🚨 Alert Center")
    thresholds, mode = engine().get_thresholds()
    levels = df.get("Threat_Level", pd.Series(index=df.index, dtype=str)).astype(str).str.upper()
    critical = df[levels.eq("CRITICAL")] if not df.empty else pd.DataFrame()
    a, b, c = st.columns(3)
    a.metric("Critical networks now", len(critical))
    b.metric("Alerts this session", len(st.session_state["alerts"]))
    c.metric("Critical cutoff", f"{thresholds['critical']:.1f}%")
    st.caption(f"Threshold state: {mode.replace('_', ' ')}")
    st.caption("Test events are labeled TEST and do not represent detected networks.")
    if st.button("Trigger test alert", type="primary"):
        alert = {"Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "SSID": "TEST_EVIL_TWIN_WIFI", "BSSID": "AA:BB:CC:DD:EE:FF", "Risk": 95, "Level": "TEST", "Reason": "Simulated presentation alert."}
        persist_alert(alert)
        notify(alert)
        st.success("Test alert added to history.")
    st.subheader("Active critical networks")
    render_table(critical, ["SSID", "BSSID", "Combined_Risk", "Reasons"])
    st.subheader("Recent saved alerts")
    render_table(read_csv(ALERT_FILE).tail(100).iloc[::-1] if ALERT_FILE.exists() else pd.DataFrame())


def page_alert_history() -> None:
    st.header("📜 Alert History")
    alerts = read_csv(ALERT_FILE)
    if alerts.empty:
        st.info("No alert history records yet.")
        return
    st.metric("Total alerts", len(alerts))
    query = st.text_input("Search alerts", placeholder="SSID, BSSID, reason...")
    minimum = st.slider("Minimum risk", 0, 100, 0)
    if "Risk" in alerts:
        alerts["Risk"] = pd.to_numeric(alerts["Risk"], errors="coerce").fillna(0)
        alerts = alerts[alerts["Risk"] >= minimum]
    if query:
        mask = alerts.astype(str).apply(lambda col: col.str.contains(query, case=False, regex=False)).any(axis=1)
        alerts = alerts[mask]
    render_table(alerts, height=500)
    st.download_button("⬇️ Export filtered alerts", alerts.to_csv(index=False).encode(), "sentinelshield_alerts.csv", "text/csv")


def page_intelligence(df: pd.DataFrame) -> None:
    st.header("☁️ Threat Intelligence")
    try:
        if get_threat_intelligence is None:
            status = {"enabled": False, "error": "Threat intelligence module unavailable"}
        else:
            status = get_threat_intelligence().status() or {}
    except Exception as exc:
        status = {"enabled": False, "error": str(exc)}
    a, b, c = st.columns(3)
    a.metric("Cloud enabled", "YES" if status.get("enabled") else "NO")
    b.metric("Cloud threats", status.get("total_cloud_threats", 0))
    c.metric("Reputation hits", status.get("reputation_hits", 0))
    if status.get("error"):
        st.warning("Threat intelligence is unavailable; local analysis continues.")
    render_table(df, ["SSID", "BSSID", "Cloud_Risk", "BSSID_Reputation", "Cloud_Reputation_Hit", "Cloud_Threat_Type"])


def page_reports(df: pd.DataFrame) -> None:
    st.header("📄 Reports & Export")
    if df.empty:
        st.info("Run a scan before generating reports.")
        return
    a, b = st.columns(2)
    a.download_button("⬇️ Download scan CSV", df.to_csv(index=False).encode(), "sentinelshield_scan.csv", "text/csv", width="stretch")
    summary = pd.DataFrame({"Metric": ["Networks", "High / critical", "Critical", "Average risk", "Maximum risk"], "Value": [len(df), int(df["Threat_Level"].isin(["HIGH", "CRITICAL"]).sum()), int(df["Threat_Level"].eq("CRITICAL").sum()), f"{risk_series(df).mean():.1f}%", f"{risk_series(df).max():.1f}%"]})
    b.download_button("⬇️ Download summary CSV", summary.to_csv(index=False).encode(), "sentinelshield_summary.csv", "text/csv", width="stretch")
    if st.button("Generate project PDF report"):
        try:
            from report_generator import ReportGenerator
            path = ReportGenerator().generate_pdf_report(df)
            st.success(f"PDF generated: {path}")
        except Exception as exc:
            st.warning(f"PDF report generation unavailable: {exc}")


def page_adaptive() -> None:
    st.header("📈 Adaptive Detection Thresholds")
    summary = engine().summary()
    if summary["mode"] == "adaptive":
        st.success("Adaptive mode is active.")
    else:
        st.info("Warm-up mode: fallback cutoffs are used until enough scan samples are collected.")
    a, b, c = st.columns(3)
    a.metric("Mode", summary["mode"].replace("_", " ").title())
    b.metric("Samples learned", summary["samples_seen"])
    c.metric("Warm-up target", summary["warmup_samples"])
    a, b, c = st.columns(3)
    a.metric("Medium and above", f"{summary['thresholds']['medium']:.1f}%")
    b.metric("High and above", f"{summary['thresholds']['high']:.1f}%")
    c.metric("Critical", f"{summary['thresholds']['critical']:.1f}%")
    a, b = st.columns(2)
    a.metric("Baseline mean", f"{summary['baseline_mean']:.2f}%")
    b.metric("Baseline variation", f"{summary['baseline_std']:.2f}")
    st.caption("Successful manual live scans are classified using the previous baseline, then update it for the next scan. Loading saved data does not train the baseline.")
    previous = st.session_state.get("last_scan_thresholds")
    if previous:
        st.caption(f"Most recent scan used {previous['mode']} cutoffs: {previous['thresholds']}")
    if st.button("Reset learned baseline"):
        engine().reset()
        st.session_state.pop("last_scan_thresholds", None)
        st.session_state["scan"] = classify(st.session_state.get("scan", pd.DataFrame()))
        st.success("Baseline reset; warm-up fallback thresholds are active.")
        st.rerun()


def page_settings() -> None:
    st.header("⚙️ System Settings")
    config = load_runtime_config()
    scan_cfg = config["fast_scanning"]
    temporal_cfg = config["temporal_analysis"]
    context_cfg = config["optional_context"]
    st.subheader("Fast and adaptive scan settings")
    fast, balanced, deep = st.columns(3)
    scan_cfg["settle_seconds"]["fast"] = fast.slider("Fast wait (s)", 0.2, 2.0, float(scan_cfg["settle_seconds"]["fast"]), 0.05)
    scan_cfg["settle_seconds"]["balanced"] = balanced.slider("Balanced wait (s)", 0.3, 3.0, float(scan_cfg["settle_seconds"]["balanced"]), 0.05)
    scan_cfg["settle_seconds"]["deep"] = deep.slider("Deep verification wait (s)", 0.5, 4.0, float(scan_cfg["settle_seconds"]["deep"]), 0.1)
    scan_cfg["max_parallel_adapters"] = st.slider("Maximum parallel Wi-Fi adapters", 1, 8, int(scan_cfg["max_parallel_adapters"]))
    scan_cfg["adaptive_deep_scan"] = st.checkbox("Deep-verify new/changed AP evidence in Auto mode", value=bool(scan_cfg["adaptive_deep_scan"]))
    temporal_cfg["rssi_jump_threshold_db"] = st.slider("Temporal RSSI jump threshold (dB)", 3.0, 40.0, float(temporal_cfg["rssi_jump_threshold_db"]))
    temporal_cfg["rssi_std_threshold_db"] = st.slider("Temporal RSSI deviation threshold (dB)", 2.0, 30.0, float(temporal_cfg["rssi_std_threshold_db"]))

    st.subheader("Optional evidence sources")
    context_cfg["bluetooth_enabled"] = st.checkbox("Enable BLE presence context (optional)", value=bool(context_cfg["bluetooth_enabled"]), help="BLE reports nearby Bluetooth advertisements only; it never performs Wi-Fi scanning or proves an AP is malicious.")
    context_cfg["location_enabled"] = st.checkbox("Enable approximate Windows location context (optional)", value=bool(context_cfg["location_enabled"]), help="Location is contextual and never required for Wi-Fi scanning.")
    wired_cfg = config["wired_correlation"]
    mesh_cfg = config["sensor_mesh"]
    sensing_cfg = config["wifi_sensing"]
    integrity_cfg = config["evidence_integrity"]
    wired_cfg["enabled"] = st.checkbox("Enable read-only wired inventory correlation", value=bool(wired_cfg["enabled"]), help="Reads an administrator-exported JSON file only; no switch or endpoint access is attempted.")
    wired_cfg["inventory_file"] = st.text_input("Wired inventory JSON", value=wired_cfg["inventory_file"])
    mesh_cfg["enabled"] = st.checkbox("Enable authorized sensor-mesh inbox", value=bool(mesh_cfg["enabled"]), help="Reads local sensor exports; SentinelShield does not open a network listener.")
    mesh_cfg["inbox_dir"] = st.text_input("Sensor inbox folder", value=mesh_cfg["inbox_dir"])
    sensing_cfg["enabled"] = st.checkbox("Enable consent-based Wi-Fi sensing research", value=bool(sensing_cfg["enabled"]), help="Contextual research only—no identity tracking or raw RF capture.")
    sensing_cfg["consent_granted"] = st.checkbox("I have documented consent for sensing research", value=bool(sensing_cfg["consent_granted"]), disabled=not sensing_cfg["enabled"])
    integrity_cfg["enabled"] = st.checkbox("Create evidence integrity receipts", value=bool(integrity_cfg["enabled"]), help="Uses SHA-256 or HMAC-SHA-256 if the configured environment key is set.")

    if st.button("Save scanner and evidence settings", type="primary"):
        current_controller = st.session_state.get("scan_controller")
        if current_controller and current_controller.status().get("status") in {"queued", "scanning", "deep-verification", "analyzing", "stopping"}:
            st.warning("Stop the active scan before changing its configuration.")
        elif save_runtime_config(config):
            st.session_state.pop("scan_controller", None)
            st.success("Settings saved atomically. They will apply to the next scan.")
        else:
            st.error("Could not save runtime settings; prior configuration was retained.")

    st.subheader("Alert and refresh controls")
    st.checkbox("Enable critical alert logging", key="critical_alerts_enabled")
    st.checkbox("Enable Windows sound alert", key="sound_enabled")
    st.checkbox("Enable desktop notifications", key="desktop_enabled")
    st.checkbox("Auto-refresh saved dashboard data", key="auto_refresh_enabled", help="This refreshes the dashboard only; it never starts a Wi-Fi scan.")
    st.caption("Critical notifications are deduplicated by network, risk and scan timestamp. Auto-refresh re-reads saved results only.")
    st.subheader("Project health")
    for name in ("fast_wifi_scanner.py", "scan_controller.py", "wifi_fingerprint.py", "temporal_analyzer.py", "evidence_fusion.py", "bluetooth_context.py", "location_context.py", "performance_benchmark.py", "scanner.py", "adaptive_thresholds.py", "database_manager.py", "threat_intelligence.py", "report_generator.py"):
        st.write(f"{'✅' if (ROOT / name).exists() else '—'} {name}")
    st.caption(f"Project directory: {ROOT}")
    st.caption(f"Scan file: {SCAN_FILE.name} · Alert file: {ALERT_FILE.name}")
    try:
        import database_manager
        db_metrics = database_manager.get_monitoring_metrics()
        st.caption(f"SQLite: {db_metrics.get('networks_found', 0)} stored AP observations · latest scan {db_metrics.get('last_scan') or 'not recorded'}")
    except Exception as exc:
        st.warning(f"SQLite persistence unavailable; CSV/session scanning remains active ({exc}).")
    if st.button("Clear current scan data"):
        SCAN_FILE.unlink(missing_ok=True)
        st.session_state["scan"] = pd.DataFrame()
        st.success("Saved scan removed.")
        st.rerun()


def main() -> None:
    defaults = {"alerts": [], "alert_keys": set(), "critical_alerts_enabled": True, "sound_enabled": True, "desktop_enabled": True, "auto_refresh_enabled": False}
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
    if "scan" not in st.session_state or st.session_state.get("auto_refresh_enabled"):
        st.session_state["scan"] = normalise(read_csv(SCAN_FILE))
    st.session_state["scan"] = classify(st.session_state["scan"])
    if st.session_state["auto_refresh_enabled"] and st_autorefresh:
        st_autorefresh(interval=5000, key="sentinelshield_refresh")
    process_alerts(st.session_state["scan"])
    df = st.session_state["scan"]

    st.sidebar.markdown("### 🛡️ SentinelShield")
    st.sidebar.caption("Wi-Fi security command center")
    pages = ["Command Center", "Live Wi-Fi Scan", "Threat Analysis", "Alert Center", "AI Detection", "Fingerprinting", "Evidence Review", "Analytics", "Anomaly Analysis", "Alert History", "Threat Intelligence", "Reports & Export", "Adaptive Thresholds", "System Settings"]
    page = st.sidebar.radio("Navigation", pages)
    st.sidebar.metric("Networks", len(df))
    st.sidebar.metric("High / critical", int(df.get("Threat_Level", pd.Series(index=df.index, dtype=str)).isin(["HIGH", "CRITICAL"]).sum()))
    controller = st.session_state.get("scan_controller")
    scanner_state = controller.status() if controller else {"status": "idle", "adapter_mode": "not started"}
    st.sidebar.caption(f"Scanner {scanner_state.get('status', 'idle')} · {scanner_state.get('adapter_mode', 'single-adapter')} · UI refresh never scans")

    critical = df[df.get("Threat_Level", pd.Series(index=df.index, dtype=str)).eq("CRITICAL")] if not df.empty else pd.DataFrame()
    if not critical.empty:
        st.markdown('<div class="alert-banner">🚨 CRITICAL WI-FI THREAT DETECTED 🚨</div>', unsafe_allow_html=True)
        st.error("A network exceeds the adaptive critical threshold. Review Alert Center.")

    if controller and controller.latest():
        latest = controller.latest()
        st.caption(f"Last controller scan: {latest.get('scan_id')} · {latest.get('aps_discovered', 0)} APs · {latest.get('scan_duration_ms', 0):.0f} ms scan / {latest.get('detection_latency_ms', 0):.0f} ms to findings")

    routes = {
        "Command Center": lambda: page_home(df),
        "Live Wi-Fi Scan": page_live_scan,
        "Threat Analysis": lambda: page_threat_analysis(df),
        "Alert Center": lambda: page_alert_center(df),
        "AI Detection": lambda: page_ai(df),
        "Fingerprinting": lambda: page_fingerprints(df),
        "Evidence Review": lambda: page_evidence_review(df),
        "Analytics": lambda: page_analytics(df),
        "Anomaly Analysis": lambda: page_anomaly(df),
        "Alert History": page_alert_history,
        "Threat Intelligence": lambda: page_intelligence(df),
        "Reports & Export": lambda: page_reports(df),
        "Adaptive Thresholds": page_adaptive,
        "System Settings": page_settings,
    }
    routes[page]()


if __name__ == "__main__":
    main()
