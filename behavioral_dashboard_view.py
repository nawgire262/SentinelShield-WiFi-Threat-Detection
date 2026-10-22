"""behavioral_dashboard_view.py – Real-time visualization dashboard for behavioral log intelligence.

Novelty: Displays live behavioral risk levels, typing biometric dynamics,
over-efficiency bot anomalies, and adaptive access control policy enforcement.
"""
from __future__ import annotations

import pandas as pd
import streamlit as st

from adaptive_access_control import AdaptiveAccessControlEngine
from behavioral_biometrics import BehavioralBiometricsEngine, BiometricProfile, KeystrokeEvent
from over_efficiency_detector import OverEfficiencyDetector
from behavioral_ml_engine import BehavioralHybridMLEngine


@st.cache_resource(show_spinner=False)
def _get_shared_behavioral_engines():
    return (
        BehavioralBiometricsEngine(),
        OverEfficiencyDetector(),
        BehavioralHybridMLEngine(),
        AdaptiveAccessControlEngine(),
    )


def render_behavioral_dashboard() -> None:
    """Render the Behavioral Intelligence and Cloud Security Dashboard."""
    st.header("🧠 Behavioral Intelligence & Access Control Lab")
    st.caption(
        "Continuous behavioral telemetry analysis framework. Employs behavioral biometrics (keystroke dynamics), "
        "over-efficiency detection (bot / automation identification), and hybrid ML (Random Forest + Isolation Forest) "
        "to trigger dynamic adaptive security actions."
    )

    # Initialize engines with cached instances to avoid retraining on every interaction
    if "biometrics_engine" not in st.session_state:
        b_eng, e_det, m_eng, a_eng = _get_shared_behavioral_engines()
        st.session_state["biometrics_engine"] = b_eng
        st.session_state["efficiency_detector"] = e_det
        st.session_state["hybrid_ml_engine"] = m_eng
        st.session_state["access_control_engine"] = a_eng

    bio_engine: BehavioralBiometricsEngine = st.session_state["biometrics_engine"]
    eff_detector: OverEfficiencyDetector = st.session_state["efficiency_detector"]
    ml_engine: BehavioralHybridMLEngine = st.session_state["hybrid_ml_engine"]
    ac_engine: AdaptiveAccessControlEngine = st.session_state["access_control_engine"]

    st.subheader("1. Interactive Behavioral Profile & Telemetry Generator")
    st.caption("Select a behavioral scenario or adjust parameters to test the real-time detection pipeline:")

    scenarios = {
        "legit_human": {
            "name": "1. Authentic Enrolled User (Normal Human Cadence)",
            "user_id": "admin_user",
            "wpm": 62.0,
            "mean_flight": 118.0,
            "std_flight": 34.0,
            "mean_dwell": 82.0,
            "chars": 45,
            "duration_ms": 7250.0,
            "errors": 3,
            "desc": "Natural human typing: 62 WPM, realistic timing variance, standard typos, nominal error-correction.",
        },
        "automated_bot": {
            "name": "2. Scripted Credential-Stuffing Bot (Over-Efficiency Anomaly)",
            "user_id": "admin_user",
            "wpm": 940.0,
            "mean_flight": 4.5,
            "std_flight": 0.8,
            "mean_dwell": 6.0,
            "chars": 50,
            "duration_ms": 280.0,
            "errors": 0,
            "desc": "Automated script / headless bot: microsecond execution, clockwork intervals, zero mistakes.",
        },
        "impostor_human": {
            "name": "3. Stolen Credentials / Impostor (Biometric Rhythm Mismatch)",
            "user_id": "admin_user",
            "wpm": 26.0,
            "mean_flight": 240.0,
            "std_flight": 85.0,
            "mean_dwell": 150.0,
            "chars": 35,
            "duration_ms": 14500.0,
            "errors": 7,
            "desc": "Valid password entered by an unauthorized human: typing rhythm severely diverges from enrolled profile.",
        },
        "fast_human": {
            "name": "4. Power User / Fast Typist (Legitimate Edge Case)",
            "user_id": "admin_user",
            "wpm": 98.0,
            "mean_flight": 72.0,
            "std_flight": 22.0,
            "mean_dwell": 68.0,
            "chars": 60,
            "duration_ms": 6100.0,
            "errors": 2,
            "desc": "Fast human typist: rapid but retains human variance, slight errors, and physiological dwell times.",
        },
    }

    selected_key = st.selectbox(
        "Select Behavioral Scenario",
        list(scenarios.keys()),
        format_func=lambda k: scenarios[k]["name"],
    )
    preset = scenarios[selected_key]
    st.info(f"**Scenario Goal:** {preset['desc']}")

    # Adjustable controls for presentation flexibility
    with st.expander("🛠️ Fine-Tune Telemetry Parameters (Optional)", expanded=False):
        c1, c2, c3, c4 = st.columns(4)
        test_wpm = c1.slider("Typing Speed (WPM)", 10.0, 1200.0, float(preset["wpm"]))
        test_flight = c2.slider("Mean Flight Time (ms)", 2.0, 350.0, float(preset["mean_flight"]))
        test_dwell = c3.slider("Mean Dwell Time (ms)", 2.0, 200.0, float(preset["mean_dwell"]))
        test_errors = c4.number_input("Typo / Backspace Count", 0, 20, int(preset["errors"]))

    # Generate synthetic keystroke events matching the parameters
    char_count = int(preset["chars"])
    duration_ms = float(preset["duration_ms"])
    if test_wpm != preset["wpm"]:
        duration_ms = max(50.0, (char_count / 5.0) / (test_wpm / 60000.0))

    # Fabricate event sequence
    events: list[KeystrokeEvent] = []
    current_time = 0.0
    intervals: list[float] = []
    for i in range(char_count):
        dwell = max(2.0, test_dwell)
        flight = max(1.0, test_flight)
        events.append(KeystrokeEvent(key=f"k{i}", press_time_ms=current_time, release_time_ms=current_time + dwell))
        intervals.append(flight)
        current_time += (dwell + flight)

    if st.button("🚀 Evaluate Behavioral Intelligence & Enforce Policy", type="primary", use_container_width=True):
        st.session_state["eval_triggered"] = True

    # ── Evaluation Pipeline ─────────────────────────────────────────────────
    # 1. Behavioral Biometrics
    bio_eval = bio_engine.evaluate_session(preset["user_id"], events, duration_ms, test_errors)

    # 2. Over-Efficiency Detection
    eff_eval = eff_detector.analyze_interaction(char_count, duration_ms, intervals, test_errors, field_count=2)

    # 3. Hybrid ML Engine (Isolation Forest + Random Forest)
    ml_features = {
        "typing_speed_wpm": bio_eval.typing_speed_wpm,
        "mean_flight_time_ms": bio_eval.mean_flight_time_ms,
        "std_flight_time_ms": bio_eval.std_flight_time_ms,
        "mean_dwell_time_ms": bio_eval.mean_dwell_time_ms,
        "char_per_sec": eff_eval.char_per_sec,
        "error_rate": bio_eval.error_rate,
        "uniformity_index": eff_eval.uniformity_index,
    }
    ml_eval = ml_engine.predict(ml_features)

    # 4. Adaptive Access Control Policy Decision
    decision = ac_engine.evaluate_policy(
        user_id=preset["user_id"],
        session_id=f"SESS-{selected_key[:4].upper()}",
        biometric_risk=bio_eval.risk_score,
        over_efficiency_score=eff_eval.efficiency_score,
        hybrid_ml_risk=ml_eval.hybrid_threat_score,
        extra_reasons=bio_eval.reasons + eff_eval.reasons,
    )

    st.divider()
    st.subheader("2. Real-Time Detection & Policy Enforcement Dashboard")

    # High-level metrics row
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Biometric Match", f"{bio_eval.similarity_score:.0f}%", f"{bio_eval.typing_speed_wpm:.0f} WPM")
    m2.metric("Efficiency Anomaly", f"{eff_eval.efficiency_score:.0f}/100", eff_eval.classification)
    m3.metric("Hybrid ML Verdict", ml_eval.verdict, f"Fake Prob: {ml_eval.rf_confidence:.0f}%")
    m4.metric("Enforced Action", decision.action, f"Risk: {decision.risk_score:.0f}%")

    # Adaptive Policy Action Banner
    if decision.action == "ALLOW":
        st.success(f"✅ **POLICY ACTION: {decision.action}** — {decision.action_details}")
    elif decision.action == "STEP_UP_MFA":
        st.warning(f"⚠️ **POLICY ACTION: {decision.action}** — {decision.action_details}")
    elif decision.action == "CHALLENGE_REAUTH":
        st.error(f"🛑 **POLICY ACTION: {decision.action}** — {decision.action_details}")
    else:
        st.error(f"🚨 **POLICY ACTION: {decision.action} (CRITICAL)** — {decision.action_details}")

    # Pipeline breakdown cards
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("#### 🔬 Behavioral Biometrics (Keystroke Dynamics)")
        st.write(f"- **Observed Typing Speed:** `{bio_eval.typing_speed_wpm:.1f} WPM`")
        st.write(f"- **Mean Flight Time:** `{bio_eval.mean_flight_time_ms:.1f} ms` (Baseline: 115 ms)")
        st.write(f"- **Key Dwell Time:** `{bio_eval.mean_dwell_time_ms:.1f} ms` (Baseline: 80 ms)")
        st.write(f"- **Error / Backspace Rate:** `{bio_eval.error_rate*100:.1f}%`")
        st.write(f"- **Biometric Anomaly Flag:** `{'YES ⚠️' if bio_eval.is_anomaly else 'NO (Normal)'}`")
        for r in bio_eval.reasons:
            st.caption(f"• {r}")

    with col_b:
        st.markdown("#### 🤖 Over-Efficiency & Bot Automation Analysis")
        st.write(f"- **Throughput Velocity:** `{eff_eval.char_per_sec:.1f} char/sec`")
        st.write(f"- **Form Completion Time:** `{eff_eval.duration_ms:.0f} ms`")
        st.write(f"- **Temporal Clockwork Index:** `{eff_eval.uniformity_index:.3f}` (1.0 = synthetic)")
        st.write(f"- **Script / Bot Detection:** `{'AUTOMATED SCRIPT 🚨' if eff_eval.is_automated else 'HUMAN OPERATED'}`")
        for r in eff_eval.reasons:
            st.caption(f"• {r}")

    st.markdown("#### 🌲 Hybrid Machine Learning Strategy (Isolation Forest + Random Forest)")
    c_ml1, c_ml2, c_ml3 = st.columns(3)
    c_ml1.metric("Random Forest Bot Confidence", f"{ml_eval.rf_confidence:.1f}%")
    c_ml2.metric("Isolation Forest Anomaly", "OUTLIER (-1)" if ml_eval.iso_anomaly else "INLIER (+1)")
    c_ml3.metric("Composite Hybrid Score", f"{ml_eval.hybrid_threat_score:.1f}%")

    st.caption("**Feature Importance Distribution in Decision:**")
    st.bar_chart(pd.DataFrame(list(ml_eval.feature_contributions.items()), columns=["Feature", "Contribution %"]).set_index("Feature"))

    st.divider()
    st.subheader("3. Adaptive Security Policy Audit Trail")
    trail = ac_engine.get_audit_trail(15)
    if trail:
        st.dataframe(pd.DataFrame(trail)[["timestamp", "user_id", "risk_score", "risk_level", "action", "action_details"]], use_container_width=True)
    else:
        st.info("No security enforcement events recorded yet.")

