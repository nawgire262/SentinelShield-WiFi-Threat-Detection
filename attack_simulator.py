"""attack_simulator.py – Real-time Evil Twin & Rogue AP attack simulation engine for SentinelShield.

Provides interactive simulation of wireless attack vectors to demonstrate
real-time defense, ML feature extraction, and multi-channel alerting without
requiring illegal hardware rogue access points in academic/evaluation settings.
"""
from __future__ import annotations

import copy
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

LOGGER = logging.getLogger(__name__)

# Predefined attack scenarios
ATTACK_SCENARIOS = {
    "evil_twin_signal_boost": {
        "name": "1. Classic Evil Twin Attack (Signal Amplification)",
        "description": (
            "Attacker deploys a rogue AP with identical SSID and high transmission power (-28 dBm) "
            "to overpower the legitimate access point and trick client devices into auto-roaming."
        ),
        "target_type": "clone_existing",
        "spoofed_bssid": "DE:AD:BE:EF:00:01",
        "rssi": -28.0,
        "channel_offset": 0,
        "security_override": None,
        "deauth_burst": False,
        "cloud_threat": False,
        "expected_findings": [
            "BSSID density anomaly (multiple BSSIDs for target SSID)",
            "Path loss model violation: implausible proximity to receiver",
            "Fingerprint mismatch against established baseline",
            "High ML Ensemble fake network probability",
        ],
    },
    "security_downgrade": {
        "name": "2. Security Downgrade / Captive Portal (Karma Attack)",
        "description": (
            "Attacker broadcasts an unencrypted (OPEN) clone of an encrypted WPA2/WPA3 corporate/home network, "
            "attempting to establish a rogue captive portal to harvest credentials."
        ),
        "target_type": "clone_existing",
        "spoofed_bssid": "DE:AD:BE:EF:00:02",
        "rssi": -35.0,
        "channel_offset": 1,
        "security_override": "OPEN",
        "deauth_burst": False,
        "cloud_threat": False,
        "expected_findings": [
            "Severe security downgrade mismatch: WPA2/WPA3 -> OPEN (95 points)",
            "Unencrypted open portal vulnerability flag",
            "Fingerprint cipher conflict",
            "Immediate CRITICAL threat score elevation",
        ],
    },
    "deauth_jamming": {
        "name": "3. Active Layer-2 Deauthentication & Jamming Flood",
        "description": (
            "Attacker broadcasts spoofed 802.11 disassociation/deauth frames to disconnect users from legitimate APs "
            "while introducing rapid RSSI temporal fluctuations."
        ),
        "target_type": "clone_existing",
        "spoofed_bssid": "DE:AD:BE:EF:00:03",
        "rssi": -42.0,
        "channel_offset": 0,
        "security_override": None,
        "deauth_burst": True,
        "cloud_threat": False,
        "expected_findings": [
            "Layer-2 active deauth packet storm (> 180 frames detected)",
            "Temporal RSSI instability (variance > 45 dB)",
            "Novelty engine active attack elevation",
        ],
    },
    "cloud_blacklisted_rogue": {
        "name": "4. Known Blacklisted Malicious Rogue AP (Threat Intel Match)",
        "description": (
            "Attacker deploys a rogue AP whose BSSID and gateway IP match known command-and-control "
            "infrastructure in global threat feeds (VirusTotal / AbuseIPDB / OpenPhish)."
        ),
        "target_type": "custom",
        "custom_ssid": "Public_Free_WiFi_Express",
        "spoofed_bssid": "DE:AD:BE:EF:00:04",
        "rssi": -48.0,
        "channel": 11,
        "security": "OPEN",
        "deauth_burst": False,
        "cloud_threat": True,
        "expected_findings": [
            "Cloud reputation hit: 95/100 risk score on global threat databases",
            "Associated with credential harvesting campaign (OpenPhish / AbuseIPDB)",
            "Automatic CRITICAL threat broadcast and Telegram dispatch",
        ],
    },
    "multi_vector_chain": {
        "name": "5. Multi-Vector Advanced Attack Chain (Evil Twin + Deauth + Downgrade)",
        "description": (
            "Full attack chain combining deauth jamming to force disconnections, an amplified Evil Twin clone, "
            "an open security downgrade, and blacklisted rogue infrastructure."
        ),
        "target_type": "clone_existing",
        "spoofed_bssid": "DE:AD:BE:EF:00:05",
        "rssi": -25.0,
        "channel_offset": 2,
        "security_override": "OPEN",
        "deauth_burst": True,
        "cloud_threat": True,
        "expected_findings": [
            "All detection engines simultaneously triggered",
            "Rule fusion score: 98% (CRITICAL)",
            "ML Ensemble anomaly confidence: 99.4%",
            "Novelty multi-signal corroboration verified",
            "Immediate multi-channel incident response dispatch",
        ],
    },
}


class AttackSimulator:
    """Generates synthetic rogue AP attack observations and injects them into SentinelShield."""

    def __init__(self, root_dir: Optional[Path] = None) -> None:
        self.root = root_dir or Path(__file__).resolve().parent

    def generate_attack_scan(
        self,
        scenario_key: str,
        current_df: pd.DataFrame,
        target_ssid: Optional[str] = None,
    ) -> pd.DataFrame:
        """Create a modified scan dataframe containing the synthesized attack alongside legitimate networks."""
        scenario = ATTACK_SCENARIOS.get(scenario_key)
        if not scenario:
            raise ValueError(f"Unknown scenario key: {scenario_key}")

        df = current_df.copy() if not current_df.empty else self._generate_fallback_baseline()

        # Determine target to clone
        if scenario.get("target_type") == "custom":
            ssid = scenario.get("custom_ssid", "Rogue_Public_WiFi")
            channel = scenario.get("channel", 6)
            security = scenario.get("security", "OPEN")
        else:
            if target_ssid and any(df["SSID"].astype(str) == target_ssid):
                target_row = df[df["SSID"].astype(str) == target_ssid].iloc[0]
            else:
                target_row = df.iloc[0]
            ssid = str(target_row.get("SSID", "HomeWiFi"))
            channel = int(target_row.get("Channel", 6)) + scenario.get("channel_offset", 0)
            if channel > 14:
                channel = 1
            original_security = str(target_row.get("Security", "WPA2-PSK"))
            security = scenario.get("security_override") or original_security

        spoofed_bssid = scenario["spoofed_bssid"]
        rssi = scenario["rssi"]

        # Synthetic rogue AP row with comprehensive telemetry
        now_iso = datetime.now(timezone.utc).isoformat()
        is_deauth = scenario["deauth_burst"]
        is_cloud = scenario["cloud_threat"]

        # Compute calculated risk
        base_risk = 75.0 if scenario_key != "multi_vector_chain" else 98.0
        if scenario_key == "evil_twin_signal_boost":
            base_risk = 82.0
            reasons = (
                f"Evil Twin signature: identical SSID '{ssid}' with unexpected BSSID; "
                f"RSSI ({rssi:.0f} dBm) indicates anomalous high-power transmission close to monitor; "
                "Fingerprint mismatch against established legitimate baseline."
            )
        elif scenario_key == "security_downgrade":
            base_risk = 92.0
            reasons = (
                f"Security downgrade attack on SSID '{ssid}': authentic network uses secure encryption, "
                "but this AP broadcasts OPEN security; Potential rogue captive portal harvesting credentials."
            )
        elif scenario_key == "deauth_jamming":
            base_risk = 88.0
            reasons = (
                "Layer-2 deauthentication packet flood detected targeting connected clients; "
                "Temporal RSSI fluctuation (variance > 45 dB) indicates aggressive rogue jamming."
            )
        elif scenario_key == "cloud_blacklisted_rogue":
            base_risk = 95.0
            reasons = (
                f"Cloud Threat Intelligence match: BSSID {spoofed_bssid} is blacklisted by 14 threat intelligence feeds; "
                "Associated with known wireless credential theft infrastructure."
            )
        else:
            reasons = (
                "FULL ATTACK CHAIN DETECTED: Evil Twin clone + Open security downgrade + "
                "Active Layer-2 deauth storm + Global threat intelligence blacklisted MAC."
            )

        rogue_row: Dict[str, Any] = {
            "SSID": ssid,
            "BSSID": spoofed_bssid,
            "RSSI": rssi,
            "Channel": channel,
            "Frequency": 2400.0 + (channel * 5),
            "Security": security,
            "Vendor": "ALFA Network / Rogue Virtualized",
            "Fingerprint_Similarity": 28.5,
            "Fingerprint_Hash": "c0ffeebad0000000000000000000000000000000000000000000000000000000",
            "Fingerprint_Baseline_Exists": True,
            "Fingerprint_Changed": True,
            "Fingerprint_Change_Reasons": f"Channel changed to {channel}; Security altered to {security}",
            "Temporal_Score": 85.0 if is_deauth else 25.0,
            "Density_Score": 75.0,
            "Confidence": "HIGH",
            "RF_Prediction": 0.96,
            "KNN_Prediction": 0.94,
            "Isolation_Forest": -1,
            "Meta_Model": "Fake",
            "Meta_Confidence": 98.4,
            "ML_Risk": 94.0,
            "Combined_Risk": base_risk,
            "Threat_Score": base_risk,
            "Threat_Level": "CRITICAL",
            "AP_Count": 2,
            "Signal_Fluctuation": 34.0 if is_deauth else 12.0,
            "Signal_History": f"{rssi},{rssi+8},{rssi-12},{rssi+4}",
            "Signal_Variance": 52.4 if is_deauth else 8.5,
            "Signal_StdDev": 7.2 if is_deauth else 2.9,
            "Signal_Delta": 18.0 if is_deauth else 3.0,
            "Observation_Count": 8,
            "Adapter_ID": "simulated-adapter-01",
            "Adapter_Name": "Realtek 8821CE (Attack Simulation)",
            "Scan_ID": f"SIM-{datetime.now().strftime('%H%M%S')}",
            "Scan_Duration_ms": 1250.0,
            "Detection_Latency_ms": 320.0,
            "Scan_Time": now_iso,
            "RAIM_Flagged": True if scenario_key != "deauth_jamming" else False,
            "RAIM_Distance_m": 1.8,
            "RAIM_Score": 85.0 if scenario_key != "deauth_jamming" else 0.0,
            "Layer2_Deauth_Detected": is_deauth,
            "Layer2_Score": 90.0 if is_deauth else 0.0,
            "Layer2_Reasons": "802.11 Deauth burst: 210 management frames/sec observed" if is_deauth else "",
            "Cloud_Risk": 95.0 if is_cloud else 0.0,
            "Cloud_Reputation_Hit": is_cloud,
            "Cloud_Threat_Type": "Malicious Hotspot Campaign" if is_cloud else "",
            "BSSID_Reputation": "Blacklisted" if is_cloud else "Clean",
            "Cloud_Risk_Score": 95.0 if is_cloud else 0.0,
            "Adapter_Mode": "simulation-mode",
            "Adapter_Count": 1,
            "Reasons": reasons,
            "Model_Explanation": "Classifier confidence driven by Signal Attenuation Delta, Security Mismatch, and Beacon Anomaly.",
        }

        # Prepend rogue AP so it appears at top of scan results
        rogue_df = pd.DataFrame([rogue_row])
        combined = pd.concat([rogue_df, df], ignore_index=True)
        return combined

    def _generate_fallback_baseline(self) -> pd.DataFrame:
        """Create a default safe local network baseline if no scan exists yet."""
        return pd.DataFrame([
            {
                "SSID": "Campus_Secure_WiFi",
                "BSSID": "AC:86:74:11:22:33",
                "RSSI": -64.0,
                "Channel": 6,
                "Frequency": 2437.0,
                "Security": "WPA2-PSK",
                "Vendor": "Cisco Systems",
                "Fingerprint_Similarity": 98.0,
                "Combined_Risk": 4.5,
                "Threat_Level": "SAFE",
                "AP_Count": 1,
                "Scan_Time": datetime.now(timezone.utc).isoformat(),
                "Reasons": "Legitimate established enterprise AP",
            },
            {
                "SSID": "Student_Lab_5G",
                "BSSID": "AC:86:74:44:55:66",
                "RSSI": -58.0,
                "Channel": 36,
                "Frequency": 5180.0,
                "Security": "WPA2-PSK",
                "Vendor": "Aruba Networks",
                "Fingerprint_Similarity": 99.2,
                "Combined_Risk": 3.8,
                "Threat_Level": "SAFE",
                "AP_Count": 1,
                "Scan_Time": datetime.now(timezone.utc).isoformat(),
                "Reasons": "Standard indoor access point",
            },
        ])

