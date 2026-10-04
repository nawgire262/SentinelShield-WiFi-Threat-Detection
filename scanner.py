"""
SentinelShield Wi-Fi scanner.

Collects repeated Wi-Fi measurements and produces
explainable risk scores.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from fingerprinting.fingerprint_matcher import compare_fingerprint

try:
    import pywifi
except ImportError:
    pywifi = None


# ================================================================
# RISK ENGINE
# ================================================================

def calculate_risk(
    bssids: set[str],
    security_levels: list[str],
    signals: list[float],
) -> tuple[int, list[str]]:
    """
    Explainable rule-based risk calculation.
    """

    risk = 0
    reasons: list[str] = []

    # Multiple APs broadcasting same SSID
    if len(bssids) > 1:
        risk += 50
        reasons.append("Multiple BSSIDs detected")

    # Open Wi-Fi
    if "Open" in security_levels:
        risk += 30
        reasons.append("Open network")

    # Large RSSI variation
    if len(signals) >= 3:

        fluctuation = max(signals) - min(signals)

        if fluctuation > 20:
            risk += 20
            reasons.append("High signal fluctuation")

    return min(100, risk), reasons


# ================================================================
# GET WIFI INTERFACE
# ================================================================

def _interface_name(interface: Any) -> str:
    for attr in ("name", "description"):
        value = getattr(interface, attr, None)
        if callable(value):
            try:
                value = value()
            except Exception:
                value = None
        if value:
            return str(value)
    return ""


def select_wifi_interface(interfaces: list[Any] | tuple[Any, ...] | None) -> Any | None:
    """Choose the actual wireless adapter instead of a virtual/direct-only adapter."""
    if not interfaces:
        return None

    ranked: list[tuple[int, Any]] = []

    for interface in interfaces:
        if interface is None:
            continue

        name = _interface_name(interface).lower()

        if not name:
            continue

        virtual_markers = (
            "virtual", "wi-fi direct", "wifi direct", "loopback",
            "bluetooth", "ethernet", "lan adapter", "vpn", "mobile broadband"
        )
        if any(marker in name for marker in virtual_markers):
            continue

        score = 0
        if "wifi" in name or "wireless" in name:
            score += 5
        if any(vendor in name for vendor in ("intel", "realtek", "atheros", "mediatek", "broadcom", "marvell")):
            score += 2

        try:
            if interface.network_profiles():
                score += 3
        except Exception:
            pass

        ranked.append((score, interface))

    if not ranked:
        return None

    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1]


def safe_scan_results(interface: Any) -> list[Any]:
    """Return an empty result set when the adapter is unusable instead of crashing."""
    if interface is None:
        return []

    try:
        interface.scan()
        time.sleep(1.5)
        return list(interface.scan_results())
    except (AttributeError, OSError, ValueError, TypeError):
        return []
    except Exception:
        return []


def _wireless_interface() -> Any | None:

    if pywifi is None:
        return None

    try:

        wifi = pywifi.PyWiFi()
        interfaces = wifi.interfaces()
        return select_wifi_interface(interfaces)

    except Exception:
        return None


# ================================================================
# SINGLE SCAN ROUND
# ================================================================

def _scan_round(interface: Any) -> list[Any]:

    interface.scan()

    time.sleep(3)

    return list(interface.scan_results())


# ================================================================
# MAIN SCANNER
# ================================================================

def scan_wifi(rounds: int = 3) -> list[dict[str, Any]]:
    """
    Scan nearby Wi-Fi networks multiple times.

    Returns dashboard-ready network information.
    """

    interface = _wireless_interface()

    if interface is None:
        return []

    # ------------------------------------------------------------
    # Historical measurements
    # ------------------------------------------------------------

    signal_history: dict[str, list[float]] = defaultdict(list)

    # Store actual network objects
    network_history: dict[str, list[Any]] = defaultdict(list)

    # ------------------------------------------------------------
    # Repeated scans
    # ------------------------------------------------------------

    for _ in range(max(1, rounds)):

        try:
            results = _scan_round(interface)
        except Exception:
            continue

        for network in results:

            ssid = str(
                getattr(network, "ssid", "") or ""
            ).strip()

            if not ssid:
                continue

            try:
                signal = float(
                    getattr(network, "signal", 0)
                )
            except (ValueError, TypeError):
                signal = 0.0

            signal_history[ssid].append(signal)

            network_history[ssid].append(network)

    # ------------------------------------------------------------
    # Build findings
    # ------------------------------------------------------------

    findings: list[dict[str, Any]] = []

    for ssid, signals in signal_history.items():

        networks = network_history.get(ssid, [])

        if not networks:
            continue

        # --------------------------------------------------------
        # Unique BSSIDs
        # --------------------------------------------------------

        unique_networks: dict[str, Any] = {}

        for network in networks:

            bssid = str(
                getattr(network, "bssid", "") or ""
            ).strip()

            if bssid:
                unique_networks[bssid] = network

        bssids = set(unique_networks.keys())

        # --------------------------------------------------------
        # Security
        # --------------------------------------------------------

        security_levels = []

        for network in unique_networks.values():

            akm = getattr(network, "akm", None)

            if not akm:
                security_levels.append("Open")
            else:
                security_levels.append("WPA2")

        security = (
            "Open"
            if "Open" in security_levels
            else "WPA2"
        )

        # --------------------------------------------------------
        # Risk
        # --------------------------------------------------------

        risk, reasons = calculate_risk(
            bssids,
            security_levels,
            signals,
        )

        # --------------------------------------------------------
        # Latest network
        # --------------------------------------------------------

        latest = list(unique_networks.values())[-1]

        bssid = str(
            getattr(latest, "bssid", "N/A")
        )

        channel = getattr(
            latest,
            "freq",
            "N/A",
        )

        try:
            rssi = float(signals[-1])
        except (ValueError, TypeError):
            rssi = 0.0

        current_ap = {
            "SSID": ssid,
            "BSSID": bssid,
            "RSSI": getattr(latest, "signal", rssi),
            "Channel": channel,
            "Security": security,
        }
        fingerprint = compare_fingerprint(current_ap)
        fingerprint_similarity = fingerprint["similarity"]

        if fingerprint_similarity is not None:
            if fingerprint_similarity < 70:
                risk += 20
                reasons.append(
                    f"Fingerprint mismatch ({fingerprint_similarity}% similarity)"
                )
            elif fingerprint_similarity < 90:
                risk += 10
                reasons.append(
                    f"Fingerprint partially matched ({fingerprint_similarity}% similarity)"
                )

        risk = min(100, risk)

        # --------------------------------------------------------
        # Threat level
        # --------------------------------------------------------

        if risk >= 70:
            threat_level = "CRITICAL"

        elif risk >= 50:
            threat_level = "MEDIUM"

        elif risk >= 30:
            threat_level = "LOW"

        else:
            threat_level = "SAFE"

        # --------------------------------------------------------
        # Result
        # --------------------------------------------------------

        findings.append(
            {
                "ssid": ssid,
                "bssid": bssid,
                "rssi": rssi,
                "channel": channel,
                "security": security,
                "fingerprint_similarity": fingerprint_similarity,

                "risk": risk,

                "threat_level": threat_level,

                "reasons": reasons,

                "signals": signals,

                "ap_count": len(bssids),

                "signal_fluctuation": (
                    max(signals) - min(signals)
                    if signals
                    else 0
                ),
            }
        )

    # ------------------------------------------------------------
    # Highest risk first
    # ------------------------------------------------------------

    findings.sort(
        key=lambda item: item["risk"],
        reverse=True,
    )

    return findings


# ================================================================
# COMMAND LINE
# ================================================================

def main() -> None:

    print("📡 SentinelShield Wi-Fi Scanner")
    print("=" * 50)

    findings = scan_wifi(rounds=3)

    if not findings:

        print(
            "❌ No supported Wi-Fi adapter was found "
            "or no networks were detected."
        )

        return

    for finding in findings:

        status = (
            "⚠️ Suspicious"
            if finding["risk"] >= 50
            else "✅ Safe"
        )

        print(
            f"{status} network: "
            f"{finding['ssid']}"
        )

        print(
            f"BSSID: "
            f"{finding['bssid']}"
        )

        print(
            f"RSSI: "
            f"{finding['rssi']} dBm"
        )

        print(
            f"Channel/Frequency: "
            f"{finding['channel']}"
        )

        print(
            f"Security: "
            f"{finding['security']}"
        )

        print(
            f"Risk score: "
            f"{finding['risk']}%"
        )

        print(
            f"Threat level: "
            f"{finding['threat_level']}"
        )

        print(
            f"AP count: "
            f"{finding['ap_count']}"
        )

        print(
            f"Signal history: "
            f"{finding['signals']}"
        )

        if finding["reasons"]:

            for reason in finding["reasons"]:
                print(f" - {reason}")

        print("-" * 50)


if __name__ == "__main__":
    main()