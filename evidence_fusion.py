"""Configurable, explainable fusion of independent Wi-Fi risk evidence."""
from __future__ import annotations

from typing import Any

from runtime_config import load_runtime_config
from wifi_fingerprint import vendor_for_bssid


class EvidenceFusion:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or load_runtime_config()
        fusion = self.config["evidence_fusion"]
        self.weights = dict(fusion["weights"])
        self.bands = dict(fusion["risk_bands"])
        self.constants = fusion
        self.fingerprint_config = self.config["fingerprints"]

    def classify(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """Return a bounded risk score and the evidence that contributed to it.

        Evidence values must be scores in [0, 100]; a missing component is excluded
        from the weighted denominator rather than silently treated as a negative.
        """
        components = evidence.get("scores", evidence)
        total_weight = 0.0
        weighted_score = 0.0
        used: dict[str, dict[str, float]] = {}
        reasons: list[str] = []
        for name, weight in self.weights.items():
            value = components.get(name)
            if value is None:
                continue
            try:
                score = max(0.0, min(100.0, float(value)))
            except (TypeError, ValueError, OverflowError):
                continue
            if weight <= 0:
                continue
            total_weight += weight
            weighted_score += score * weight
            used[name] = {"score": round(score, 2), "weight": weight}
            if score > 0:
                labels = evidence.get("reasons", {}).get(name, []) if isinstance(evidence.get("reasons"), dict) else []
                if isinstance(labels, str):
                    labels = [labels]
                reasons.extend(str(label) for label in labels)
        risk = round(weighted_score / total_weight, 2) if total_weight else 0.0
        if risk >= self.bands["critical"]:
            level = "CRITICAL"
        elif risk >= self.bands["high"]:
            level = "HIGH"
        elif risk >= self.bands["medium"]:
            level = "MEDIUM"
        else:
            level = "LOW"
        return {
            "risk_score": risk,
            "threat_level": level,
            "evidence_scores": used,
            "reasons": list(dict.fromkeys(reasons)),
        }

    def score_observation(
        self,
        observation: dict[str, Any],
        baseline: dict[str, Any] | None,
        trusted_ssid_aps: list[dict[str, Any]],
        temporal: dict[str, Any],
        density: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        ml_score: float | None = None,
    ) -> dict[str, Any]:
        # Wired correlation is optional.  Unlike ordinary zero-valued detector
        # outputs, it must be absent from fusion when no authorized inventory
        # was enabled, otherwise it dilutes all existing risk scores.
        scores: dict[str, float | None] = {name: (None if name == "wired" else 0.0) for name in self.weights}
        reasons: dict[str, list[str]] = {name: [] for name in self.weights}
        ssid = str(observation.get("ssid") or "")
        channel = observation.get("channel")
        security = str(observation.get("security") or "UNKNOWN").upper()
        rssi = observation.get("rssi_dbm")
        vendor = observation.get("vendor") or vendor_for_bssid(observation.get("bssid"))

        if security == "OPEN":
            scores["security"] = float(self.constants["open_security_score"])
            reasons["security"].append("Open Wi-Fi security is weaker than encrypted access")
        elif security in {"WEP", "WPA"}:
            scores["security"] = float(self.constants["weak_security_score"])
            reasons["security"].append(f"Deprecated or legacy security mode observed: {security}")

        if rssi is not None and float(rssi) >= float(self.constants["strong_rssi_threshold_dbm"]):
            scores["rssi"] = float(self.constants["strong_rssi_score"])
            reasons["rssi"].append("Unusually strong RSSI; treat as one contextual signal, not proof of spoofing")

        if baseline:
            known_channels = {int(value) for value in baseline.get("channels", []) if value is not None}
            security_history = {str(value).upper() for value in baseline.get("security_history", [])}
            if security_history and security not in security_history:
                scores["security"] = float(self.constants["security_mismatch_score"])
                scores["identity"] = max(float(scores["identity"] or 0.0), float(self.constants["unknown_bssid_same_ssid_score"]))
                reasons["identity"].append("Previously observed BSSID changed its advertised security configuration")
                reasons["security"].append("Security/encryption differs from this BSSID's recorded baseline")
            if channel is not None and known_channels and int(channel) not in known_channels:
                scores["channel"] = float(self.constants["channel_mismatch_score"])
                scores["identity"] = max(float(scores["identity"] or 0.0), float(self.constants["unknown_bssid_same_ssid_score"]))
                reasons["identity"].append("Previously observed BSSID changed its channel configuration")
                reasons["channel"].append("Channel is not in this BSSID's known channel history")
            baseline_vendor = str(baseline.get("vendor") or "").casefold()
            if vendor and baseline_vendor and str(vendor).casefold() != baseline_vendor:
                scores["identity"] = max(float(scores["identity"] or 0.0), float(self.constants["vendor_mismatch_score"]))
                reasons["identity"].append("Observed vendor/OUI differs from the fingerprint baseline")
            mean = baseline.get("rssi_mean")
            variance = baseline.get("rssi_variance")
            if rssi is not None and mean is not None:
                tolerance = max(
                    float(self.fingerprint_config["rssi_deviation_db"]),
                    float(self.fingerprint_config["rssi_standard_deviation_multiplier"])
                    * (float(variance or 0.0) ** 0.5),
                )
                deviation = abs(float(rssi) - float(mean))
                scores["fingerprint"] = min(100.0, deviation / tolerance * 100.0)
                if deviation > tolerance:
                    reasons["fingerprint"].append(f"RSSI differs from this AP's historical mean by {deviation:.1f} dB")
            elif known_channels or security_history:
                scores["fingerprint"] = 0.0
        else:
            scores["fingerprint"] = 0.0
            scores["identity"] = float(self.constants["new_ap_score"])
            if trusted_ssid_aps:
                scores["identity"] = float(self.constants["unknown_bssid_same_ssid_score"])
                reasons["identity"].append("Known SSID is being advertised by a BSSID not in the trusted AP baseline")
                known_security = {str(sec).upper() for ap in trusted_ssid_aps for sec in ap.get("security_history", [])}
                known_channels = {int(ch) for ap in trusted_ssid_aps for ch in ap.get("channels", []) if ch is not None}
                if known_security and security not in known_security:
                    scores["security"] = float(self.constants["security_mismatch_score"])
                    reasons["security"].append("New BSSID for a known SSID uses an unexpected security mode")
                if channel is not None and known_channels and int(channel) not in known_channels:
                    scores["channel"] = float(self.constants["channel_mismatch_score"])
                    reasons["channel"].append("New BSSID for a known SSID uses an unexpected channel")
            else:
                reasons["identity"].append("BSSID has not been observed before; newness alone is not treated as proof of a rogue AP")

        temporal_score = temporal.get("temporal_score") if temporal else None
        if temporal_score is not None:
            scores["temporal"] = float(temporal_score)
            reasons["temporal"].extend(temporal.get("reasons", []))
        if density:
            scores["density"] = float(density.get("score", 0.0))
            reasons["density"].extend(density.get("reasons", []))
        if context:
            scores["context"] = float(context.get("score", 0.0))
            reasons["context"].extend(context.get("reasons", []))
            wired = context.get("wired") if isinstance(context, dict) else None
            if isinstance(wired, dict):
                scores["wired"] = float(wired.get("score", 0.0))
                reasons["wired"].extend(wired.get("reasons", []))
        if ml_score is not None:
            scores["ml"] = float(ml_score)
            if ml_score > 0:
                reasons["ml"].append(f"Existing ML ensemble anomaly evidence: {ml_score:.0f}/100")

        fused = self.classify({"scores": scores, "reasons": reasons})
        return {
            **fused,
            "scores": scores,
            "reasons": fused["reasons"],
        }
