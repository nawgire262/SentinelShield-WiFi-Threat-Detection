"""Explainable novelty-driven alert rules for SentinelShield Wi-Fi scans.

This module does not claim a network is malicious from a single weak clue.
Strong security evidence (cloud reputation, RAIM, or layer-2 attack detection)
can alert immediately; weaker signals are fused and require corroboration.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Mapping
import math


def _number(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return result if math.isfinite(result) else default
    except (TypeError, ValueError, OverflowError):
        return default


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"true", "yes", "1", "on", "hit", "flagged", "detected"}


@dataclass(frozen=True)
class NoveltyAssessment:
    should_alert: bool
    level: str
    novelty_score: int
    trigger_type: str
    evidence: tuple[str, ...]
    strong_evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        result["strong_evidence"] = list(self.strong_evidence)
        return result


def evaluate_novelty(row: Mapping[str, Any]) -> NoveltyAssessment:
    """Evaluate row fields emitted by dashboard.scan_to_frame()."""
    evidence: list[str] = []
    strong: list[str] = []
    score = 0
    base_risk = max(0, min(100, _number(row.get("Combined_Risk", row.get("Risk_Score", 0)))))

    # Novelty: cloud threat-intelligence/reputation evidence.
    cloud_risk = max(_number(row.get("Cloud_Risk")), _number(row.get("Cloud_Risk_Score")))
    if _truthy(row.get("Cloud_Reputation_Hit")) or cloud_risk >= 75:
        evidence.append(f"Cloud reputation hit/high cloud risk ({cloud_risk:.0f}/100)")
        strong.append("cloud_reputation")
        score += 45

    # Novelty: RAIM-style location/consistency evidence and Layer-2 indicators.
    if _truthy(row.get("RAIM_Flagged")) or _number(row.get("RAIM_Score")) >= 75:
        evidence.append("RAIM consistency check flagged this observation")
        score += 35
        # Only treat as a strong candidate if corroborated by high RAIM score or elevated risk
        if _number(row.get("RAIM_Score")) >= 75 or base_risk >= 50:
            strong.append("raim_flag")

    layer2_score = _number(row.get("Layer2_Score"))
    if _truthy(row.get("Layer2_Deauth_Detected")) or layer2_score >= 75:
        detail = str(row.get("Layer2_Reasons") or "deauthentication/jamming evidence")
        evidence.append(f"Layer-2 anomaly: {detail[:180]}")
        strong.append("layer2_attack")
        score += 40

    # Novelty: temporal RSSI behaviour. Require enough observations to reduce
    # single-sample noise; a large range or variance is only one weak indicator.
    observations = int(max(0, _number(row.get("Observation_Count"))))
    fluctuation = abs(_number(row.get("Signal_Fluctuation")))
    variance = max(0, _number(row.get("Signal_Variance")))
    temporal_score = _number(row.get("Temporal_Score", row.get("temporal_score", 0)))
    if observations >= 3 and (fluctuation >= 18 or variance >= 36 or temporal_score >= 50):
        evidence.append(f"Unusual temporal RSSI behaviour (range={fluctuation:.1f} dB, variance={variance:.1f}, temporal score={temporal_score:.1f}, n={observations})")
        score += 15

    # A change against an established fingerprint is evidence of change, not proof
    # of an attack. Keep it weak so it must be corroborated before alerting.
    if _truthy(row.get("Fingerprint_Changed")):
        detail = str(row.get("Fingerprint_Change_Reasons") or "established fingerprint attributes changed")
        evidence.append(f"Established Wi-Fi fingerprint changed: {detail[:180]}")
        score += 20

    # Novelty: multiple BSSIDs advertising one SSID may be legitimate (mesh/roaming),
    # so density is weak evidence and must be corroborated by another signal.
    ap_count = int(max(0, _number(row.get("AP_Count"))))
    density_score = _number(row.get("Density_Score", row.get("density_score", 0)))
    if ap_count >= 3 or density_score >= 35:
        evidence.append(f"SSID/BSSID density signal: {ap_count} access points observed for this SSID (density score={density_score:.1f})")
        score += 12

    # Novelty: a poor match against the stored baseline fingerprint.
    similarity = _number(row.get("Fingerprint_Similarity"), default=-1)
    # Dashboard/controller exports similarity as a percentage (0..100).
    # Accept normalized fractions too for older integrations.
    if 0 <= similarity <= 1:
        similarity_percent = similarity * 100
    else:
        similarity_percent = similarity
    if 0 <= similarity_percent <= 65 and _truthy(row.get("Fingerprint_Baseline_Exists", True)):
        evidence.append(f"Wi-Fi fingerprint differs from baseline (similarity={similarity_percent:.1f}%)")
        score += 20

    # Isolation Forest convention: -1 means anomaly in sklearn predict output.
    # Other numeric scales are not assumed because artifacts may emit raw scores.
    if _number(row.get("Isolation_Forest"), default=0) == -1:
        evidence.append("Isolation Forest classified this observation as an anomaly")
        score += 20

    fake_confidence = _number(row.get("Meta_Confidence"))
    if fake_confidence >= 80:
        evidence.append(f"Hybrid model fake-network confidence is high ({fake_confidence:.0f}%)")
        score += 25

    score = min(100, score)
    # Active confirmed attacks that justify an alert regardless of baseline risk
    has_active_attack = bool({"cloud_reputation", "layer2_attack"}.intersection(strong))

    # A strong indicator is enough for a HIGH alert if corroborated or risk >= 50.
    # Weak evidence requires corroboration AND a meaningful risk score (>= 40).
    weak_count = len(evidence) - len(strong)
    should_alert = (
        has_active_attack
        or ("raim_flag" in strong and base_risk >= 50)
        or (weak_count >= 2 and base_risk >= 50)
        or (weak_count >= 3 and base_risk >= 40)
        or (base_risk >= 65)
    )

    if base_risk >= 85 or (has_active_attack and score >= 70) or (len(strong) >= 2 and base_risk >= 50):
        level = "CRITICAL"
    elif should_alert:
        level = "HIGH"
    elif base_risk >= 50:
        level = "MEDIUM"
    else:
        level = "MEDIUM" if (evidence and base_risk >= 20) else "SAFE"

    trigger_type = "+".join(strong) if strong else ("multi_signal_fusion" if should_alert else "risk_threshold" if base_risk >= 65 else "observation")
    return NoveltyAssessment(should_alert, level, score, trigger_type, tuple(evidence), tuple(strong))
