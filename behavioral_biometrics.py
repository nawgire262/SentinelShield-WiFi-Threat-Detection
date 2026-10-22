"""behavioral_biometrics.py – Behavioral biometrics and typing speed analysis engine.

Novelty: Introduces typing cadence, keystroke dynamics, and rhythm variance
analysis to detect suspicious user behavior beyond credential-based authentication.
"""
from __future__ import annotations

import math
import statistics
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


@dataclass
class KeystrokeEvent:
    """Represents a single key press event with dwell and flight timings."""
    key: str
    press_time_ms: float
    release_time_ms: float

    @property
    def dwell_time_ms(self) -> float:
        """Time the key remained held down."""
        return max(0.0, self.release_time_ms - self.press_time_ms)


@dataclass
class BiometricProfile:
    """Baseline typing profile for an authentic user."""
    user_id: str
    baseline_wpm: float = 60.0
    mean_flight_time_ms: float = 120.0
    std_flight_time_ms: float = 35.0
    mean_dwell_time_ms: float = 85.0
    typical_error_rate: float = 0.05  # 5% typos expected for humans


@dataclass
class BiometricAssessment:
    """Output from evaluating a typing dynamics session."""
    user_id: str
    typing_speed_wpm: float
    mean_flight_time_ms: float
    std_flight_time_ms: float
    mean_dwell_time_ms: float
    error_rate: float
    similarity_score: float  # 0 to 100%
    is_anomaly: bool
    risk_score: float        # 0 to 100
    reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BehavioralBiometricsEngine:
    """Extracts keystroke dynamics and calculates biometric deviation from baseline."""

    def __init__(self) -> None:
        self._profiles: Dict[str, BiometricProfile] = {}
        # Pre-seed default legitimate baseline for demo
        self.register_profile(BiometricProfile(user_id="admin_user", baseline_wpm=62.0, mean_flight_time_ms=115.0, std_flight_time_ms=32.0, mean_dwell_time_ms=80.0, typical_error_rate=0.04))

    def register_profile(self, profile: BiometricProfile) -> None:
        self._profiles[profile.user_id] = profile

    def get_profile(self, user_id: str) -> BiometricProfile:
        return self._profiles.get(user_id, BiometricProfile(user_id=user_id))

    def extract_features(self, events: List[KeystrokeEvent], total_duration_ms: float, backspace_count: int = 0) -> Dict[str, float]:
        """Compute summary keystroke biometric metrics from raw events."""
        if not events:
            return {
                "wpm": 0.0,
                "mean_flight": 0.0,
                "std_flight": 0.0,
                "mean_dwell": 0.0,
                "error_rate": 0.0,
            }

        # Dwell times
        dwells = [e.dwell_time_ms for e in events]
        mean_dwell = statistics.mean(dwells) if dwells else 80.0

        # Flight times (intervals between consecutive keys)
        flights: List[float] = []
        for i in range(len(events) - 1):
            flight = events[i + 1].press_time_ms - events[i].release_time_ms
            flights.append(flight)

        mean_flight = statistics.mean(flights) if flights else 100.0
        std_flight = statistics.stdev(flights) if len(flights) > 1 else 0.0

        # Typing Speed (WPM): standard formula assumes 5 characters = 1 word
        char_count = len(events)
        minutes = max(0.001, total_duration_ms / 60000.0)
        wpm = round((char_count / 5.0) / minutes, 1)

        # Error rate (backspaces / total keypresses)
        total_actions = char_count + backspace_count
        error_rate = round(backspace_count / max(1, total_actions), 3)

        return {
            "wpm": wpm,
            "mean_flight": round(mean_flight, 2),
            "std_flight": round(std_flight, 2),
            "mean_dwell": round(mean_dwell, 2),
            "error_rate": error_rate,
        }

    def evaluate_session(
        self,
        user_id: str,
        events: List[KeystrokeEvent],
        total_duration_ms: float,
        backspace_count: int = 0,
    ) -> BiometricAssessment:
        """Evaluate a user session against their enrolled behavioral profile."""
        profile = self.get_profile(user_id)
        metrics = self.extract_features(events, total_duration_ms, backspace_count)

        wpm = metrics["wpm"]
        mean_flight = metrics["mean_flight"]
        std_flight = metrics["std_flight"]
        mean_dwell = metrics["mean_dwell"]
        error_rate = metrics["error_rate"]

        reasons: List[str] = []
        anomaly_points = 0.0

        # 1. Flight time rhythm deviation
        flight_diff = abs(mean_flight - profile.mean_flight_time_ms)
        if flight_diff > 60.0:
            anomaly_points += 30.0
            reasons.append(f"Keystroke flight cadence differs from baseline (diff={flight_diff:.1f}ms)")
        elif flight_diff > 35.0:
            anomaly_points += 15.0

        # 2. Dwell time anomaly
        dwell_diff = abs(mean_dwell - profile.mean_dwell_time_ms)
        if dwell_diff > 45.0:
            anomaly_points += 25.0
            reasons.append(f"Key hold duration atypical (observed={mean_dwell:.1f}ms, baseline={profile.mean_dwell_time_ms:.1f}ms)")

        # 3. Typing speed deviation
        wpm_ratio = wpm / max(1.0, profile.baseline_wpm)
        if wpm_ratio > 2.5:
            anomaly_points += 35.0
            reasons.append(f"Typing speed dramatically exceeds baseline profile ({wpm:.0f} WPM vs {profile.baseline_wpm:.0f} WPM)")
        elif wpm_ratio < 0.4:
            anomaly_points += 15.0
            reasons.append(f"Typing speed significantly below historical baseline ({wpm:.0f} WPM)")

        # 4. Mechanical rhythm uniformity (Robotic consistency)
        if std_flight < 4.0 and len(events) >= 8:
            anomaly_points += 40.0
            reasons.append(f"Robotic cadence detected: flight time variance abnormally near zero (std={std_flight:.1f}ms)")

        # Similarity score
        similarity = max(0.0, min(100.0, 100.0 - anomaly_points))
        risk_score = round(max(0.0, min(100.0, anomaly_points)), 1)
        is_anomaly = risk_score >= 45.0

        return BiometricAssessment(
            user_id=user_id,
            typing_speed_wpm=wpm,
            mean_flight_time_ms=mean_flight,
            std_flight_time_ms=std_flight,
            mean_dwell_time_ms=mean_dwell,
            error_rate=error_rate,
            similarity_score=round(similarity, 1),
            is_anomaly=is_anomaly,
            risk_score=risk_score,
            reasons=reasons or ["Typing behavioral biometrics match authentic user profile."],
        )

