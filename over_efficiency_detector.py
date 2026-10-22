"""over_efficiency_detector.py – Over-efficiency and automated bot anomaly detection engine.

Novelty: Identifies automated, scripted, or malicious activity through abnormal
execution speed, microsecond completion times, and error-free activity patterns.
"""
from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


@dataclass
class OverEfficiencyResult:
    """Output from evaluating an activity sequence for over-efficiency anomalies."""
    is_automated: bool
    efficiency_score: float  # 0 to 100 (100 = extreme non-human automation)
    classification: str      # 'HUMAN_TYPICAL', 'POWER_USER', 'SUSPICIOUS_SCRIPT', 'BOT_AUTOMATION'
    duration_ms: float
    characters_processed: int
    char_per_sec: float
    backspace_count: int
    uniformity_index: float  # 0 to 1 (1 = exact machine clockwork intervals)
    reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class OverEfficiencyDetector:
    """Detects credential-stuffing tools, headless browsers, and automated scripts."""

    # Biological human limit: even world-champion typists rarely exceed 210 WPM (~17.5 char/sec)
    HUMAN_MAX_CHARS_PER_SEC = 18.0
    # Minimum human thought/reaction interval between distinct fields
    HUMAN_MIN_REACTION_MS = 150.0

    def analyze_interaction(
        self,
        char_count: int,
        duration_ms: float,
        interval_history_ms: Optional[List[float]] = None,
        backspace_count: int = 0,
        field_count: int = 1,
    ) -> OverEfficiencyResult:
        """Inspect operation velocity and error patterns for machine over-efficiency."""
        reasons: List[str] = []
        automation_score = 0.0

        safe_duration_ms = max(1.0, duration_ms)
        char_per_sec = (char_count / (safe_duration_ms / 1000.0)) if safe_duration_ms > 0 else 999.0

        # 1. Biological Speed Ceiling Check
        if char_per_sec > 100.0:
            automation_score += 55.0
            reasons.append(f"Impossible throughput: {char_per_sec:.1f} char/sec (script injection / paste detected)")
        elif char_per_sec > self.HUMAN_MAX_CHARS_PER_SEC:
            automation_score += 40.0
            reasons.append(f"Speed exceeds human physiological limits: {char_per_sec:.1f} char/sec (world record limit ~18 char/sec)")
        elif char_per_sec > 12.0:
            automation_score += 15.0

        # 2. Form/Action Completion Velocity
        per_field_time_ms = safe_duration_ms / max(1, field_count)
        if per_field_time_ms < 60.0 and char_count > 10:
            automation_score += 30.0
            reasons.append(f"Instantaneous multi-field form submission ({per_field_time_ms:.1f}ms per field)")

        # 3. Error-Free Execution Pattern
        # Humans routinely make backspaces/corrections (especially on longer texts).
        # Automated scripts never make typos or hit backspace unless programmed to simulate it.
        if char_count >= 25 and backspace_count == 0:
            automation_score += 15.0
            reasons.append(f"Zero-error execution across {char_count} characters without a single correction")

        # 4. Temporal Uniformity (Machine Clockwork Check)
        uniformity_index = 0.0
        if interval_history_ms and len(interval_history_ms) >= 5:
            try:
                variance = statistics.variance(interval_history_ms)
                mean_interval = statistics.mean(interval_history_ms)
                # Coefficient of variation (CV = std / mean)
                std_dev = math.sqrt(variance)
                cv = std_dev / max(1.0, mean_interval)

                # If intervals are almost identical (e.g. sleep(0.01)), CV is close to 0
                if cv < 0.08:
                    uniformity_index = round(1.0 - cv, 3)
                    automation_score += 35.0
                    reasons.append(f"Clockwork interval cadence detected (CV={cv:.3f}): synthetic timer signature")
                else:
                    uniformity_index = round(max(0.0, 1.0 - cv), 3)
            except Exception:
                uniformity_index = 0.0

        final_score = min(100.0, max(0.0, automation_score))

        if final_score >= 70.0:
            classification = "BOT_AUTOMATION"
        elif final_score >= 45.0:
            classification = "SUSPICIOUS_SCRIPT"
        elif final_score >= 25.0:
            classification = "POWER_USER"
        else:
            classification = "HUMAN_TYPICAL"

        return OverEfficiencyResult(
            is_automated=final_score >= 45.0,
            efficiency_score=round(final_score, 1),
            classification=classification,
            duration_ms=round(duration_ms, 1),
            characters_processed=char_count,
            char_per_sec=round(char_per_sec, 2),
            backspace_count=backspace_count,
            uniformity_index=uniformity_index,
            reasons=reasons or ["Action speed, duration, and variation reflect natural human behavior."],
        )

