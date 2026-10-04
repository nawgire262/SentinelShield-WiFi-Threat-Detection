"""Bounded rolling temporal RSSI analysis with configurable thresholds."""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Iterable

from runtime_config import load_runtime_config


def _parse_timestamp(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


class TemporalAnalyzer:
    """Keep bounded per-BSSID RSSI history and report explainable statistics."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or load_runtime_config()
        opts = self.config["temporal_analysis"]
        self.history_limit = int(opts["history_limit"])
        self.minimum_samples = int(opts["minimum_samples"])
        self.jump_threshold = float(opts["rssi_jump_threshold_db"])
        self.std_threshold = float(opts["rssi_std_threshold_db"])
        self._history: dict[str, deque[tuple[datetime, float]]] = defaultdict(
            lambda: deque(maxlen=self.history_limit)
        )

    def seed(self, bssid: str, history: Iterable[dict[str, Any]]) -> None:
        key = str(bssid or "").upper()
        if not key:
            return
        q = self._history[key]
        for item in history:
            try:
                value = float(item.get("rssi_dbm", item.get("rssi")))
                if -127 <= value <= 0:
                    q.append((_parse_timestamp(item.get("timestamp")), value))
            except (TypeError, ValueError, AttributeError):
                continue

    def observe(self, observation: dict[str, Any]) -> dict[str, Any]:
        return self._evaluate(observation, append=True)

    def preview(self, observation: dict[str, Any]) -> dict[str, Any]:
        """Analyze a measurement without changing history; useful before verification scans."""
        return self._evaluate(observation, append=False)

    def _evaluate(self, observation: dict[str, Any], append: bool) -> dict[str, Any]:
        bssid = str(observation.get("bssid") or "").upper()
        value = observation.get("rssi_dbm")
        if not bssid or value is None:
            return self._empty("RSSI observation unavailable")
        try:
            rssi = float(value)
        except (TypeError, ValueError):
            return self._empty("RSSI observation invalid")
        if not -127 <= rssi <= 0:
            return self._empty("RSSI outside dBm range")

        history = self._history[bssid]
        timestamp = _parse_timestamp(observation.get("timestamp"))
        previous = history[-1][1] if history else None
        prior = list(history)
        samples = prior + [(timestamp, rssi)]
        if append:
            history.append((timestamp, rssi))
            samples = list(history)
        values = [sample for _, sample in samples]
        count = len(values)
        mean = sum(values) / count
        variance = sum((sample - mean) ** 2 for sample in values) / count
        std = variance ** 0.5
        delta = abs(rssi - previous) if previous is not None else 0.0
        short_count = max(2, count // 4)
        short = values[-short_count:]
        long_range = max(values) - min(values) if count > 1 else 0.0
        short_range = max(short) - min(short) if len(short) > 1 else 0.0
        elapsed = max(1.0, (samples[-1][0] - samples[0][0]).total_seconds()) if count > 1 else 1.0
        frequency = count * 3600.0 / elapsed

        reasons: list[str] = []
        score = 0.0
        if count >= self.minimum_samples:
            if std > self.std_threshold:
                score += min(50.0, ((std - self.std_threshold) / self.std_threshold) * 50.0)
                reasons.append(f"RSSI standard deviation {std:.1f} dB exceeds configured {self.std_threshold:.1f} dB")
            if delta > self.jump_threshold:
                score += min(50.0, ((delta - self.jump_threshold) / self.jump_threshold) * 50.0)
                reasons.append(f"RSSI changed by {delta:.1f} dB; configured jump limit is {self.jump_threshold:.1f} dB")
        else:
            reasons.append(f"Insufficient temporal samples ({count}/{self.minimum_samples})")

        return {
            "bssid": bssid,
            "sample_count": count,
            "rssi_mean": round(mean, 2),
            "rssi_variance": round(variance, 2),
            "rssi_stddev": round(std, 2),
            "rssi_delta": round(delta, 2),
            "short_term_range": round(short_range, 2),
            "long_term_range": round(long_range, 2),
            "observation_frequency_per_hour": round(frequency, 3),
            "temporal_score": round(min(100.0, score), 2),
            "reasons": reasons,
        }

    @staticmethod
    def _empty(reason: str) -> dict[str, Any]:
        return {
            "sample_count": 0, "rssi_mean": None, "rssi_variance": None,
            "rssi_stddev": None, "rssi_delta": None, "short_term_range": None,
            "long_term_range": None, "observation_frequency_per_hour": 0.0,
            "temporal_score": 0.0, "reasons": [reason],
        }
