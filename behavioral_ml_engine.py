"""behavioral_ml_engine.py – Hybrid Machine Learning engine for behavioral and log anomaly detection.

Novelty: Combines Isolation Forest (unsupervised anomaly detection) and
Random Forest (supervised classification) to achieve high-precision detection
of automated bots, credential stuffing, and behavioral biometric divergence.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

LOGGER = logging.getLogger(__name__)


@dataclass
class HybridMLPrediction:
    """Consolidated prediction from the Isolation Forest + Random Forest ensemble."""
    rf_prediction: str               # 'HUMAN_LEGIT' or 'AUTOMATED_ANOMALOUS'
    rf_confidence: float             # 0 to 100%
    iso_anomaly: bool                # True if Isolation Forest flags as outlier
    iso_anomaly_score: float         # Raw decision score
    hybrid_threat_score: float       # Consolidated risk (0 to 100)
    verdict: str                     # 'SAFE', 'SUSPICIOUS', 'MALICIOUS_AUTOMATION'
    feature_contributions: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BehavioralHybridMLEngine:
    """Ensemble engine combining Isolation Forest and Random Forest on behavioral features."""

    FEATURE_NAMES = [
        "typing_speed_wpm",
        "mean_flight_time_ms",
        "std_flight_time_ms",
        "mean_dwell_time_ms",
        "char_per_sec",
        "error_rate",
        "uniformity_index",
    ]

    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self.iso_forest = IsolationForest(n_estimators=50, contamination=0.15, random_state=42, n_jobs=-1)
        self.rf_classifier = RandomForestClassifier(n_estimators=50, max_depth=6, random_state=42, n_jobs=-1)
        self.is_trained = False
        self._initialize_baseline_models()

    def _generate_synthetic_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Synthesize training distributions representing human typists vs. automated scripts."""
        np.random.seed(42)
        n_human = 350
        n_bot = 250

        # Human Distribution:
        # WPM ~ 35-85, flight ~ 80-180ms, std_flight ~ 20-55ms, dwell ~ 65-110ms,
        # char_per_sec ~ 2.5-7.0, error_rate ~ 0.02-0.12, uniformity ~ 0.1-0.4
        human_wpm = np.random.normal(58.0, 14.0, n_human).clip(20.0, 110.0)
        human_flight = np.random.normal(120.0, 30.0, n_human).clip(60.0, 250.0)
        human_std_flight = np.random.normal(35.0, 10.0, n_human).clip(15.0, 75.0)
        human_dwell = np.random.normal(85.0, 15.0, n_human).clip(50.0, 140.0)
        human_cps = (human_wpm * 5.0 / 60.0).clip(1.5, 9.0)
        human_err = np.random.beta(2, 25, n_human).clip(0.01, 0.25)
        human_unif = np.random.beta(2, 8, n_human).clip(0.05, 0.45)

        X_human = np.column_stack([human_wpm, human_flight, human_std_flight, human_dwell, human_cps, human_err, human_unif])
        y_human = np.zeros(n_human)

        # Bot / Script Distribution:
        # WPM ~ 250-1800, flight ~ 0-15ms, std_flight ~ 0-4ms, dwell ~ 2-15ms,
        # char_per_sec ~ 25-150, error_rate ~ 0.0, uniformity ~ 0.85-0.99
        bot_wpm = np.random.uniform(220.0, 1500.0, n_bot)
        bot_flight = np.random.normal(6.0, 3.0, n_bot).clip(0.5, 20.0)
        bot_std_flight = np.random.normal(1.2, 0.8, n_bot).clip(0.0, 4.0)
        bot_dwell = np.random.normal(8.0, 3.0, n_bot).clip(1.0, 20.0)
        bot_cps = np.random.uniform(20.0, 120.0, n_bot)
        bot_err = np.zeros(n_bot)
        bot_unif = np.random.uniform(0.85, 0.99, n_bot)

        X_bot = np.column_stack([bot_wpm, bot_flight, bot_std_flight, bot_dwell, bot_cps, bot_err, bot_unif])
        y_bot = np.ones(n_bot)

        X = np.vstack([X_human, X_bot])
        y = np.concatenate([y_human, y_bot])
        return X, y

    def _initialize_baseline_models(self) -> None:
        """Fit Isolation Forest and Random Forest onto the baseline behavioral distributions."""
        try:
            X, y = self._generate_synthetic_training_data()
            X_scaled = self.scaler.fit_transform(X)
            self.iso_forest.fit(X_scaled[y == 0])  # Isolation Forest learns authentic human profile
            self.rf_classifier.fit(X_scaled, y)    # Random Forest learns boundary
            self.is_trained = True
            LOGGER.info("Behavioral Hybrid ML models successfully initialized.")
        except Exception as exc:
            LOGGER.error("Failed to initialize Behavioral Hybrid ML engine: %s", exc)

    def predict(self, feature_dict: Dict[str, float]) -> HybridMLPrediction:
        """Evaluate a behavioral feature vector through the hybrid ensemble."""
        if not self.is_trained:
            self._initialize_baseline_models()

        raw_vector = np.array([[
            float(feature_dict.get("typing_speed_wpm", 60.0)),
            float(feature_dict.get("mean_flight_time_ms", 120.0)),
            float(feature_dict.get("std_flight_time_ms", 35.0)),
            float(feature_dict.get("mean_dwell_time_ms", 85.0)),
            float(feature_dict.get("char_per_sec", 5.0)),
            float(feature_dict.get("error_rate", 0.05)),
            float(feature_dict.get("uniformity_index", 0.15)),
        ]])

        scaled_vector = self.scaler.transform(raw_vector)

        # 1. Isolation Forest Evaluation
        iso_pred = self.iso_forest.predict(scaled_vector)[0]  # -1 for anomaly, 1 for inlier
        iso_score = float(self.iso_forest.score_samples(scaled_vector)[0])
        is_iso_anomaly = bool(iso_pred == -1)

        # 2. Random Forest Evaluation
        rf_probs = self.rf_classifier.predict_proba(scaled_vector)[0]
        bot_probability = float(rf_probs[1]) if len(rf_probs) > 1 else 0.0
        rf_confidence = round(bot_probability * 100.0, 1)
        rf_prediction = "AUTOMATED_ANOMALOUS" if bot_probability >= 0.5 else "HUMAN_LEGIT"

        # 3. Consolidated Hybrid Threat Score (0 to 100)
        # Combines supervised probability with unsupervised anomaly distance
        iso_penalty = 35.0 if is_iso_anomaly else 0.0
        hybrid_score = round(min(100.0, max(0.0, (bot_probability * 65.0) + iso_penalty)), 1)

        if hybrid_score >= 70.0:
            verdict = "MALICIOUS_AUTOMATION"
        elif hybrid_score >= 35.0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        # Feature importance delta contributions
        importances = self.rf_classifier.feature_importances_
        contributions = {
            name: round(float(importances[idx] * 100.0), 1)
            for idx, name in enumerate(self.FEATURE_NAMES)
        }

        return HybridMLPrediction(
            rf_prediction=rf_prediction,
            rf_confidence=rf_confidence,
            iso_anomaly=is_iso_anomaly,
            iso_anomaly_score=round(iso_score, 3),
            hybrid_threat_score=hybrid_score,
            verdict=verdict,
            feature_contributions=contributions,
        )

