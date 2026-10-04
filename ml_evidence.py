"""Fail-safe inference adapter for the repository's existing RF/KNN/IF stack.

No training occurs here. Features are RSSI, frequency in MHz, Security_enc,
AP_Count and Signal_Var. Base features and meta features are transformed with
the scalers saved by train_model.py. Per-AP occlusion uses the legitimate
training median when that baseline was saved.
"""
from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Any

import numpy as np

from ensemble_contract import FEATURES, score_features
from xai_explain import explanation_payload, local_occlusion

LOGGER = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parent


class ExistingModelEvidence:
    def __init__(self, model_dir: str | Path = ROOT) -> None:
        self.model_dir = Path(model_dir)
        self.rf = self.knn = self.isolation = self.meta = None
        self.security_encoder = self.label_encoder = None
        self.feature_scaler = self.meta_scaler = None
        self.baseline = None
        self.load_error: str | None = None
        try:
            self.rf = self._load("rf_model.pkl")
            self.knn = self._load("knn_model.pkl")
            self.isolation = self._load("iso_model.pkl")
            self.meta = self._load("meta_model.pkl")
            self.security_encoder = self._load("le_security.pkl")
            self.label_encoder = self._load("le_label.pkl")
            self.feature_scaler = self._load("scaler.pkl")
            self.meta_scaler = self._load("meta_scaler.pkl")
            self.baseline = self._load("explanation_baseline.pkl")
            if not all((self.rf, self.knn, self.isolation, self.meta, self.security_encoder, self.label_encoder, self.feature_scaler, self.meta_scaler)):
                raise ValueError("one or more expected model artifacts are empty")
        except Exception as exc:
            self.load_error = f"Existing ensemble unavailable: {type(exc).__name__}: {exc}"
            LOGGER.warning(self.load_error)
            self.rf = self.knn = self.isolation = self.meta = None
            self.feature_scaler = self.meta_scaler = None

    def _load(self, filename: str) -> Any:
        path = self.model_dir / filename
        if not path.is_file():
            return None
        with path.open("rb") as handle:
            return pickle.load(handle)

    @property
    def available(self) -> bool:
        return self.rf is not None and self.knn is not None and self.isolation is not None and self.meta is not None and self.feature_scaler is not None and self.meta_scaler is not None

    def _explain(self, raw_row: np.ndarray, fake_class: int) -> dict[str, Any] | None:
        if self.baseline is None:
            return None
        baseline = np.asarray(self.baseline, dtype=float).reshape(-1)

        def score_fn(matrix: np.ndarray) -> np.ndarray:
            return score_features(
                self.rf, self.knn, self.isolation, self.meta,
                self.feature_scaler, self.meta_scaler, fake_class, matrix,
            )["meta_fake"]

        return explanation_payload(local_occlusion(score_fn, raw_row, baseline, FEATURES))

    def predict(self, observation: dict[str, Any], ap_count: int, signal_variance: float) -> dict[str, Any] | None:
        return self.predict_many([observation], [ap_count], [signal_variance])[0]

    def predict_many(self, observations: list[dict[str, Any]], ap_counts: list[int], signal_variances: list[float]) -> list[dict[str, Any] | None]:
        if not self.available:
            return [None] * len(observations)
        try:
            classes = list(self.label_encoder.classes_)
            if "Fake" not in classes:
                return [None] * len(observations)
            fake_class = int(self.label_encoder.transform(["Fake"])[0])
            security_classes = list(self.security_encoder.classes_)
            rows = []
            for observation, ap_count, signal_variance in zip(observations, ap_counts, signal_variances):
                security = str(observation.get("security") or "OPEN").upper()
                security = {"WPA/WPA2": "WPA2", "SECURED": "WPA2", "WPA/WPA2/WPA3": "WPA3"}.get(security, security)
                if security not in security_classes:
                    security = "WPA2" if security != "OPEN" and "WPA2" in security_classes else "Open" if "Open" in security_classes else security_classes[0]
                rows.append({
                    "RSSI": float(observation.get("rssi_dbm") if observation.get("rssi_dbm") is not None else -80),
                    # Existing models were trained in MHz even though this feature is named Channel.
                    "Channel": float(observation.get("frequency_mhz") or 0),
                    "Security_enc": int(self.security_encoder.transform([security])[0]),
                    "AP_Count": int(ap_count),
                    "Signal_Var": float(signal_variance),
                })
            raw = np.array([[row[name] for name in FEATURES] for row in rows], dtype=float)
            scored = score_features(
                self.rf, self.knn, self.isolation, self.meta,
                self.feature_scaler, self.meta_scaler, fake_class, raw,
            )
            explanations = [self._explain(raw[i], fake_class) for i in range(len(rows))]
            return [{
                "available": True,
                "rf_fake_probability": round(float(scored["rf_fake"][i]), 4),
                "knn_fake_probability": round(float(scored["knn_fake"][i]), 4),
                "isolation_anomaly_score": round(float(scored["isolation_anomaly"][i]), 4),
                "fake_probability": round(float(scored["meta_fake"][i]), 4),
                "risk_score": round(float(scored["meta_fake"][i]) * 100, 2),
                "explanation": explanations[i],
                "model_files": ["rf_model.pkl", "knn_model.pkl", "iso_model.pkl", "meta_model.pkl", "scaler.pkl", "meta_scaler.pkl"],
            } for i in range(len(rows))]
        except Exception as exc:
            LOGGER.warning("Existing ML inference skipped: %s", exc)
            return [None] * len(observations)
