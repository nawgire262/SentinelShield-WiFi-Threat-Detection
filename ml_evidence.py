"""Fail-safe inference adapter for the repository's existing RF/KNN/IF stack.

No training occurs here. Existing feature contract is RSSI, frequency-MHz Channel,
Security_enc, AP_Count and Signal_Var as emitted by train_model.py.
"""
from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Any

import pandas as pd

LOGGER = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parent


class ExistingModelEvidence:
    def __init__(self, model_dir: str | Path = ROOT) -> None:
        self.model_dir = Path(model_dir)
        self.rf = self.knn = self.isolation = self.meta = None
        self.security_encoder = self.label_encoder = None
        self.load_error: str | None = None
        try:
            self.rf = self._load("rf_model.pkl")
            self.knn = self._load("knn_model.pkl")
            self.isolation = self._load("iso_model.pkl")
            self.meta = self._load("meta_model.pkl")
            self.security_encoder = self._load("le_security.pkl")
            self.label_encoder = self._load("le_label.pkl")
            if not all((self.rf, self.knn, self.isolation, self.meta, self.security_encoder, self.label_encoder)):
                raise ValueError("one or more expected model artifacts are empty")
        except Exception as exc:
            self.load_error = f"Existing ensemble unavailable: {type(exc).__name__}: {exc}"
            LOGGER.warning(self.load_error)
            self.rf = self.knn = self.isolation = self.meta = None

    def _load(self, filename: str) -> Any:
        path = self.model_dir / filename
        if not path.is_file():
            return None
        with path.open("rb") as handle:
            return pickle.load(handle)

    @property
    def available(self) -> bool:
        return self.rf is not None and self.knn is not None and self.isolation is not None and self.meta is not None

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
            features = pd.DataFrame(rows, columns=["RSSI", "Channel", "Security_enc", "AP_Count", "Signal_Var"])
            rf_matrix = self.rf.predict_proba(features)
            knn_matrix = self.knn.predict_proba(features)
            rf_classes = list(self.rf.classes_)
            knn_classes = list(self.knn.classes_)
            rf_index = rf_classes.index(fake_class) if fake_class in rf_classes else 0
            knn_index = knn_classes.index(fake_class) if fake_class in knn_classes else 0
            rf_fake = rf_matrix[:, rf_index]
            knn_fake = knn_matrix[:, knn_index]
            anomaly = [max(0.0, float(-value)) for value in self.isolation.decision_function(features)]
            meta_input = [[float(rf_fake[i]), float(knn_fake[i]), anomaly[i]] for i in range(len(rows))]
            meta_matrix = self.meta.predict_proba(meta_input)
            meta_classes = list(self.meta.classes_)
            meta_index = meta_classes.index(fake_class) if fake_class in meta_classes else 0
            return [{
                "available": True,
                "rf_fake_probability": round(float(rf_fake[i]), 4),
                "knn_fake_probability": round(float(knn_fake[i]), 4),
                "isolation_anomaly_score": round(anomaly[i], 4),
                "fake_probability": round(float(meta_matrix[i, meta_index]), 4),
                "risk_score": round(float(meta_matrix[i, meta_index]) * 100, 2),
                "model_files": ["rf_model.pkl", "knn_model.pkl", "iso_model.pkl", "meta_model.pkl"],
            } for i in range(len(rows))]
        except Exception as exc:
            LOGGER.warning("Existing ML inference skipped: %s", exc)
            return [None] * len(observations)
