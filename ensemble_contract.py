"""Shared feature contract for the stacked Wi-Fi ensemble.

Training and inference both build meta features as
[Random Forest P(Fake), KNN P(Fake), negated Isolation Forest decision]
and pass them through the same saved StandardScaler.
"""

from __future__ import annotations

import numpy as np

FEATURES = ["RSSI", "Channel", "Security_enc", "AP_Count", "Signal_Var"]
META_FEATURES = ["rf_fake_probability", "knn_fake_probability", "isolation_anomaly"]


def probability_column(model, proba, positive_label: int) -> np.ndarray:
    """Return P(positive_label) using the estimator's own class order."""
    matrix = np.asarray(proba, dtype=float)
    if matrix.ndim == 1:
        matrix = matrix.reshape(1, -1)
    classes = list(model.classes_)
    if positive_label not in classes:
        return np.zeros(len(matrix), dtype=float)
    return matrix[:, classes.index(positive_label)]


def meta_feature_matrix(rf_fake, knn_fake, isolation_anomaly) -> np.ndarray:
    return np.column_stack([
        np.asarray(rf_fake, dtype=float).reshape(-1),
        np.asarray(knn_fake, dtype=float).reshape(-1),
        np.asarray(isolation_anomaly, dtype=float).reshape(-1),
    ])


def score_features(rf_model, knn_model, iso_model, meta_model, feature_scaler, meta_scaler, positive_label: int, raw_features) -> dict:
    """Score raw feature rows with the scalers that were fit at training time."""
    raw = np.asarray(raw_features, dtype=float)
    if raw.ndim == 1:
        raw = raw.reshape(1, -1)
    scaled = feature_scaler.transform(raw)
    rf_fake = probability_column(rf_model, rf_model.predict_proba(scaled), positive_label)
    knn_fake = probability_column(knn_model, knn_model.predict_proba(scaled), positive_label)
    isolation_anomaly = -np.asarray(iso_model.decision_function(scaled), dtype=float).reshape(-1)
    meta_raw = meta_feature_matrix(rf_fake, knn_fake, isolation_anomaly)
    meta_scaled = meta_scaler.transform(meta_raw)
    meta_fake = probability_column(meta_model, meta_model.predict_proba(meta_scaled), positive_label)
    return {
        "rf_fake": rf_fake,
        "knn_fake": knn_fake,
        "isolation_anomaly": isolation_anomaly,
        "meta_fake": meta_fake,
    }
