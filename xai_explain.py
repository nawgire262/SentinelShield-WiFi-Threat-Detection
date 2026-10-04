"""Model-level explanations for the saved Wi-Fi ensemble.

Occlusion replaces one live feature with the legitimate-training median and
records how P(Fake) changes. Permutation importance is a training-row
diagnostic of which inputs the saved model uses. Neither number is a
detection rate.
"""

from __future__ import annotations

import numpy as np

BASE_FEATURES = ["RSSI", "Channel", "Security_enc", "AP_Count", "Signal_Var"]
FEATURE_LABELS = {
    "RSSI": "RSSI",
    "Channel": "Channel (MHz)",
    "Security_enc": "Security",
    "AP_Count": "AP count",
    "Signal_Var": "Signal variance",
}


def local_occlusion(score_fn, row, baseline, feature_names=None) -> list[dict]:
    """Signed change in P(Fake) when each feature is replaced by `baseline`.

    `score_fn` accepts a 2-D array and returns one probability per row.
    """
    names = list(feature_names or BASE_FEATURES)
    observed = np.asarray(row, dtype=float).reshape(-1)
    anchor = np.asarray(baseline, dtype=float).reshape(-1)
    if observed.shape != anchor.shape or observed.size != len(names):
        raise ValueError("row, baseline, and feature names must have the same length")
    matrix = [observed]
    for index in range(len(names)):
        ablated = observed.copy()
        ablated[index] = anchor[index]
        matrix.append(ablated)
    scores = np.asarray(score_fn(np.vstack(matrix)), dtype=float).reshape(-1)
    original = float(scores[0])
    effects = []
    for index, name in enumerate(names):
        delta = original - float(scores[index + 1])
        effects.append({
            "feature": name,
            "label": FEATURE_LABELS.get(name, name),
            "delta": round(delta, 6),
            "delta_points": round(delta * 100.0, 2),
        })
    return effects


def explanation_payload(effects: list[dict], method: str = "occlusion") -> dict:
    ranked = sorted(effects, key=lambda item: abs(item["delta"]), reverse=True)
    top = ranked[0] if ranked else None
    if top is None or abs(top["delta"]) < 0.005:
        summary = "No model input moves P(Fake) by more than half a point from the legitimate baseline."
    else:
        direction = "raises" if top["delta"] > 0 else "lowers"
        summary = (
            f"{top['label']} {direction} P(Fake) by {abs(top['delta_points']):.1f} points "
            "compared with the legitimate baseline."
        )
    return {
        "method": method,
        "summary": summary,
        "effects": effects,
        "is_detection_accuracy": False,
    }


def permutation_importance(score_fn, rows, labels, feature_names=None, n_repeats: int = 5, seed: int = 42) -> list[dict] | None:
    """Mean drop in training-row ROC-AUC when each column is shuffled.

    This describes the fitted model. It is not a held-out detection score.
    """
    from sklearn.metrics import roc_auc_score

    names = list(feature_names or BASE_FEATURES)
    matrix = np.asarray(rows, dtype=float)
    target = np.asarray(labels, dtype=int).reshape(-1)
    if matrix.ndim != 2 or matrix.shape[1] != len(names) or len(np.unique(target)) < 2:
        return None
    baseline = float(roc_auc_score(target, np.asarray(score_fn(matrix), dtype=float).reshape(-1)))
    generator = np.random.default_rng(seed)
    ranked = []
    for index, name in enumerate(names):
        drops = []
        for _ in range(n_repeats):
            shuffled = matrix.copy()
            generator.shuffle(shuffled[:, index])
            scored = float(roc_auc_score(target, np.asarray(score_fn(shuffled), dtype=float).reshape(-1)))
            drops.append(baseline - scored)
        ranked.append({
            "feature": name,
            "label": FEATURE_LABELS.get(name, name),
            "importance": round(float(np.mean(drops)), 6),
        })
    ranked.sort(key=lambda item: item["importance"], reverse=True)
    return ranked
