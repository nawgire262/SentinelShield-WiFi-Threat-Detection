"""
ml_ensemble.py
======================
Hybrid stacked ensemble for Wi-Fi threat detection.

Detection stack:
  - Random Forest
  - KNN
  - Isolation Forest, fit only on rows labeled Legit
  - Logistic Regression meta-classifier on out-of-fold base scores

Meta features are scaled with a StandardScaler that is saved and applied
again at prediction time. This module does not print a detection score.
Use evaluation.py for held-out precision, recall, F1, and false-positive rate.
"""

import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler

from ensemble_contract import FEATURES, probability_column, score_features
from xai_explain import BASE_FEATURES, explanation_payload, local_occlusion, permutation_importance


class HybridEnsembleDetector:
    """Stacked RF / KNN / Isolation Forest detector."""

    def __init__(self, n_estimators: int = 200, n_neighbors: int = 5, random_state: int = 42):
        self.n_estimators = n_estimators
        self.n_neighbors = n_neighbors
        self.random_state = random_state
        self.rf_model = None
        self.knn_model = None
        self.iso_model = None
        self.meta_model = None
        self.le_security = None
        self.le_label = None
        self.scaler = None
        self.meta_scaler = None
        self.explanation_baseline_ = None
        self.permutation_importance_ = None
        self.is_trained = False
        self.fake_label_ = None
        self.training_matrix_ = None
        self.training_labels_ = None

    def _new_isolation(self) -> IsolationForest:
        return IsolationForest(
            n_estimators=self.n_estimators,
            contamination="auto",
            random_state=self.random_state,
            n_jobs=1,
        )

    def _encode_frame(self, frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        data = frame.copy()
        if "Security_enc" not in data.columns:
            if self.le_security is None:
                self.le_security = LabelEncoder()
                data["Security_enc"] = self.le_security.fit_transform(data["Security"].fillna("OPEN").astype(str))
            else:
                data["Security_enc"] = data["Security"].map(self._security_code)
        if "Label_enc" not in data.columns:
            if self.le_label is None:
                self.le_label = LabelEncoder()
                data["Label_enc"] = self.le_label.fit_transform(data["Label"].astype(str))
            else:
                data["Label_enc"] = self.le_label.transform(data["Label"].astype(str))
        self.fake_label_ = int(self.le_label.transform(["Fake"])[0])
        features = data[FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0.0)
        return features.to_numpy(dtype=float), data["Label_enc"].to_numpy(dtype=int)

    def _security_code(self, value: object) -> int:
        text = str(value or "OPEN")
        classes = list(self.le_security.classes_)
        if text not in classes:
            text = "WPA2" if "WPA2" in classes else classes[0]
        return int(self.le_security.transform([text])[0])

    def train_frame(self, frame: pd.DataFrame, compute_importance: bool = True) -> bool:
        """Fit the stack on an already cleaned frame. Does not score that frame."""
        if frame is None or frame.empty or "Label" not in frame.columns:
            print("Dataset is empty")
            return False
        labels = frame["Label"].astype(str)
        if labels.nunique() < 2 or len(frame) < 20:
            print(f"Need at least 20 rows and both labels to fit the stack (got {len(frame)}).")
            return False
        raw, y = self._encode_frame(frame)
        self.scaler = StandardScaler()
        scaled = self.scaler.fit_transform(raw)
        fake = self.fake_label_
        smallest = int(np.bincount(y).min()) if len(y) else 0
        n_splits = max(2, min(5, smallest))
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=self.random_state)

        rf_oof = cross_val_predict(
            RandomForestClassifier(n_estimators=self.n_estimators, max_depth=10, random_state=self.random_state, n_jobs=1),
            scaled, y, cv=cv, method="predict_proba",
        )
        fold_train = len(scaled) - max(1, len(scaled) // n_splits)
        knn_neighbors = max(1, min(self.n_neighbors, fold_train))
        knn_oof_model = KNeighborsClassifier(n_neighbors=knn_neighbors)
        knn_oof = cross_val_predict(knn_oof_model, scaled, y, cv=cv, method="predict_proba")
        rf_fake = probability_column(self._prototype_classes(y), rf_oof, fake)
        knn_fake = probability_column(self._prototype_classes(y), knn_oof, fake)

        iso_oof = np.zeros(len(scaled), dtype=float)
        for train_idx, test_idx in cv.split(scaled, y):
            legit_idx = train_idx[y[train_idx] != fake]
            if len(legit_idx) < 2:
                continue
            fold_iso = self._new_isolation()
            fold_iso.fit(scaled[legit_idx])
            iso_oof[test_idx] = -fold_iso.decision_function(scaled[test_idx])

        from ensemble_contract import meta_feature_matrix

        meta_raw = meta_feature_matrix(rf_fake, knn_fake, iso_oof)
        self.meta_scaler = StandardScaler()
        meta_scaled = self.meta_scaler.fit_transform(meta_raw)
        self.meta_model = LogisticRegression(random_state=self.random_state, max_iter=1000)
        self.meta_model.fit(meta_scaled, y)

        self.rf_model = RandomForestClassifier(
            n_estimators=self.n_estimators, max_depth=10, random_state=self.random_state, n_jobs=1
        )
        self.rf_model.fit(scaled, y)
        self.knn_model = KNeighborsClassifier(n_neighbors=max(1, min(self.n_neighbors, len(scaled) - 1)))
        self.knn_model.fit(scaled, y)
        legit = y != fake
        self.iso_model = self._new_isolation()
        self.iso_model.fit(scaled[legit])

        self.training_matrix_ = scaled
        self.training_labels_ = y
        legit_raw = raw[legit]
        self.explanation_baseline_ = np.median(legit_raw, axis=0) if len(legit_raw) else np.median(raw, axis=0)
        self.permutation_importance_ = None
        if compute_importance:
            def _score(matrix):
                return score_features(
                    self.rf_model, self.knn_model, self.iso_model, self.meta_model,
                    self.scaler, self.meta_scaler, fake, matrix,
                )["meta_fake"]

            self.permutation_importance_ = permutation_importance(
                _score, raw, (y == fake).astype(int), BASE_FEATURES, n_repeats=5, seed=self.random_state
            )
        self.is_trained = True
        print(f"Ensemble fit on {len(raw)} rows ({int(legit.sum())} legit used for Isolation Forest). No detection score was computed.")
        return True

    @staticmethod
    def _prototype_classes(y: np.ndarray):
        """Stand-in so OOF probability columns follow sorted class labels."""
        class _Classes:
            classes_ = np.array(sorted(np.unique(y)))
        return _Classes()

    def train(self, dataset_file: str = "training_dataset.csv") -> bool:
        from dataset_prep import load_clean_dataset, quality_gate, training_rows

        frame, self.data_audit_ = load_clean_dataset(dataset_file)
        allowed, self.metrics_reason_ = quality_gate(frame)
        self.metrics_withheld_ = not allowed
        usable = training_rows(frame) if "synthetic_placeholder" in frame.columns else frame
        return self.train_frame(usable)

    def _positive_label(self) -> int:
        if self.fake_label_ is not None:
            return int(self.fake_label_)
        return int(self.le_label.transform(["Fake"])[0])

    def predict_frame(self, frame: pd.DataFrame) -> np.ndarray:
        raw, _ = self._encode_frame(frame.assign(Label=frame["Label"] if "Label" in frame.columns else "Legit"))
        # _encode_frame transforms labels when le_label is already fit. A frame
        # without Label is given a dummy that must already be a known class.
        scored = score_features(
            self.rf_model, self.knn_model, self.iso_model, self.meta_model,
            self.scaler, self.meta_scaler, self._positive_label(), raw,
        )
        return scored["meta_fake"]

    def predict(self, features_dict):
        if not self.is_trained or self.rf_model is None or self.knn_model is None or self.meta_scaler is None:
            return None
        try:
            security = features_dict.get("Security", "OPEN")
            raw = np.array([[
                float(features_dict.get("RSSI", -50)),
                float(features_dict.get("Channel", 2412)),
                float(self._security_code(security)),
                float(features_dict.get("AP_Count", 1)),
                float(features_dict.get("Signal_Var", 0)),
            ]], dtype=float)
            scored = score_features(
                self.rf_model, self.knn_model, self.iso_model, self.meta_model,
                self.scaler, self.meta_scaler, self._positive_label(), raw,
            )
            meta_fake = float(scored["meta_fake"][0])
            rf_fake = float(scored["rf_fake"][0])
            knn_fake = float(scored["knn_fake"][0])
            iso_score = float(scored["isolation_anomaly"][0])
            meta_pred = "Fake" if meta_fake >= 0.5 else "Legit"
            meta_conf = max(meta_fake, 1.0 - meta_fake) * 100.0
            if meta_pred == "Fake":
                risk = int(20 + meta_fake * 10)
            else:
                risk = int((1.0 - meta_conf / 100.0) * 10)
            iso_pred = self.iso_model.predict(self.scaler.transform(raw))[0] if self.iso_model is not None else 1
            explanation = None
            contributions = {}
            if self.explanation_baseline_ is not None:
                def _score(matrix):
                    return score_features(
                        self.rf_model, self.knn_model, self.iso_model, self.meta_model,
                        self.scaler, self.meta_scaler, self._positive_label(), matrix,
                    )["meta_fake"]

                effects = local_occlusion(_score, raw.reshape(-1), self.explanation_baseline_, BASE_FEATURES)
                explanation = explanation_payload(effects)
                total = sum(abs(item["delta"]) for item in effects)
                if total > 0:
                    contributions = {item["feature"]: round(abs(item["delta"]) / total * 100.0, 2) for item in effects}
            return {
                "rf_prediction": "Fake" if rf_fake >= 0.5 else "Legit",
                "knn_prediction": "Fake" if knn_fake >= 0.5 else "Legit",
                "iso_score": round(iso_score, 3),
                "iso_prediction": "Anomaly" if iso_pred == -1 else "Normal",
                "meta_prediction": meta_pred,
                "meta_confidence": round(meta_conf, 1),
                "ensemble_risk": min(100, risk),
                "feature_contributions": contributions,
                "explanation": explanation,
            }
        except Exception as exc:
            print(f"Prediction error: {exc}")
            return None

    def save_models(self, directory: str = ".") -> None:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        artifacts = {
            "rf_model.pkl": self.rf_model,
            "knn_model.pkl": self.knn_model,
            "iso_model.pkl": self.iso_model,
            "meta_model.pkl": self.meta_model,
            "le_security.pkl": self.le_security,
            "le_label.pkl": self.le_label,
            "scaler.pkl": self.scaler,
            "meta_scaler.pkl": self.meta_scaler,
            "explanation_baseline.pkl": self.explanation_baseline_,
        }
        for name, model in artifacts.items():
            if model is None:
                continue
            with (root / name).open("wb") as handle:
                pickle.dump(model, handle)
            print(f"Saved {name}")
        if self.permutation_importance_:
            payload = {
                "method": "permutation_importance",
                "score": "roc_auc_decrease",
                "rows": "cleaned_training_rows",
                "is_detection_accuracy": False,
                "note": "Permutation importance on the cleaned training rows shows which inputs the saved model uses. It is not a detection rate.",
                "features": self.permutation_importance_,
            }
            (root / "permutation_importance.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print("Saved permutation_importance.json")

    def load_models(self, directory: str = ".") -> bool:
        root = Path(directory)
        required = ["rf_model.pkl", "knn_model.pkl", "le_security.pkl", "le_label.pkl", "scaler.pkl", "meta_scaler.pkl"]
        optional = ["iso_model.pkl", "meta_model.pkl", "explanation_baseline.pkl"]
        loaded = {}
        for name in required + optional:
            path = root / name
            if not path.is_file():
                if name in required:
                    print(f"Missing {name}")
                    return False
                continue
            with path.open("rb") as handle:
                loaded[name] = pickle.load(handle)
        self.rf_model = loaded["rf_model.pkl"]
        self.knn_model = loaded["knn_model.pkl"]
        self.le_security = loaded["le_security.pkl"]
        self.le_label = loaded["le_label.pkl"]
        self.scaler = loaded["scaler.pkl"]
        self.meta_scaler = loaded["meta_scaler.pkl"]
        self.iso_model = loaded.get("iso_model.pkl")
        self.meta_model = loaded.get("meta_model.pkl")
        self.explanation_baseline_ = loaded.get("explanation_baseline.pkl")
        self.fake_label_ = int(self.le_label.transform(["Fake"])[0]) if "Fake" in list(self.le_label.classes_) else None
        self.is_trained = self.meta_model is not None and self.iso_model is not None
        return self.is_trained


if __name__ == "__main__":
    ensemble = HybridEnsembleDetector()
    if ensemble.train("training_dataset.csv"):
        ensemble.save_models()
        sample = ensemble.predict({
            "RSSI": -35,
            "Channel": 2412,
            "Security": "OPEN",
            "AP_Count": 2,
            "Signal_Var": 8,
        })
        print(sample)
        print("Sample output is one prediction, not a detection score.")
    else:
        raise SystemExit(1)
