"""
ml_ensemble.py
======================
Hybrid stacked ensemble for advanced WiFi threat detection.

Detection Stack:
  - Random Forest (non-linear feature interactions)
  - KNN Classifier (local similarity matching)
  - Isolation Forest (unsupervised anomaly detection)
  - Logistic Regression Meta-Classifier (stacked ensemble voting)

This uses out-of-fold (OOF) predictions to avoid data leakage.
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler

class HybridEnsembleDetector:
    """Advanced ML ensemble for WiFi threat detection"""
    
    def __init__(self):
        self.rf_model = None
        self.knn_model = None
        self.iso_model = None
        self.meta_model = None
        self.le_security = None
        self.le_label = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def train(self, dataset_file="wifi_dataset.csv"):
        """Train the hybrid ensemble on labeled WiFi data"""
        
        if not os.path.exists(dataset_file):
            print(f"❌ Dataset file not found: {dataset_file}")
            return False
        
        # Load dataset
        data = pd.read_csv(dataset_file, on_bad_lines="skip")
        
        if data.empty:
            print("❌ Dataset is empty")
            return False
        
        print(f"📊 Training on {len(data)} samples...")
        
        # ============ FEATURE ENGINEERING ============
        # Encode categorical variables
        self.le_security = LabelEncoder()
        self.le_label = LabelEncoder()
        
        if "Security" in data.columns:
            data["Security_enc"] = self.le_security.fit_transform(
                data["Security"].fillna("Open")
            )
        else:
            data["Security_enc"] = 0
        
        if "Label" not in data.columns:
            print("❌ 'Label' column required (Fake/Legit)")
            return False
        
        data["Label_enc"] = self.le_label.fit_transform(data["Label"])
        
        # Select features
        feature_cols = ["RSSI", "Channel", "Security_enc", "AP_Count", "Signal_Var"]
        missing_cols = [col for col in feature_cols if col not in data.columns]
        
        if missing_cols:
            print(f"⚠️  Missing columns: {missing_cols}")
            feature_cols = [col for col in feature_cols if col in data.columns]
        
        X = data[feature_cols].fillna(0)
        y = data["Label_enc"]
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        X_scaled_df = pd.DataFrame(X_scaled, columns=feature_cols)
        
        # ============ BASE LAYER MODELS ============
        print("\n🔧 Training base models...")
        
        # 1. Random Forest
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        self.rf_model.fit(X_scaled_df, y)
        print("✅ Random Forest trained")
        
        # 2. KNN Classifier
        self.knn_model = KNeighborsClassifier(n_neighbors=5)
        self.knn_model.fit(X_scaled_df, y)
        print("✅ KNN Classifier trained")
        
        # 3. Isolation Forest (anomaly detection on "Legit" only)
        legit_data = X_scaled_df[y == self.le_label.transform(["Legit"])[0]]
        self.iso_model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        self.iso_model.fit(legit_data)
        print("✅ Isolation Forest trained")
        
        # ============ META LAYER - Out-of-Fold (OOF) ============
        print("\n🎯 Generating OOF predictions for meta-model...")
        
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        
        # Get OOF predictions from base models
        rf_oof = cross_val_predict(
            RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1),
            X_scaled_df, y, cv=skf, method="predict_proba"
        )
        
        knn_oof = cross_val_predict(
            KNeighborsClassifier(n_neighbors=5),
            X_scaled_df, y, cv=skf, method="predict_proba"
        )
        
        iso_oof = np.zeros((len(X_scaled_df), 2))
        for idx, (train_idx, val_idx) in enumerate(skf.split(X_scaled_df, y)):
            iso_train = self.iso_model.fit(X_scaled_df.iloc[train_idx])
            iso_scores = iso_train.decision_function(X_scaled_df.iloc[val_idx])
            iso_oof[val_idx, 0] = np.maximum(0, -iso_scores)  # Anomaly score
            iso_oof[val_idx, 1] = np.maximum(0, iso_scores)   # Normal score
        
        iso_oof = iso_oof / (iso_oof.sum(axis=1, keepdims=True) + 1e-6)
        
        # Meta-features: take probabilities of "Fake" class (typically index 1)
        meta_features = np.hstack([
            rf_oof[:, 1].reshape(-1, 1),   # RF fake probability
            knn_oof[:, 1].reshape(-1, 1),  # KNN fake probability
            iso_oof[:, 0].reshape(-1, 1)   # Isolation anomaly score
        ])
        
        # 4. Logistic Regression Meta-Classifier
        self.meta_model = LogisticRegression(random_state=42, max_iter=1000)
        self.meta_model.fit(meta_features, y)
        print("✅ Logistic Regression meta-classifier trained")
        
        # ============ EVALUATION ============
        print("\n📊 Model Evaluation:")
        
        # Base model accuracies
        rf_acc = self.rf_model.score(X_scaled_df, y)
        knn_acc = self.knn_model.score(X_scaled_df, y)
        meta_acc = self.meta_model.score(meta_features, y)
        
        print(f"  Random Forest Accuracy: {rf_acc:.3f}")
        print(f"  KNN Accuracy: {knn_acc:.3f}")
        print(f"  Meta-Model Accuracy: {meta_acc:.3f}")
        
        # ROC-AUC
        try:
            meta_roc = roc_auc_score(y, self.meta_model.predict_proba(meta_features)[:, 1])
            print(f"  Meta-Model ROC-AUC: {meta_roc:.3f}")
        except:
            pass
        
        self.is_trained = True
        return True
    
    def predict(self, features_dict):
        """
        Predict threat level for a WiFi network
        
        Args:
            features_dict: {
                'RSSI': int,
                'Channel': int,
                'Security': str,
                'AP_Count': int,
                'Signal_Var': float
            }
        
        Returns:
            {
                'rf_prediction': str,
                'knn_prediction': str,
                'iso_score': float,
                'meta_prediction': str,
                'meta_confidence': float,
                'ensemble_risk': int (0-100)
            }
        """
        
        if not self.is_trained or not self.rf_model or not self.knn_model:
            return None
        
        try:
            # Prepare features
            security = features_dict.get('Security', 'Open')
            if security not in self.le_security.classes_:
                security = 'Open'
            
            sec_encoded = self.le_security.transform([security])[0]
            
            X = np.array([[
                features_dict.get('RSSI', -50),
                features_dict.get('Channel', 1),
                sec_encoded,
                features_dict.get('AP_Count', 1),
                features_dict.get('Signal_Var', 0)
            ]])
            
            # Only transform with a fitted scaler.  A fresh StandardScaler has
            # no learned statistics and previously caused every prediction/XAI
            # explanation to fail silently.
            if self.scaler is not None and hasattr(self.scaler, "mean_"):
                X_scaled = self.scaler.transform(X)
            else:
                X_scaled = X
            
            # Base model predictions
            rf_proba = self.rf_model.predict_proba(X_scaled)[0]
            knn_proba = self.knn_model.predict_proba(X_scaled)[0]
            rf_pred = self.le_label.inverse_transform([self.rf_model.predict(X_scaled)[0]])[0]
            knn_pred = self.le_label.inverse_transform([self.knn_model.predict(X_scaled)[0]])[0]
            
            iso_result = "N/A"
            iso_score = 0.5
            
            # Isolation Forest (if available)
            if self.iso_model:
                try:
                    iso_score = -self.iso_model.decision_function(X_scaled)[0]
                    iso_pred = self.iso_model.predict(X_scaled)[0]
                    iso_result = "Anomaly" if iso_pred == -1 else "Normal"
                except:
                    iso_score = 0.5
                    iso_result = "N/A"
            
            meta_result = "N/A"
            meta_conf = 0
            ml_risk_addition = 0
            
            # Meta-model (if available)
            if self.meta_model:
                try:
                    meta_features = np.array([[
                        rf_proba[1] if len(rf_proba) > 1 else 0.5,
                        knn_proba[1] if len(knn_proba) > 1 else 0.5,
                        iso_score
                    ]])
                    
                    meta_pred_proba = self.meta_model.predict_proba(meta_features)[0]
                    meta_pred = self.le_label.inverse_transform([self.meta_model.predict(meta_features)[0]])[0]
                    meta_conf = max(meta_pred_proba) * 100
                    
                    # Calculate ML risk from meta confidence
                    if meta_pred == "Fake":
                        ml_risk_addition = int(20 + (meta_conf / 100) * 10)  # 20-30 pts
                    else:
                        ml_risk_addition = int((1 - meta_conf / 100) * 10)  # 0-10 pts
                
                except Exception as e:
                    print(f"Meta-model error: {e}")
                    meta_result = "Error"
                    meta_conf = 0
            else:
                # No meta-model, use simple voting
                fake_votes = sum([1 for p in [rf_pred, knn_pred] if p == "Fake"])
                if fake_votes >= 2:
                    meta_result = "Fake"
                    meta_conf = 100
                    ml_risk_addition = 25
                else:
                    meta_result = "Legit"
                    meta_conf = 50
                    ml_risk_addition = 0
            
            # Prediction-specific feature contribution.  We combine the RF's
            # learned feature importance with this network's normalized model
            # input; raw channel frequency is never plotted directly.
            feature_names = ["RSSI", "Channel", "Security_enc", "AP_Count", "Signal_Var"]
            learned = np.asarray(getattr(self.rf_model, "feature_importances_", np.ones(len(feature_names))), dtype=float)
            # Use unitless feature magnitudes for explanation display.  Wi-Fi
            # frequencies are measured in Hz while RSSI is in dBm; multiplying
            # raw values made Channel appear in the millions and invalidated
            # the chart.  The prediction itself still receives its trained
            # input vector above.
            display_scales = np.array([100.0, 6_000_000.0, max(1, len(self.le_security.classes_) - 1), 20.0, 100.0])
            magnitude = np.clip(np.abs(np.asarray(X, dtype=float).reshape(-1)) / display_scales, 0.0, 1.0)
            raw_contributions = np.nan_to_num(learned * magnitude, nan=0.0, posinf=0.0, neginf=0.0)
            if raw_contributions.sum() <= 0:
                raw_contributions = np.nan_to_num(learned, nan=0.0, posinf=0.0, neginf=0.0)
            total = raw_contributions.sum()
            contributions = {
                name: round(float(value / total * 100), 2)
                for name, value in zip(feature_names, raw_contributions)
            } if total > 0 else {}

            return {
                'rf_prediction': rf_pred,
                'knn_prediction': knn_pred,
                'iso_score': round(iso_score, 3),
                'iso_prediction': iso_result,
                'meta_prediction': meta_result,
                'meta_confidence': round(meta_conf, 1),
                'ensemble_risk': min(100, ml_risk_addition),
                'feature_contributions': contributions,
            }
        
        except Exception as e:
            print(f"❌ Prediction error: {e}")
            return None
    
    def save_models(self):
        """Save all models to pickle files"""
        
        models = {
            'rf_model': self.rf_model,
            'knn_model': self.knn_model,
            'iso_model': self.iso_model,
            'meta_model': self.meta_model,
            'le_security': self.le_security,
            'le_label': self.le_label,
            'scaler': self.scaler
        }
        
        for name, model in models.items():
            if model:
                with open(f"{name}.pkl", "wb") as f:
                    pickle.dump(model, f)
                print(f"✅ Saved {name}.pkl")
    
    def load_models(self):
        """Load all models from pickle files (graceful fallback)"""
        
        # Core models (required)
        core_models = ['rf_model', 'knn_model', 'le_security', 'le_label']
        # Optional advanced models
        advanced_models = ['iso_model', 'meta_model', 'scaler']
        
        # Load core models
        for name in core_models:
            try:
                with open(f"{name}.pkl", "rb") as f:
                    setattr(self, name, pickle.load(f))
                print(f"✅ Loaded {name}.pkl")
            except FileNotFoundError:
                print(f"❌ Missing {name}.pkl (required)")
                return False
        
        # Load optional advanced models
        advanced_available = True
        for name in advanced_models:
            try:
                with open(f"{name}.pkl", "rb") as f:
                    setattr(self, name, pickle.load(f))
                print(f"✅ Loaded {name}.pkl")
            except FileNotFoundError:
                print(f"⚠️  {name}.pkl not found (optional)")
                advanced_available = False
        
        # If scaler not loaded, create a new one
        if not self.scaler:
            self.scaler = StandardScaler()
            print("⚠️  Created new scaler")
        
        self.is_trained = True
        return True


if __name__ == "__main__":
    # Example usage
    ensemble = HybridEnsembleDetector()
    
    print("🚀 Training Hybrid Ensemble...")
    if ensemble.train("wifi_dataset.csv"):
        ensemble.save_models()
        
        # Test prediction
        test_network = {
            'RSSI': -35,
            'Channel': 6,
            'Security': 'WPA2',
            'AP_Count': 3,
            'Signal_Var': 8
        }
        
        result = ensemble.predict(test_network)
        if result:
            print(f"\n🎯 Test Prediction:\n{result}")
    else:
        print("❌ Training failed")
