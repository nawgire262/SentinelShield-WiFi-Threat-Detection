"""
train_model.py
================
Trains a HYBRID STACKED ENSEMBLE for rogue / evil-twin Wi-Fi detection:

    Base layer (learn different things about each network):
        1. Random Forest      -> supervised, non-linear feature interactions
        2. K-Nearest Neighbors -> supervised, local similarity to known networks
        3. Isolation Forest    -> UNSUPERVISED anomaly detector, trained only on
                                  networks labeled "Legit". It learns what normal
                                  Wi-Fi behavior looks like, so it can flag rogue
                                  patterns even if they don't resemble any
                                  previously-labeled "Fake" example.

    Meta layer:
        A Logistic Regression "referee" model that learns how to weigh and
        combine the three base signals into one final Fake/Legit call plus a
        confidence score. This mirrors the hybrid stacking approach used in
        recent Wi-Fi IDS literature (e.g. hybrid base-model + meta-classifier
        pipelines evaluated on AWID3 in 2025 studies).

Why out-of-fold (OOF) predictions?
    If we trained the meta-model on predictions the base models made on data
    they were ALSO trained on, the meta-model would over-trust them (data
    leakage). Instead we use cross-validation to generate honest "out of
    sample" base-model outputs for every row, train the meta-model on those,
    and only then refit the base models on the FULL dataset for deployment.

Outputs (all saved next to this script):
    rf_model.pkl     - Random Forest, fit on all labeled data
    knn_model.pkl    - KNN, fit on all labeled data
    iso_model.pkl    - Isolation Forest, fit on all "Legit" rows only
    meta_model.pkl   - Logistic Regression stacker
    le_security.pkl  - LabelEncoder for the Security column
    le_label.pkl     - LabelEncoder for the Label column (Fake/Legit)
"""

import os
import pickle
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder

# Windows terminals may default to cp1252; retain readable training output.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ================= CONFIG =================
DATASET_FILE = "wifi_dataset.csv"  # relative path (was hardcoded D:\ before)
FEATURES = ["RSSI", "Channel", "Security_enc", "AP_Count", "Signal_Var"]
MIN_ROWS = 20  # below this, cross-validated stacking isn't meaningful

# ================= LOAD DATA =================
if not os.path.exists(DATASET_FILE):
    print(f"❌ Dataset not found: {DATASET_FILE}")
    raise SystemExit(1)

# on_bad_lines="skip" also protects against the known corrupted row in this
# dataset where two CSV rows got concatenated without a newline (shows up as
# a bogus "FakeFTTH" label) — pandas drops any row with the wrong column count.
data = pd.read_csv(DATASET_FILE, on_bad_lines="skip")
raw_rows = len(data)

# Keep only cleanly labeled rows
data = data.dropna(subset=["Label"])
data = data[data["Label"].isin(["Legit", "Fake"])].reset_index(drop=True)

dropped = raw_rows - len(data)
if dropped:
    print(f"ℹ️ Skipped {dropped} malformed/unlabeled row(s) while loading dataset.")

if len(data) < MIN_ROWS:
    print(f"⚠️ Only {len(data)} clean labeled rows found (need >= {MIN_ROWS}). "
          f"Not enough data to train a reliable hybrid model!")
    raise SystemExit(1)

label_counts = data["Label"].value_counts()
print(f"📊 Dataset: {len(data)} rows -> {label_counts.to_dict()}")

# ================= ENCODE =================
le_security = LabelEncoder()
le_label = LabelEncoder()

data["Security_enc"] = le_security.fit_transform(data["Security"])
data["Label_enc"] = le_label.fit_transform(data["Label"])

X = data[FEATURES].reset_index(drop=True)
y = data["Label_enc"].reset_index(drop=True)

fake_idx = list(le_label.classes_).index("Fake")
print(f"ℹ️ Label encoding -> {dict(zip(le_label.classes_, range(len(le_label.classes_))))}")

# Number of CV folds can't exceed the size of the smallest class
n_splits = min(5, y.value_counts().min())
n_splits = max(n_splits, 2)
cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
print(f"ℹ️ Using {n_splits}-fold stratified CV to build honest (out-of-fold) meta-features")

# ================= BASE MODEL 1: RANDOM FOREST (supervised) =================
rf_model = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
rf_oof_proba = cross_val_predict(rf_model, X, y, cv=cv, method="predict_proba")[:, fake_idx]

# ================= BASE MODEL 2: KNN (supervised) =================
knn_model = KNeighborsClassifier(n_neighbors=5)
knn_oof_proba = cross_val_predict(knn_model, X, y, cv=cv, method="predict_proba")[:, fake_idx]

# ================= BASE MODEL 3: ISOLATION FOREST (unsupervised anomaly score) =================
# Fit fold-by-fold on ONLY the legit rows of the training split, then score the
# held-out fold (legit + fake) to get an honest, non-leaky anomaly score for
# every row. Higher score = more anomalous / less like a normal known network.
iso_oof_scores = np.zeros(len(X))

for train_idx, test_idx in cv.split(X, y):
    y_train_fold = y.iloc[train_idx]
    legit_train_idx = train_idx[y_train_fold.values != fake_idx]

    fold_iso = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    fold_iso.fit(X.iloc[legit_train_idx])

    # decision_function: lower = more anomalous, so flip the sign
    iso_oof_scores[test_idx] = -fold_iso.decision_function(X.iloc[test_idx])

# ================= META MODEL: LOGISTIC REGRESSION STACKER =================
meta_X = np.column_stack([rf_oof_proba, knn_oof_proba, iso_oof_scores])
meta_model = LogisticRegression()
meta_model.fit(meta_X, y)

meta_pred = meta_model.predict(meta_X)
rf_oof_pred = np.where(rf_oof_proba > 0.5, fake_idx, 1 - fake_idx)
knn_oof_pred = np.where(knn_oof_proba > 0.5, fake_idx, 1 - fake_idx)

print("\n📊 Cross-validated (out-of-fold) hybrid stack performance estimate:")
print(f"   Random Forest alone : {accuracy_score(y, rf_oof_pred):.4f}")
print(f"   KNN alone           : {accuracy_score(y, knn_oof_pred):.4f}")
print(f"   Hybrid stack (meta) : {accuracy_score(y, meta_pred):.4f}")
print("\n📊 Hybrid stack classification report:")
print(classification_report(y, meta_pred, target_names=le_label.classes_))

# ================= REFIT BASE MODELS ON FULL DATA FOR DEPLOYMENT =================
rf_model.fit(X, y)
knn_model.fit(X, y)

legit_mask = (y != fake_idx)
iso_model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
iso_model.fit(X[legit_mask])

# ================= SAVE ARTIFACTS =================
artifacts = {
    "rf_model.pkl": rf_model,
    "knn_model.pkl": knn_model,
    "iso_model.pkl": iso_model,
    "meta_model.pkl": meta_model,
    "le_security.pkl": le_security,
    "le_label.pkl": le_label,
}

for filename, obj in artifacts.items():
    with open(filename, "wb") as f:
        pickle.dump(obj, f)

print("\n✅ Hybrid stacked model saved: rf_model.pkl, knn_model.pkl, iso_model.pkl, "
      "meta_model.pkl, le_security.pkl, le_label.pkl")
