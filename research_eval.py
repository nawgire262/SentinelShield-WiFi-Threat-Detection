"""research_eval.py  (Member 1)
================================
Paper-grade evaluation for the SentinelShield hybrid detector.

Why this exists (what evaluation.py does not do)
  1. Splits by SESSION, not by random row. AP_Count and Signal_Var are SSID-level
     aggregates, so rows from the same scan session are near-duplicates. A random
     row split puts them on both sides and inflates every metric.
  2. Ablation: RF, KNN, IF, RF+KNN (no IF) and the full stacked hybrid are scored on
     identical folds.
  3. Zero-day test: leave one ATTACK TYPE out of training, then test on it.
  4. Repeats over several seeds and reports mean +/- std.
  5. False-positive rate by environment (crowded vs quiet).
  6. Permutation importance on HELD-OUT rows (the repo's version uses training rows).

Required CSV columns (extra columns are kept by dataset_prep.prepare_dataset)
  SSID,BSSID,RSSI,Channel,Security,AP_Count,Signal_Var,Label      <- existing
  session_id      one id per capture session (REQUIRED for a valid split)
  label_source    field_verified for rows you captured yourself
  attack_type     Fake rows only, e.g. open_clone / wpa2_clone / other_channel
  environment     crowded or quiet (optional, enables the FPR-by-environment table)

Usage
  python research_eval.py training_dataset.csv --out results
  python research_eval.py --self-test          # harness check on SIMULATED data

The real-data path refuses to print scores until the repo's own quality gate AND
the session gate below pass. The self-test output is NOT a research result.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, StratifiedGroupKFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler

from dataset_prep import load_clean_dataset, quality_gate
from ensemble_contract import score_features
from ml_ensemble import HybridEnsembleDetector
from xai_explain import BASE_FEATURES, permutation_importance

SECURITY_CODE = {"OPEN": 0, "WEP": 1, "WPA2": 2, "WPA3": 3}
MODELS = ["RF", "KNN", "IsolationForest", "RF+KNN (no IF)", "Hybrid stacked"]
MIN_LEGIT_SESSIONS = 5
MIN_FAKE_SESSIONS = 3


# ----------------------------------------------------------------- helpers
def feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Same column order as ensemble_contract.FEATURES."""
    security = df["Security"].map(lambda s: SECURITY_CODE.get(str(s).upper(), 2))
    return np.column_stack([df["RSSI"], df["Channel"], security, df["AP_Count"], df["Signal_Var"]]).astype(float)


def labels01(df: pd.DataFrame) -> np.ndarray:
    return (df["Label"].astype(str) == "Fake").to_numpy(dtype=int)


def group_column(frame: pd.DataFrame) -> tuple[str, bool]:
    """Return (column, is_session). Falls back to SSID, which is a weaker split."""
    if "session_id" in frame.columns and frame["session_id"].notna().all():
        return "session_id", True
    return "SSID", False


def session_gate(frame: pd.DataFrame, group: str, is_session: bool) -> tuple[bool, str]:
    reasons = []
    if not is_session:
        reasons.append("no complete session_id column; add one id per capture session.")
    real = frame.loc[~frame["synthetic_placeholder"].astype(bool)] if "synthetic_placeholder" in frame.columns else frame
    legit_n = real.loc[real["Label"] == "Legit", group].nunique()
    fake_n = real.loc[real["Label"] == "Fake", group].nunique()
    if legit_n < MIN_LEGIT_SESSIONS:
        reasons.append(f"only {legit_n} Legit sessions (need {MIN_LEGIT_SESSIONS}).")
    if fake_n < MIN_FAKE_SESSIONS:
        reasons.append(f"only {fake_n} Fake sessions (need {MIN_FAKE_SESSIONS}).")
    return (not reasons), " ".join(reasons)


def metrics(y: np.ndarray, score: np.ndarray, pred: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) and not np.isnan(recall) else 0.0
    out = {
        "precision": precision, "recall": recall, "f1": f1,
        "fpr": fp / (fp + tn) if (fp + tn) else float("nan"),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "roc_auc": float("nan"), "pr_auc": float("nan"),
    }
    if len(np.unique(y)) == 2:
        out["roc_auc"] = float(roc_auc_score(y, score))
        out["pr_auc"] = float(average_precision_score(y, score))
    return out


# ----------------------------------------------------------------- models
class Bundle:
    """All five detectors fit on one training frame, scored on another."""

    def __init__(self, seed: int):
        self.seed = seed

    def fit(self, train: pd.DataFrame, groups: np.ndarray) -> "Bundle":
        X, y = feature_matrix(train), labels01(train)
        self.scaler = StandardScaler().fit(X)
        Xs = self.scaler.transform(X)
        self.rf = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=self.seed, n_jobs=1).fit(Xs, y)
        self.knn = KNeighborsClassifier(n_neighbors=max(1, min(5, len(Xs) - 1))).fit(Xs, y)
        legit = Xs[y == 0]
        self.iso = IsolationForest(n_estimators=200, random_state=self.seed, n_jobs=1).fit(legit)
        self.iso_thr = self._iso_threshold(Xs, y, groups)
        with contextlib.redirect_stdout(io.StringIO()):
            det = HybridEnsembleDetector(n_estimators=200, random_state=self.seed)
            self.hybrid = det if det.train_frame(train.reset_index(drop=True), compute_importance=False) else None
        return self

    def _iso_threshold(self, Xs, y, groups, quantile: float = 0.95) -> float:
        """Alarm threshold from out-of-fold Legit scores of the TRAIN split only.

        In-sample scores are too low, which would make the threshold too tight and
        the held-out false-positive rate higher than intended.
        """
        legit_idx = np.where(y == 0)[0]
        g = groups[legit_idx]
        n_splits = min(5, len(np.unique(g)))
        if n_splits >= 2:
            scores = []
            for tr, te in GroupKFold(n_splits=n_splits).split(legit_idx, groups=g):
                m = IsolationForest(n_estimators=100, random_state=self.seed, n_jobs=1).fit(Xs[legit_idx[tr]])
                scores.append(-m.decision_function(Xs[legit_idx[te]]))
            return float(np.quantile(np.concatenate(scores), quantile))
        return float(np.quantile(-self.iso.decision_function(Xs[legit_idx]), quantile))

    def score(self, test: pd.DataFrame) -> dict[str, tuple[np.ndarray, np.ndarray]]:
        Xs = self.scaler.transform(feature_matrix(test))
        rf_p = self.rf.predict_proba(Xs)[:, list(self.rf.classes_).index(1)]
        knn_p = self.knn.predict_proba(Xs)[:, list(self.knn.classes_).index(1)]
        iso_s = -self.iso.decision_function(Xs)
        avg = (rf_p + knn_p) / 2
        out = {
            "RF": (rf_p, (rf_p >= 0.5).astype(int)),
            "KNN": (knn_p, (knn_p >= 0.5).astype(int)),
            "IsolationForest": (iso_s, (iso_s > self.iso_thr).astype(int)),
            "RF+KNN (no IF)": (avg, (avg >= 0.5).astype(int)),
        }
        if self.hybrid is not None:
            hp = np.asarray(self.hybrid.predict_frame(test.reset_index(drop=True)), dtype=float)
            out["Hybrid stacked"] = (hp, (hp >= 0.5).astype(int))
        return out


# ----------------------------------------------------------------- experiments
def grouped_cv(frame: pd.DataFrame, group: str, seeds: list[int], n_splits: int):
    folds, pooled, skipped = [], [], 0
    y_all = labels01(frame)
    groups = frame[group].astype(str).to_numpy()
    for seed in seeds:
        cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
        for k, (tr, te) in enumerate(cv.split(frame, y_all, groups)):
            if len(np.unique(y_all[tr])) < 2 or len(np.unique(y_all[te])) < 2:
                skipped += 1
                continue
            bundle = Bundle(seed).fit(frame.iloc[tr], groups[tr])
            test = frame.iloc[te]
            for name, (score, pred) in bundle.score(test).items():
                folds.append({"model": name, "seed": seed, "fold": k, **metrics(y_all[te], score, pred)})
                if "environment" in frame.columns:
                    pooled.append(pd.DataFrame({
                        "model": name, "seed": seed, "y": y_all[te], "pred": pred,
                        "environment": test["environment"].fillna("unknown").to_numpy(),
                    }))
    return pd.DataFrame(folds), (pd.concat(pooled) if pooled else pd.DataFrame()), skipped


def zero_day(frame: pd.DataFrame, group: str, seeds: list[int], legit_test_frac: float = 0.3) -> pd.DataFrame:
    """Train without attack type A, test on A plus unseen Legit sessions."""
    if "attack_type" not in frame.columns:
        return pd.DataFrame()
    fake = frame[frame["Label"] == "Fake"]
    types = sorted(fake["attack_type"].dropna().astype(str).unique())
    if len(types) < 2:
        return pd.DataFrame()
    legit = frame[frame["Label"] == "Legit"].reset_index(drop=True)
    rows = []
    for seed in seeds:
        splitter = GroupShuffleSplit(n_splits=1, test_size=legit_test_frac, random_state=seed)
        l_tr, l_te = next(splitter.split(legit, groups=legit[group].astype(str)))
        for held in types:
            train = pd.concat([legit.iloc[l_tr], fake[fake["attack_type"].astype(str) != held]], ignore_index=True)
            test = pd.concat([legit.iloc[l_te], fake[fake["attack_type"].astype(str) == held]], ignore_index=True)
            bundle = Bundle(seed).fit(train, train[group].astype(str).to_numpy())
            y = labels01(test)
            for name, (score, pred) in bundle.score(test).items():
                m = metrics(y, score, pred)
                rows.append({"model": name, "held_out_attack": held, "seed": seed,
                             "recall_unseen": m["recall"], "fpr": m["fpr"], "roc_auc": m["roc_auc"]})
    return pd.DataFrame(rows)


def heldout_importance(frame: pd.DataFrame, group: str, seed: int) -> list[dict] | None:
    y = labels01(frame)
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=seed).split(frame, y, frame[group].astype(str)))
    test = frame.iloc[te].reset_index(drop=True)
    if len(np.unique(labels01(test))) < 2:
        return None
    with contextlib.redirect_stdout(io.StringIO()):
        det = HybridEnsembleDetector(n_estimators=200, random_state=seed)
        if not det.train_frame(frame.iloc[tr].reset_index(drop=True), compute_importance=False):
            return None
    raw, _ = det._encode_frame(test)
    fake = det._positive_label()

    def score_fn(matrix):
        return score_features(det.rf_model, det.knn_model, det.iso_model, det.meta_model,
                              det.scaler, det.meta_scaler, fake, matrix)["meta_fake"]

    return permutation_importance(score_fn, raw, labels01(test), BASE_FEATURES, n_repeats=20, seed=seed)


# ----------------------------------------------------------------- reporting
def summarise(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    agg = df.groupby("model")[cols].agg(["mean", "std"])
    agg = agg.reindex([m for m in MODELS if m in agg.index])
    return agg


def to_markdown(summary: pd.DataFrame, cols: list[str], title: str) -> str:
    lines = [f"### {title}", "", "| Model | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
    for model, row in summary.iterrows():
        cells = [f"{row[(c, 'mean')]:.3f} ± {0.0 if np.isnan(row[(c, 'std')]) else row[(c, 'std')]:.3f}" for c in cols]
        lines.append(f"| {model} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def run(frame: pd.DataFrame, out_dir: Path, seeds: list[int], n_splits: int, banner: str = "") -> int:
    group, is_session = group_column(frame)
    out_dir.mkdir(parents=True, exist_ok=True)
    cv_df, pooled, skipped = grouped_cv(frame, group, seeds, n_splits)
    if cv_df.empty:
        print("No valid folds (every fold lacked one class). Collect more sessions of each class.")
        return 2
    cols = ["precision", "recall", "f1", "fpr", "roc_auc", "pr_auc"]
    cv_df.to_csv(out_dir / "cv_per_fold.csv", index=False)
    report = [banner, to_markdown(summarise(cv_df, cols), cols,
                                  f"Grouped {n_splits}-fold CV by {group}, {len(seeds)} seeds (mean ± std over folds×seeds)")]

    if not pooled.empty:
        per = pooled.assign(neg=lambda d: d["y"] == 0, fp=lambda d: (d["y"] == 0) & (d["pred"] == 1))
        env = (per[per["neg"]].groupby(["model", "environment", "seed"])["fp"].mean()
               .groupby(["model", "environment"]).mean().unstack("environment"))
        env = env.reindex([m for m in MODELS if m in env.index])
        env.to_csv(out_dir / "fpr_by_environment.csv")
        report.append("### False-positive rate by environment (Legit rows only)\n\n" + env.round(3).to_markdown() + "\n")

    zd = zero_day(frame, group, seeds)
    if zd.empty:
        report.append("### Zero-day test\n\nSkipped: needs an `attack_type` column with at least 2 Fake types.\n")
    else:
        zd.to_csv(out_dir / "zero_day.csv", index=False)
        table = zd.groupby(["held_out_attack", "model"])["recall_unseen"].mean().unstack("model")
        table = table[[m for m in MODELS if m in table.columns]]
        report.append("### Zero-day: recall on an attack type never seen in training\n\n" + table.round(3).to_markdown() + "\n")

    imp = heldout_importance(frame, group, seeds[0])
    if imp:
        (out_dir / "heldout_permutation_importance.json").write_text(json.dumps(imp, indent=2), encoding="utf-8")
        report.append("### Permutation importance on HELD-OUT rows (ROC-AUC drop)\n\n" + pd.DataFrame(imp)[["label", "importance"]].round(4).to_markdown(index=False) + "\n")

    config = {
        "sklearn": sklearn.__version__, "seeds": seeds, "n_splits": n_splits, "group_column": group,
        "rows": int(len(frame)), "legit": int((frame["Label"] == "Legit").sum()), "fake": int((frame["Label"] == "Fake").sum()),
        "groups": int(frame[group].nunique()), "folds_skipped_single_class": skipped,
    }
    (out_dir / "run_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    text = "\n".join(report)
    (out_dir / "results.md").write_text(text, encoding="utf-8")
    print(text)
    if skipped:
        print(f"Note: {skipped} fold(s) skipped because train or test had a single class.")
    return 0


# ----------------------------------------------------------------- simulated data (harness check only)
def simulated_frame(seed: int = 0) -> pd.DataFrame:
    """SIMULATED rows. Used only to prove the harness runs. Not evidence."""
    rng = np.random.default_rng(seed)
    rows = []
    for s in range(14):
        crowded = s % 2 == 0
        for a in range(6):
            n_ap = int(rng.integers(5, 10) if crowded else rng.integers(1, 3))
            rows.append(dict(
                SSID=f"net{s}_{a}", BSSID=f"10:{s:02X}:{a:02X}:00:00:01", RSSI=float(rng.normal(-68, 7)),
                Channel=float(rng.choice([2412, 2437, 2462, 5180, 5765])), Security="WPA2",
                AP_Count=n_ap, Signal_Var=float(abs(rng.normal(9 if crowded else 4, 2))), Label="Legit",
                session_id=f"L{s}", label_source="field_verified", environment="crowded" if crowded else "quiet",
                attack_type=None, synthetic_placeholder=False))
    kinds = {"open_clone": ("OPEN", -40, 18), "wpa2_clone": ("WPA2", -45, 14), "other_channel": ("WPA2", -50, 20)}
    for s in range(9):
        kind = list(kinds)[s % 3]
        sec, rssi, var = kinds[kind]
        for a in range(4):
            rows.append(dict(
                SSID=f"fake{s}_{a}", BSSID=f"DA:{s:02X}:{a:02X}:00:00:01", RSSI=float(rng.normal(rssi, 4)),
                Channel=float(rng.choice([2412, 2437, 2462])), Security=sec, AP_Count=int(rng.integers(1, 4)),
                Signal_Var=float(abs(rng.normal(var, 3))), Label="Fake", session_id=f"F{s}",
                label_source="field_verified", environment="quiet", attack_type=kind, synthetic_placeholder=False))
    return pd.DataFrame(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dataset", nargs="?", default="training_dataset.csv")
    ap.add_argument("--out", default="results")
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    ap.add_argument("--splits", type=int, default=5)
    ap.add_argument("--include-synthetic", action="store_true",
                    help="keep hand-typed placeholder rows (honesty comparison only)")
    ap.add_argument("--self-test", action="store_true", help="run on SIMULATED data to check the harness")
    args = ap.parse_args(argv)

    if args.self_test:
        banner = "**SIMULATED DATA. This checks that the code runs. It is NOT a research result.**\n"
        return run(simulated_frame(), Path(args.out) / "selftest", args.seeds[:2], 3, banner)

    frame, audit = load_clean_dataset(args.dataset)
    print(f"Source: {audit.get('source')}  rows: {audit.get('rows_in')}")
    allowed, reason = quality_gate(frame)
    if not allowed:
        print("METRICS_WITHHELD\n" + reason)
        return 2
    if "synthetic_placeholder" in frame.columns and not args.include_synthetic:
        frame = frame.loc[~frame["synthetic_placeholder"].astype(bool)].reset_index(drop=True)
    group, is_session = group_column(frame)
    ok, why = session_gate(frame, group, is_session)
    if not ok:
        print("METRICS_WITHHELD\n" + why)
        return 2
    return run(frame, Path(args.out), args.seeds, args.splits)


if __name__ == "__main__":
    sys.exit(main())
