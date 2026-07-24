"""
ARGUS Phase 2 — Isolation Forest Detector
==========================================
Trains an Isolation Forest on NORMAL-ONLY training session features as a
cold-start, distribution-free anomaly baseline. Saves model weights and
produces per-session anomaly scores.

Architecture choice rationale:
  Isolation Forest is the ideal cold-start signal because:
  1. It trains on normal traffic only — no label dependency.
  2. It produces raw continuous anomaly scores accessible to the Phase 3
     fusion layer.
  3. CPU-friendly with O(n * trees) inference.

Usage:
    python src/models/isolation_forest.py
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    average_precision_score, roc_auc_score,
    classification_report,
)
from sklearn.preprocessing import RobustScaler

# ─────────────────────────────────────────────────────────────────────────────
# Feature columns used for training
# ─────────────────────────────────────────────────────────────────────────────

BASE_FEATURES = [
    "duration_min", "event_count", "file_access_count", "http_count",
    "email_count", "device_connect_count", "failure_ratio",
    "distinct_resources", "distinct_resource_depts", "distinct_devices",
    "foreign_access_count", "bytes_total", "bytes_max", "bytes_mean",
    "distinct_countries", "distinct_ips", "off_hours_flag",
]

DEV_FEATURES = [f"dev_{f}" for f in BASE_FEATURES]
PEER_DEV_FEATURES = [f"peer_dev_{f}" for f in BASE_FEATURES]

ALL_MODEL_FEATURES = BASE_FEATURES + DEV_FEATURES + PEER_DEV_FEATURES


def load_features(path: str = "data/processed/session_features.parquet") -> pd.DataFrame:
    sf = pd.read_parquet(path)
    sf["session_start"] = pd.to_datetime(sf["session_start"])
    return sf


def prepare_X(sf: pd.DataFrame, feature_cols: list) -> np.ndarray:
    """Fill NaN baselines (sessions without rolling history) with 0 (no deviation)."""
    X = sf[feature_cols].copy()
    X = X.fillna(0.0)
    return X.values.astype(np.float32)


def train_isolation_forest(
    sf: pd.DataFrame,
    feature_cols: list,
    n_estimators: int = 200,
    contamination: float = 0.01,
    random_state: int = 42,
):
    """Train on normal-only training sessions."""
    train_normal = sf[(sf["split"] == "train") & (~sf["is_malicious"])]
    print(f"  Training on {len(train_normal):,} normal training sessions.")

    X_train = prepare_X(train_normal, feature_cols)

    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    iforest = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    iforest.fit(X_train_scaled)

    return iforest, scaler


def score_all_sessions(
    sf: pd.DataFrame,
    iforest: IsolationForest,
    scaler: RobustScaler,
    feature_cols: list,
) -> pd.Series:
    """
    Return anomaly scores for every session.
    Isolation Forest decision_function returns:
      - More negative = more anomalous
    We negate so that higher score = more anomalous (consistent with other models).
    """
    X = prepare_X(sf, feature_cols)
    X_scaled = scaler.transform(X)
    raw_scores = iforest.decision_function(X_scaled)
    # Negate so high = anomalous
    anomaly_scores = -raw_scores
    return pd.Series(anomaly_scores, index=sf.index, name="iforest_score")


def evaluate(sf: pd.DataFrame, threshold_percentile: float = 95.0) -> dict:
    """
    Evaluate on the held-out test split.
    Threshold is set at the <threshold_percentile>-th percentile of scores
    on normal training data (calibrated on training set).
    """
    train_normal_scores = sf.loc[
        (sf["split"] == "train") & (~sf["is_malicious"]), "iforest_score"
    ]
    threshold = np.percentile(train_normal_scores, threshold_percentile)
    print(f"  Decision threshold (p{threshold_percentile:.0f} on train normal): {threshold:.4f}")

    test_df = sf[sf["split"] == "test"].copy()
    test_df["pred"] = (test_df["iforest_score"] >= threshold).astype(int)
    y_true = test_df["is_malicious"].astype(int).values
    y_pred = test_df["pred"].values
    y_score = test_df["iforest_score"].values

    results = {}
    results["overall"] = {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall":    float(recall_score(y_true, y_pred, zero_division=0)),
        "f1":        float(f1_score(y_true, y_pred, zero_division=0)),
        "pr_auc":    float(average_precision_score(y_true, y_score)),
        "roc_auc":   float(roc_auc_score(y_true, y_score)) if y_true.sum() > 0 else 0.0,
        "threshold": float(threshold),
        "n_test_sessions": len(test_df),
        "n_malicious_test": int(y_true.sum()),
    }

    # Per-attack-type breakdown
    per_type = {}
    for atk_type in test_df["attack_type"].unique():
        if atk_type == "none":
            continue
        mask = (test_df["attack_type"] == atk_type) | (test_df["attack_type"] == "none")
        sub = test_df[mask]
        yt = sub["is_malicious"].astype(int).values
        yp = sub["pred"].values
        ys = sub["iforest_score"].values
        n_campaigns = test_df.loc[test_df["attack_type"] == atk_type, "attack_instance_id"].nunique()
        per_type[atk_type] = {
            "precision": float(precision_score(yt, yp, zero_division=0)),
            "recall":    float(recall_score(yt, yp, zero_division=0)),
            "f1":        float(f1_score(yt, yp, zero_division=0)),
            "pr_auc":    float(average_precision_score(yt, ys)) if yt.sum() > 0 else 0.0,
            "n_malicious_sessions": int((yt == 1).sum()),
            "n_campaigns_in_test":  int(n_campaigns),
            "note": "small-sample estimate (1-2 campaigns held out per type)"
        }
    results["per_attack_type"] = per_type

    return results, threshold


def main():
    print("[*] Loading session features...")
    sf = load_features()
    print(f"    {len(sf):,} sessions loaded.")

    feature_cols = [c for c in ALL_MODEL_FEATURES if c in sf.columns]
    print(f"    Using {len(feature_cols)} feature columns.")

    print("[*] Training Isolation Forest...")
    iforest, scaler = train_isolation_forest(sf, feature_cols)

    print("[*] Scoring all sessions...")
    sf["iforest_score"] = score_all_sessions(sf, iforest, scaler, feature_cols)

    print("[*] Evaluating on test split...")
    results, threshold = evaluate(sf)

    # ── Save model artifacts ──────────────────────────────────────────────────
    os.makedirs("src/models", exist_ok=True)
    model_path = "src/models/iforest_model.pkl"
    with open(model_path, "wb") as f:
        pickle.dump({"model": iforest, "scaler": scaler, "feature_cols": feature_cols,
                     "threshold": threshold}, f)
    print(f"[OK] Saved Isolation Forest model to {model_path}.")

    # ── Save scored sessions for Phase 3 fusion ───────────────────────────────
    score_path = "data/processed/iforest_scores.parquet"
    sf[["session_id", "entity_id", "split", "is_malicious", "attack_type",
        "attack_instance_id", "session_start", "iforest_score"]].to_parquet(score_path, index=False)
    print(f"[OK] Saved per-session scores to {score_path}.")

    # ── Save results JSON ─────────────────────────────────────────────────────
    results_path = "data/processed/iforest_results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[OK] Saved evaluation results to {results_path}.")

    # ── Print summary ─────────────────────────────────────────────────────────
    ov = results["overall"]
    print(f"\n--- Isolation Forest Test Results ---")
    print(f"  Overall  P={ov['precision']:.3f}  R={ov['recall']:.3f}  F1={ov['f1']:.3f}  PR-AUC={ov['pr_auc']:.3f}  ROC-AUC={ov['roc_auc']:.3f}")
    print(f"\n  Per-attack-type (small-sample estimates):")
    for atk, m in results["per_attack_type"].items():
        print(f"    {atk:20s}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}  PR-AUC={m['pr_auc']:.3f}  n_malicious_sessions={m['n_malicious_sessions']}  n_campaigns={m['n_campaigns_in_test']}")


if __name__ == "__main__":
    main()
