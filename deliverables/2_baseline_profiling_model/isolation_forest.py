"""
ARGUS Phase 2 — Isolation Forest Detector (Retrained on 20-Field Schema)
=========================================================================
Trains an Isolation Forest on NORMAL-ONLY training session features as a
cold-start, distribution-free anomaly baseline. Saves model weights and
produces per-session anomaly scores.

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
)
from sklearn.preprocessing import RobustScaler

# ─────────────────────────────────────────────────────────────────────────────
# Feature columns (27 base features + rolling deviations + peer deviations = 81)
# ─────────────────────────────────────────────────────────────────────────────

BASE_FEATURES = [
    "duration_min", "event_count", "file_access_count", "http_count",
    "email_count", "device_connect_count", "failure_ratio",
    "distinct_resources", "distinct_resource_depts", "distinct_devices",
    "foreign_access_count", "bytes_total", "bytes_max", "bytes_mean",
    "distinct_countries", "distinct_ips", "off_hours_flag",
    "cmd_seq_length", "cmd_risky_count", "cmd_risky_ratio",
    "cmd_has_escalate", "cmd_has_delete", "cmd_has_export",
    "cmd_entropy", "auth_risk", "entity_type_code", "fp_mismatch",
]

DEV_FEATURES = [f"dev_{f}" for f in BASE_FEATURES]
PEER_DEV_FEATURES = [f"peer_dev_{f}" for f in BASE_FEATURES]

ALL_MODEL_FEATURES = BASE_FEATURES + DEV_FEATURES + PEER_DEV_FEATURES


def load_features(path: str = "data/processed/session_features.parquet") -> pd.DataFrame:
    sf = pd.read_parquet(path)
    sf["session_start"] = pd.to_datetime(sf["session_start"])
    return sf


def prepare_X(sf: pd.DataFrame, feature_cols: list) -> np.ndarray:
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
    X = prepare_X(sf, feature_cols)
    X_scaled = scaler.transform(X)
    raw_scores = iforest.decision_function(X_scaled)
    anomaly_scores = -raw_scores
    return pd.Series(anomaly_scores, index=sf.index, name="iforest_score")


def evaluate(sf: pd.DataFrame, threshold_percentile: float = 95.0) -> dict:
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
        "pr_auc":    float(average_precision_score(y_true, y_score)) if y_true.sum() > 0 else 0.0,
        "roc_auc":   float(roc_auc_score(y_true, y_score)) if y_true.sum() > 0 else 0.0,
        "threshold": float(threshold),
        "n_test_sessions": len(test_df),
        "n_malicious_test": int(y_true.sum()),
    }

    # ── Per-attack-type breakdown (Recall & PR-AUC vs normal) ──
    per_type = {}
    for atk_type in sorted(test_df["attack_type"].unique()):
        if atk_type == "none":
            continue
        sub_atk = test_df[test_df["attack_type"] == atk_type]
        sub_norm = test_df[test_df["attack_type"] == "none"]
        sub = pd.concat([sub_atk, sub_norm])

        yt = sub["is_malicious"].astype(int).values
        ys = sub["iforest_score"].values
        yp = (ys >= threshold).astype(int)

        n_campaigns = test_df.loc[test_df["attack_type"] == atk_type, "attack_instance_id"].nunique()
        is_benign_pattern = (atk_type == "insider_drift")

        # Class-specific recall = TP_atk / N_atk
        n_total_atk = len(sub_atk)
        n_flagged_atk = int((sub_atk["iforest_score"] >= threshold).sum())
        atk_recall = float(n_flagged_atk / max(n_total_atk, 1))

        per_type[atk_type] = {
            "recall":               round(atk_recall, 4),
            "pr_auc":               round(float(average_precision_score(yt, ys)), 4) if yt.sum() > 0 else 0.0,
            "n_sessions_this_type": n_total_atk,
            "n_flagged_sessions":   n_flagged_atk,
            "n_campaigns_in_test":  int(n_campaigns),
            "is_benign_edge_case":  is_benign_pattern,
            "note": "BENIGN edge case (is_malicious=False). Model should NOT flag these." if is_benign_pattern else "recall & PR-AUC vs normal traffic"
        }
    results["per_attack_type"] = per_type

    # ── Precision@top-k% alert budget ──
    top_k_results = {}
    for pct in [0.5, 1.0, 2.0]:
        k = max(1, int(len(test_df) * pct / 100.0))
        top_k_idx = test_df["iforest_score"].nlargest(k).index
        top_k_df = test_df.loc[top_k_idx]
        tp = int(top_k_df["is_malicious"].sum())
        fp = k - tp
        insider_drift_in_top_k = int((top_k_df["attack_type"] == "insider_drift").sum())

        top_k_results[f"top_{pct}pct"] = {
            "k": k,
            "true_positives": tp,
            "false_positives": fp,
            "precision": round(tp / k, 4),
            "insider_drift_flagged": insider_drift_in_top_k,
            "note": f"Top {pct}% of test sessions by anomaly score ({k} sessions)"
        }
    results["precision_at_top_k"] = top_k_results

    # ── Insider drift FP analysis ──
    drift_test = test_df[test_df["attack_type"] == "insider_drift"]
    drift_flagged = int((drift_test["iforest_score"] >= threshold).sum()) if len(drift_test) > 0 else 0
    results["insider_drift_analysis"] = {
        "total_drift_test_sessions": len(drift_test),
        "drift_flagged_as_anomaly": drift_flagged,
        "drift_false_positive_rate": round(drift_flagged / max(len(drift_test), 1), 4),
        "drift_mean_score": float(drift_test["iforest_score"].mean()) if len(drift_test) > 0 else 0.0,
        "normal_mean_score": float(test_df.loc[(test_df["attack_type"] == "none"), "iforest_score"].mean()),
        "malicious_mean_score": float(test_df.loc[test_df["is_malicious"], "iforest_score"].mean()) if y_true.sum() > 0 else 0.0,
        "note": "insider_drift sessions are BENIGN (is_malicious=False). Flagging them counts against precision."
    }

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

    os.makedirs("src/models", exist_ok=True)
    model_path = "src/models/iforest_model.pkl"
    with open(model_path, "wb") as f:
        pickle.dump({"model": iforest, "scaler": scaler, "feature_cols": feature_cols,
                     "threshold": threshold}, f)
    print(f"[OK] Saved Isolation Forest model to {model_path}.")

    score_path = "data/processed/iforest_scores.parquet"
    sf[["session_id", "entity_id", "entity_type", "split", "is_malicious", "attack_type",
        "attack_instance_id", "session_start", "iforest_score"]].to_parquet(score_path, index=False)
    print(f"[OK] Saved per-session scores to {score_path}.")

    results_path = "data/processed/iforest_results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[OK] Saved evaluation results to {results_path}.")

    ov = results["overall"]
    print(f"\n--- Isolation Forest Test Results ---")
    print(f"  Overall  P={ov['precision']:.3f}  R={ov['recall']:.3f}  F1={ov['f1']:.3f}  PR-AUC={ov['pr_auc']:.3f}  ROC-AUC={ov['roc_auc']:.3f}")
    print(f"\n  Per-attack-type:")
    for atk, m in results["per_attack_type"].items():
        label = " (BENIGN)" if m.get("is_benign_edge_case") else ""
        print(f"    {atk:30s}  Recall={m['recall']:.3f}  PR-AUC={m['pr_auc']:.3f}  sessions={m['n_sessions_this_type']}{label}")

    print(f"\n  Precision@top-k% alert budget:")
    for k, v in results["precision_at_top_k"].items():
        print(f"    {k}: precision={v['precision']:.3f}  TP={v['true_positives']}  FP={v['false_positives']}  insider_drift_flagged={v['insider_drift_flagged']}  (k={v['k']})")

    ida = results["insider_drift_analysis"]
    print(f"\n  Insider drift FP analysis:")
    print(f"    Total drift sessions in test: {ida['total_drift_test_sessions']}")
    print(f"    Drift flagged as anomaly:     {ida['drift_flagged_as_anomaly']}  (FP rate: {ida['drift_false_positive_rate']:.3f})")


if __name__ == "__main__":
    main()
