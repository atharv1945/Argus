"""
ARGUS Phase 2 — Transformer Sequence Anomaly Detector (Retrained on 20-Field Schema)
=====================================================================================
Architecture: A small Transformer encoder over each entity's chronological
session-feature sequence. The final session's representation is passed through
an anomaly scoring head trained as binary classification (normal vs. malicious).

Usage:
    python src/models/sequence_model.py
"""

import os
import json
import time
import pickle
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    average_precision_score, roc_auc_score,
)
from sklearn.preprocessing import RobustScaler

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

SEQ_LEN         = 8
D_MODEL         = 32
N_HEADS         = 4
N_LAYERS        = 2
DIM_FF          = 64
DROPOUT         = 0.1
BATCH_SIZE      = 128
EPOCHS          = 20
LR              = 1e-3
DEVICE          = torch.device("cpu")
RANDOM_STATE    = 42

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
DEV_FEATURES      = [f"dev_{f}"      for f in BASE_FEATURES]
PEER_DEV_FEATURES = [f"peer_dev_{f}" for f in BASE_FEATURES]
ALL_FEATURES      = BASE_FEATURES + DEV_FEATURES + PEER_DEV_FEATURES


# ─────────────────────────────────────────────────────────────────────────────
# Dataset
# ─────────────────────────────────────────────────────────────────────────────

class SessionSequenceDataset(Dataset):
    def __init__(self, sf: pd.DataFrame, feature_cols: list, seq_len: int):
        self.sequences: list = []
        self.labels:    list = []
        self.meta:      list = []

        sf = sf.sort_values(["entity_id", "session_start"]).reset_index(drop=True)

        for entity_id, grp in sf.groupby("entity_id"):
            grp = grp.reset_index(drop=True)
            n   = len(grp)

            if n < 2:
                continue

            feats = grp[feature_cols].fillna(0.0).values.astype(np.float32)
            labels = grp["is_malicious"].astype(int).values

            for end in range(1, n):
                start = max(0, end - seq_len + 1)
                window = feats[start:end + 1]

                if len(window) < seq_len:
                    pad = np.zeros((seq_len - len(window), window.shape[1]), dtype=np.float32)
                    window = np.concatenate([pad, window], axis=0)

                self.sequences.append(window)
                self.labels.append(labels[end])
                self.meta.append((entity_id, grp.at[end, "session_id"]))

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        X = torch.from_numpy(self.sequences[idx])
        y = torch.tensor(self.labels[idx], dtype=torch.float32)
        return X, y


# ─────────────────────────────────────────────────────────────────────────────
# Model
# ─────────────────────────────────────────────────────────────────────────────

class ARGUSTransformerDetector(nn.Module):
    def __init__(self, n_features: int, d_model: int, nhead: int,
                 num_layers: int, dim_ff: int, dropout: float, seq_len: int):
        super().__init__()
        self.input_proj = nn.Linear(n_features, d_model)
        self.pos_emb = nn.Embedding(seq_len, d_model)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_ff,
            dropout=dropout,
            batch_first=True,
            norm_first=True,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        self.norm = nn.LayerNorm(d_model)
        self.head = nn.Sequential(
            nn.Linear(d_model, 16),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(16, 1),
        )

    def forward(self, x):
        B, S, _ = x.shape
        pos = torch.arange(S, device=x.device).unsqueeze(0).expand(B, -1)
        h = self.input_proj(x) + self.pos_emb(pos)
        h = self.transformer(h)
        h = self.norm(h[:, -1, :])
        return self.head(h).squeeze(-1)


# ─────────────────────────────────────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────────────────────────────────────

def compute_class_weight(labels: list) -> float:
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    return float(n_neg / max(n_pos, 1))


def train_model(train_dataset: SessionSequenceDataset,
                n_features: int,
                epochs: int = EPOCHS,
                batch_size: int = BATCH_SIZE) -> ARGUSTransformerDetector:

    pos_weight = compute_class_weight(train_dataset.labels)
    print(f"  pos_weight = {pos_weight:.1f}  (n_train_sequences={len(train_dataset):,})")

    loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, drop_last=False)

    model = ARGUSTransformerDetector(
        n_features=n_features,
        d_model=D_MODEL,
        nhead=N_HEADS,
        num_layers=N_LAYERS,
        dim_ff=DIM_FF,
        dropout=DROPOUT,
        seq_len=SEQ_LEN,
    ).to(DEVICE)

    criterion = nn.BCEWithLogitsLoss(
        pos_weight=torch.tensor([pos_weight], device=DEVICE)
    )
    optimizer = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    t0 = time.time()
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for X_batch, y_batch in loader:
            X_batch = X_batch.to(DEVICE)
            y_batch = y_batch.to(DEVICE)

            optimizer.zero_grad()
            logits = model(X_batch)
            loss   = criterion(logits, y_batch)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            total_loss += loss.item() * len(y_batch)

        scheduler.step()
        elapsed = time.time() - t0

        if epoch == 1 or epoch % 5 == 0:
            avg_loss = total_loss / len(train_dataset)
            print(f"  Epoch {epoch:3d}/{epochs}  loss={avg_loss:.4f}  elapsed={elapsed:.0f}s")

        if elapsed > 4200:
            print(f"  [WARN] Training time limit reached at epoch {epoch}. Stopping early.")
            break

    print(f"  Training complete in {time.time() - t0:.0f}s.")
    return model


# ─────────────────────────────────────────────────────────────────────────────
# Inference
# ─────────────────────────────────────────────────────────────────────────────

@torch.no_grad()
def score_dataset(model: ARGUSTransformerDetector,
                  dataset: SessionSequenceDataset,
                  batch_size: int = 256) -> np.ndarray:
    model.eval()
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)
    all_scores = []
    for X_batch, _ in loader:
        logits = model(X_batch.to(DEVICE))
        scores = torch.sigmoid(logits).cpu().numpy()
        all_scores.append(scores)
    return np.concatenate(all_scores)


# ─────────────────────────────────────────────────────────────────────────────
# Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate(
    sf: pd.DataFrame,
    test_session_ids: set,
    test_scores_map: dict,
    threshold: float = 0.5,
) -> dict:
    test_df = sf[sf["session_id"].isin(test_session_ids)].copy()
    test_df["transformer_score"] = test_df["session_id"].map(test_scores_map)
    test_df = test_df.dropna(subset=["transformer_score"])

    y_true  = test_df["is_malicious"].astype(int).values
    y_score = test_df["transformer_score"].values
    y_pred  = (y_score >= threshold).astype(int)

    results = {}
    results["overall"] = {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall":    float(recall_score(y_true, y_pred, zero_division=0)),
        "f1":        float(f1_score(y_true, y_pred, zero_division=0)),
        "pr_auc":    float(average_precision_score(y_true, y_score)) if y_true.sum() > 0 else 0.0,
        "roc_auc":   float(roc_auc_score(y_true, y_score)) if y_true.sum() > 0 else 0.0,
        "threshold": float(threshold),
        "n_test_sessions":   len(test_df),
        "n_malicious_test":  int(y_true.sum()),
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
        ys = sub["transformer_score"].values
        yp = (ys >= threshold).astype(int)

        n_campaigns = test_df.loc[test_df["attack_type"] == atk_type, "attack_instance_id"].nunique()
        is_benign_pattern = (atk_type == "insider_drift")

        n_total_atk = len(sub_atk)
        n_flagged_atk = int((sub_atk["transformer_score"] >= threshold).sum())
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
        top_k_idx = test_df["transformer_score"].nlargest(k).index
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
    drift_flagged = int((drift_test["transformer_score"] >= threshold).sum()) if len(drift_test) > 0 else 0
    results["insider_drift_analysis"] = {
        "total_drift_test_sessions": len(drift_test),
        "drift_flagged_as_anomaly": drift_flagged,
        "drift_false_positive_rate": round(drift_flagged / max(len(drift_test), 1), 4),
        "drift_mean_score": float(drift_test["transformer_score"].mean()) if len(drift_test) > 0 else 0.0,
        "normal_mean_score": float(test_df.loc[(test_df["attack_type"] == "none"), "transformer_score"].mean()),
        "malicious_mean_score": float(test_df.loc[test_df["is_malicious"], "transformer_score"].mean()) if y_true.sum() > 0 else 0.0,
        "note": "insider_drift sessions are BENIGN (is_malicious=False). Flagging them counts against precision."
    }

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    torch.manual_seed(RANDOM_STATE)
    np.random.seed(RANDOM_STATE)

    print("[*] Loading session features...")
    sf = pd.read_parquet("data/processed/session_features.parquet")
    sf["session_start"] = pd.to_datetime(sf["session_start"])
    print(f"    {len(sf):,} sessions, {sf['entity_id'].nunique()} entities.")

    feature_cols = [c for c in ALL_FEATURES if c in sf.columns]
    n_features   = len(feature_cols)
    print(f"    {n_features} feature columns.")

    scaler = RobustScaler()
    train_mask = sf["split"] == "train"
    X_all = sf[feature_cols].fillna(0.0).values
    scaler.fit(X_all[train_mask])
    X_scaled = scaler.transform(X_all)

    sf_scaled = sf.copy()
    for i, col in enumerate(feature_cols):
        sf_scaled[col] = X_scaled[:, i]

    train_sf = sf_scaled[sf_scaled["split"] == "train"].reset_index(drop=True)
    print("[*] Building sequence datasets...")
    train_dataset = SessionSequenceDataset(train_sf, feature_cols, SEQ_LEN)
    full_dataset  = SessionSequenceDataset(sf_scaled, feature_cols, SEQ_LEN)
    print(f"    Train sequences: {len(train_dataset):,}")

    print("[*] Training Transformer Detector...")
    model = train_model(train_dataset, n_features)

    print("[*] Scoring all sessions...")
    all_scores = score_dataset(model, full_dataset)
    score_map = {meta[1]: float(score)
                 for meta, score in zip(full_dataset.meta, all_scores)}

    print("[*] Evaluating on test split...")
    test_session_ids = set(sf[sf["split"] == "test"]["session_id"].values)
    results = evaluate(sf, test_session_ids, score_map, threshold=0.5)

    os.makedirs("src/models", exist_ok=True)
    weights_path = "src/models/transformer_weights.pt"
    torch.save(model.state_dict(), weights_path)

    meta_path = "src/models/transformer_meta.pkl"
    with open(meta_path, "wb") as f:
        pickle.dump({
            "feature_cols": feature_cols,
            "scaler":       scaler,
            "seq_len":      SEQ_LEN,
            "d_model":      D_MODEL,
            "n_heads":      N_HEADS,
            "n_layers":     N_LAYERS,
            "dim_ff":       DIM_FF,
            "dropout":      DROPOUT,
        }, f)
    print(f"[OK] Saved model weights to {weights_path}.")

    score_rows = []
    for (entity_id, session_id), score in zip(full_dataset.meta, all_scores):
        score_rows.append({"session_id": session_id, "transformer_score": float(score)})
    score_df = pd.DataFrame(score_rows).drop_duplicates("session_id")
    score_path = "data/processed/transformer_scores.parquet"
    score_df.to_parquet(score_path, index=False)
    print(f"[OK] Saved {len(score_df):,} session transformer scores to {score_path}.")

    results_path = "data/processed/transformer_results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[OK] Saved evaluation results to {results_path}.")

    ov = results["overall"]
    print(f"\n--- Transformer Test Results ---")
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
