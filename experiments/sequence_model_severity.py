"""
ARGUS Part A — Transformer with Auxiliary Severity Head
=======================================================
Architecture identical to sequence_model.py EXCEPT:
  - Dataset returns (X, y_cls, y_sev) tuples
  - Model has a second regression head (severity_head) on the same encoder
  - Combined loss: BCE(cls) + LAMBDA_SEV * MSE(sev|malicious_only)

Loss weighting rationale:
  LAMBDA_SEV = 0.3  →  30% gradient from severity regression, 70% from
  classification.  Severity regression only applies to malicious sessions
  (y_cls > 0 in the batch), preventing the dominant-normal-class from
  trivially zeroing the regression target and collapsing the gradient.

ISOLATION: outputs to transformer_severity_weights.pt and
           transformer_severity_scores.parquet — does NOT overwrite the
           live transformer_weights.pt or transformer_scores.parquet.
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
from scipy import stats as scipy_stats
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    average_precision_score, roc_auc_score,
)
from sklearn.preprocessing import RobustScaler

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

SEQ_LEN      = 8
D_MODEL      = 32
N_HEADS      = 4
N_LAYERS     = 2
DIM_FF       = 64
DROPOUT      = 0.1
BATCH_SIZE   = 128
EPOCHS       = 20
LR           = 1e-3
LAMBDA_SEV   = 0.3   # weight for auxiliary severity regression loss
DEVICE       = torch.device("cpu")
RANDOM_STATE = 42

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
# Dataset (returns cls label + severity target)
# ─────────────────────────────────────────────────────────────────────────────

class SeveritySessionDataset(Dataset):
    def __init__(self, sf: pd.DataFrame, feature_cols: list, seq_len: int):
        self.sequences: list = []
        self.labels_cls: list = []
        self.labels_sev: list = []
        self.meta:       list = []

        sf = sf.sort_values(["entity_id", "session_start"]).reset_index(drop=True)

        for entity_id, grp in sf.groupby("entity_id"):
            grp = grp.reset_index(drop=True)
            n   = len(grp)
            if n < 2:
                continue

            feats     = grp[feature_cols].fillna(0.0).values.astype(np.float32)
            labels_c  = grp["is_malicious"].astype(int).values
            labels_s  = grp["severity"].fillna(0.0).values.astype(np.float32)

            for end in range(1, n):
                start  = max(0, end - seq_len + 1)
                window = feats[start:end + 1]

                if len(window) < seq_len:
                    pad    = np.zeros((seq_len - len(window), window.shape[1]), dtype=np.float32)
                    window = np.concatenate([pad, window], axis=0)

                self.sequences.append(window)
                self.labels_cls.append(labels_c[end])
                self.labels_sev.append(labels_s[end])
                self.meta.append((entity_id, grp.at[end, "session_id"]))

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        X     = torch.from_numpy(self.sequences[idx])
        y_cls = torch.tensor(self.labels_cls[idx], dtype=torch.float32)
        y_sev = torch.tensor(self.labels_sev[idx], dtype=torch.float32)
        return X, y_cls, y_sev


# ─────────────────────────────────────────────────────────────────────────────
# Model (two heads on shared encoder)
# ─────────────────────────────────────────────────────────────────────────────

class ARGUSTransformerSeverity(nn.Module):
    def __init__(self, n_features: int, d_model: int, nhead: int,
                 num_layers: int, dim_ff: int, dropout: float, seq_len: int):
        super().__init__()
        self.input_proj = nn.Linear(n_features, d_model)
        self.pos_emb    = nn.Embedding(seq_len, d_model)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=dim_ff,
            dropout=dropout, batch_first=True, norm_first=True,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.norm        = nn.LayerNorm(d_model)

        # Classification head (anomaly score)
        self.cls_head = nn.Sequential(
            nn.Linear(d_model, 16), nn.GELU(), nn.Dropout(dropout), nn.Linear(16, 1),
        )
        # Severity regression head (auxiliary — shares same encoder representation)
        self.sev_head = nn.Sequential(
            nn.Linear(d_model, 16), nn.GELU(), nn.Dropout(dropout),
            nn.Linear(16, 1), nn.Sigmoid(),  # output clamped to [0,1]
        )

    def forward(self, x):
        B, S, _ = x.shape
        pos  = torch.arange(S, device=x.device).unsqueeze(0).expand(B, -1)
        h    = self.input_proj(x) + self.pos_emb(pos)
        h    = self.transformer(h)
        h    = self.norm(h[:, -1, :])
        return self.cls_head(h).squeeze(-1), self.sev_head(h).squeeze(-1)


# ─────────────────────────────────────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────────────────────────────────────

def compute_class_weight(labels: list) -> float:
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    return float(n_neg / max(n_pos, 1))


def train_model(train_dataset: SeveritySessionDataset,
                n_features: int,
                epochs: int = EPOCHS,
                batch_size: int = BATCH_SIZE) -> ARGUSTransformerSeverity:

    pos_weight = compute_class_weight(train_dataset.labels_cls)
    print(f"  pos_weight = {pos_weight:.1f}  (n_train_sequences={len(train_dataset):,})")

    loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, drop_last=False)

    model = ARGUSTransformerSeverity(
        n_features=n_features, d_model=D_MODEL, nhead=N_HEADS,
        num_layers=N_LAYERS, dim_ff=DIM_FF, dropout=DROPOUT, seq_len=SEQ_LEN,
    ).to(DEVICE)

    bce_loss = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([pos_weight], device=DEVICE))
    mse_loss = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    t0 = time.time()
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss_cls = 0.0
        total_loss_sev = 0.0

        for X_batch, y_cls_batch, y_sev_batch in loader:
            X_batch       = X_batch.to(DEVICE)
            y_cls_batch   = y_cls_batch.to(DEVICE)
            y_sev_batch   = y_sev_batch.to(DEVICE)

            optimizer.zero_grad()
            cls_logits, sev_preds = model(X_batch)

            loss_cls = bce_loss(cls_logits, y_cls_batch)

            # Regression loss only on malicious sessions in the batch
            mal_mask = y_cls_batch > 0.5
            if mal_mask.sum() > 0:
                loss_sev = mse_loss(sev_preds[mal_mask], y_sev_batch[mal_mask])
            else:
                loss_sev = torch.tensor(0.0, device=DEVICE)

            loss = loss_cls + LAMBDA_SEV * loss_sev
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            total_loss_cls += loss_cls.item() * len(y_cls_batch)
            total_loss_sev += loss_sev.item() * mal_mask.sum().item()

        scheduler.step()
        elapsed = time.time() - t0
        if epoch == 1 or epoch % 5 == 0:
            avg_cls = total_loss_cls / len(train_dataset)
            print(f"  Epoch {epoch:3d}/{epochs}  cls_loss={avg_cls:.4f}  elapsed={elapsed:.0f}s")

        if elapsed > 4200:
            print(f"  [WARN] Time limit at epoch {epoch}. Stopping.")
            break

    print(f"  Training complete in {time.time() - t0:.0f}s.")
    return model


# ─────────────────────────────────────────────────────────────────────────────
# Inference
# ─────────────────────────────────────────────────────────────────────────────

@torch.no_grad()
def score_dataset(model: ARGUSTransformerSeverity,
                  dataset: SeveritySessionDataset,
                  batch_size: int = 256):
    model.eval()
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)
    all_cls, all_sev = [], []
    for X_batch, _, _ in loader:
        cls_logits, sev_preds = model(X_batch.to(DEVICE))
        all_cls.append(torch.sigmoid(cls_logits).cpu().numpy())
        all_sev.append(sev_preds.cpu().numpy())
    return np.concatenate(all_cls), np.concatenate(all_sev)


# ─────────────────────────────────────────────────────────────────────────────
# Gradient check — per-campaign Spearman r
# ─────────────────────────────────────────────────────────────────────────────

def gradient_check_low_and_slow(sf: pd.DataFrame, score_map: dict, sev_map: dict):
    """
    Train-side check: for each low_and_slow campaign in train set, compute
    Spearman r between bytes_total (magnitude) and the model's severity-head
    output.  If the severity head learned a real gradient (not flat ceiling),
    we expect r > 0.5 for most campaigns.
    """
    ls_train = sf[
        (sf["split"] == "train") & (sf["attack_type"] == "low_and_slow_exfiltration")
    ].copy()
    ls_train["sev_pred"]   = ls_train["session_id"].map(sev_map)
    ls_train["cls_pred"]   = ls_train["session_id"].map(score_map)
    ls_train = ls_train.dropna(subset=["sev_pred"])

    print(f"\n[GRADIENT CHECK] Low-and-Slow (train set)")
    print(f"  Checking severity-head vs bytes_total per campaign")
    results = []
    for camp_id, grp in ls_train.groupby("attack_instance_id"):
        if len(grp) < 3:
            continue
        r_sev, p_sev = scipy_stats.spearmanr(grp["bytes_total"], grp["sev_pred"])
        r_cls, _     = scipy_stats.spearmanr(grp["bytes_total"], grp["cls_pred"])
        results.append({"campaign": camp_id, "n": len(grp),
                         "r_severity_head": r_sev, "r_cls_head": r_cls, "p": p_sev})
        print(f"    {camp_id}: n={len(grp)}  r_sev={r_sev:+.3f}  r_cls={r_cls:+.3f}  p={p_sev:.3f}")

    if results:
        mean_r = np.mean([x["r_severity_head"] for x in results])
        verdict = "PASS (real gradient)" if mean_r > 0.4 else "WARN (weak gradient)"
        print(f"  Mean Spearman r (severity head) = {mean_r:.3f}  -> {verdict}")
        return mean_r, results
    return None, []


# ─────────────────────────────────────────────────────────────────────────────
# Evaluation (same as baseline)
# ─────────────────────────────────────────────────────────────────────────────

def evaluate(sf, test_session_ids, score_map, threshold=0.5):
    test_df = sf[sf["session_id"].isin(test_session_ids)].copy()
    test_df["cls_score"] = test_df["session_id"].map(score_map)
    test_df = test_df.dropna(subset=["cls_score"])

    y_true  = test_df["is_malicious"].astype(int).values
    y_score = test_df["cls_score"].values
    y_pred  = (y_score >= threshold).astype(int)

    normal_test  = test_df[test_df["attack_type"] == "none"]
    n_normal     = len(normal_test)
    fp_count     = int((normal_test["cls_score"] >= threshold).sum())
    fp_rate      = fp_count / max(n_normal, 1)

    results = {
        "overall": {
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall":    float(recall_score(y_true, y_pred, zero_division=0)),
            "f1":        float(f1_score(y_true, y_pred, zero_division=0)),
            "pr_auc":    float(average_precision_score(y_true, y_score)) if y_true.sum() > 0 else 0.0,
            "roc_auc":   float(roc_auc_score(y_true, y_score))          if y_true.sum() > 0 else 0.0,
            "normal_fp_count": fp_count,
            "normal_fp_rate":  round(fp_rate, 4),
            "n_normal_test":   n_normal,
            "threshold":       float(threshold),
        }
    }

    per_type = {}
    for atk in sorted(test_df["attack_type"].unique()):
        if atk == "none":
            continue
        sub = test_df[test_df["attack_type"] == atk]
        n_total   = len(sub)
        n_flagged = int((sub["cls_score"] >= threshold).sum())
        per_type[atk] = {
            "recall":     round(n_flagged / max(n_total, 1), 4),
            "n_sessions": n_total,
            "n_flagged":  n_flagged,
            "n_campaigns": int(test_df.loc[test_df["attack_type"] == atk, "attack_instance_id"].nunique()),
        }
    results["per_attack_type"] = per_type
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

    if "severity" not in sf.columns:
        raise RuntimeError("severity column not found — regenerate dataset first.")

    feature_cols = [c for c in ALL_FEATURES if c in sf.columns]
    n_features   = len(feature_cols)
    print(f"    {n_features} feature columns.")

    # Scale features using train split only
    scaler    = RobustScaler()
    train_mask = sf["split"] == "train"
    X_all     = sf[feature_cols].fillna(0.0).values
    scaler.fit(X_all[train_mask])
    X_scaled  = scaler.transform(X_all)

    sf_scaled = sf.copy()
    for i, col in enumerate(feature_cols):
        sf_scaled[col] = X_scaled[:, i]

    train_sf = sf_scaled[sf_scaled["split"] == "train"].reset_index(drop=True)

    print("[*] Building sequence datasets...")
    train_dataset = SeveritySessionDataset(train_sf, feature_cols, SEQ_LEN)
    full_dataset  = SeveritySessionDataset(sf_scaled, feature_cols, SEQ_LEN)
    print(f"    Train sequences: {len(train_dataset):,}")

    # Quick severity variance sanity-check on train
    sev_vals = [v for v in train_dataset.labels_sev if v > 0]
    print(f"    Non-zero severity labels in train: {len(sev_vals)} (std={np.std(sev_vals):.3f})")

    print("[*] Training Transformer+Severity Detector...")
    model = train_model(train_dataset, n_features)

    print("[*] Scoring all sessions...")
    all_cls, all_sev = score_dataset(model, full_dataset)
    score_map = {meta[1]: float(s) for meta, s in zip(full_dataset.meta, all_cls)}
    sev_map   = {meta[1]: float(s) for meta, s in zip(full_dataset.meta, all_sev)}

    # ── Gradient Check ──────────────────────────────────────────────────────
    mean_r, gc_results = gradient_check_low_and_slow(sf, score_map, sev_map)

    print("[*] Evaluating on test split...")
    test_session_ids = set(sf[sf["split"] == "test"]["session_id"].values)
    results = evaluate(sf, test_session_ids, score_map, threshold=0.5)

    # Save weights + scores
    os.makedirs("src/models", exist_ok=True)
    torch.save(model.state_dict(), "src/models/transformer_severity_weights.pt")

    score_rows = []
    for (entity_id, session_id), cls_s, sev_s in zip(full_dataset.meta, all_cls, all_sev):
        score_rows.append({
            "session_id":           session_id,
            "severity_cls_score":   float(cls_s),
            "severity_sev_score":   float(sev_s),
        })
    score_df = pd.DataFrame(score_rows).drop_duplicates("session_id")
    score_df.to_parquet("data/processed/transformer_severity_scores.parquet", index=False)
    print(f"[OK] Saved {len(score_df):,} severity scores to transformer_severity_scores.parquet")

    results["gradient_check"] = {
        "mean_spearman_r_ls_train": float(mean_r) if mean_r is not None else None,
        "per_campaign": gc_results,
    }

    with open("data/processed/transformer_severity_results.json", "w") as f:
        json.dump(results, f, indent=2)

    ov = results["overall"]
    print(f"\n--- Transformer+Severity Test Results ---")
    print(f"  P={ov['precision']:.3f}  R={ov['recall']:.3f}  F1={ov['f1']:.3f}  "
          f"PR-AUC={ov['pr_auc']:.3f}  ROC-AUC={ov['roc_auc']:.3f}")
    print(f"  Normal FPs: {ov['normal_fp_count']} / {ov['n_normal_test']}  "
          f"({ov['normal_fp_rate']*100:.2f}%)")
    print(f"\n  Per-attack-type recall:")
    for atk, m in results["per_attack_type"].items():
        print(f"    {atk:35s}  Recall={m['recall']:.3f}  sessions={m['n_sessions']}  campaigns={m['n_campaigns']}")


if __name__ == "__main__":
    main()
