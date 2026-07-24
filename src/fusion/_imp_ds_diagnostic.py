"""
Check schema and data for impossible_travel vs device_spoofing verification.
"""
import pandas as pd
import numpy as np

raw_df = pd.read_parquet("data/processed/full_dataset.parquet")
sess_df = pd.read_parquet("data/processed/session_features.parquet")
fused_df = pd.read_parquet("data/processed/fused_scores.parquet")

print("=== RAW DATASET COLUMNS (full_dataset.parquet) ===")
print(list(raw_df.columns))
print("\nSample row from raw_df:")
print(raw_df.iloc[0].to_dict())

print("\n=== SESSION FEATURES COLUMNS (session_features.parquet) ===")
print(list(sess_df.columns))

print("\n=== Geo / IP / Location / Timing related columns in raw_df ===")
geo_cols_raw = [c for c in raw_df.columns if any(k in c.lower() for k in ["geo", "ip", "country", "location", "dist", "time", "speed", "vel"])]
print("Raw candidate cols:", geo_cols_raw)
for c in geo_cols_raw:
    print(f"  {c}: dtype={raw_df[c].dtype}, nunique={raw_df[c].nunique()}, sample={raw_df[c].dropna().unique()[:5]}")

print("\n=== Geo / IP / Location / Timing related columns in sess_df ===")
geo_cols_sess = [c for c in sess_df.columns if any(k in c.lower() for k in ["geo", "ip", "country", "location", "dist", "time", "speed", "vel"])]
print("Sess candidate cols:", geo_cols_sess)
for c in geo_cols_sess:
    print(f"  {c}: dtype={sess_df[c].dtype}, nunique={sess_df[c].nunique()}, sample={sess_df[c].dropna().unique()[:5]}")

print("\n=== Side-by-side: impossible_travel vs device_spoofing in fused_df (TEST SPLIT) ===")
imp_test = fused_df[(fused_df["split"]=="test") & (fused_df["attack_type"]=="impossible_travel")]
ds_test  = fused_df[(fused_df["split"]=="test") & (fused_df["attack_type"]=="device_spoofing")]

print(f"Count: impossible_travel test={len(imp_test)}, device_spoofing test={len(ds_test)}")

diff_cols = ["session_id", "entity_id", "attack_type", "predicted_attack_type", "fp_mismatch", "event_count", "failure_ratio", "entity_fan_out", "distinct_countries", "foreign_access_count", "distinct_ips", "new_device_edge_count", "ip_entity_fan_in", "transformer_score", "iforest_score", "fused_risk_score", "hard_rule_detail"]

print("\n--- impossible_travel test sessions ---")
print(imp_test[diff_cols].to_string())

print("\n--- device_spoofing test sessions ---")
print(ds_test[diff_cols].to_string())

print("\n=== Check ALL impossible_travel sessions across dataset (train + test) ===")
imp_all = fused_df[fused_df["attack_type"]=="impossible_travel"]
ds_all = fused_df[fused_df["attack_type"]=="device_spoofing"]
print("All impossible_travel:", len(imp_all))
print(imp_all[diff_cols].to_string())

print("\nAll device_spoofing:", len(ds_all))
print(ds_all[diff_cols].head(10)[diff_cols].to_string())

