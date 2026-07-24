"""
Goal 3 pre-check: Verify new_device_edge_count for Campaign 4 insider_drift
vs device_spoofing / impossible_travel after the timestamp fix.
"""
import pandas as pd
from src.graph.entity_graph import EntityGraph, build_graph_features

raw_df = pd.read_parquet('data/processed/full_dataset.parquet')
sess_df = pd.read_parquet('data/processed/session_features.parquet')
raw_df['timestamp'] = pd.to_datetime(raw_df['timestamp'])

gf = build_graph_features(raw_df, sess_df)

meta = sess_df[['session_id','attack_type','attack_instance_id','split','is_malicious','fp_mismatch','event_count']]
gf_m = gf.merge(meta, on='session_id', how='left')

# insider_drift Campaign 4 (ATK_ID_*_004) — benign hardware/cert upgrade
c4 = gf_m[gf_m['attack_instance_id'].str.endswith('_004') & (gf_m['attack_type']=='insider_drift')]

# Malicious sessions in device_spoofing, impossible_travel (test split)
ds_it = gf_m[gf_m['attack_type'].isin(['device_spoofing','impossible_travel']) & (gf_m['split']=='test')]

# Also get lateral_movement test for Goal 2
lm_test = gf_m[(gf_m['attack_type']=='lateral_movement') & (gf_m['split']=='test')]

# Get Campaign 1 insider_drift (ATK_ID_*_001)
c1 = gf_m[gf_m['attack_instance_id'].str.endswith('_001') & (gf_m['attack_type']=='insider_drift')]

print('=== insider_drift Campaign 4 (benign hardware upgrade) ===')
cols = ['session_id','attack_instance_id','new_device_edge','new_device_edge_count','fp_mismatch','event_count','entity_fan_out','lateral_hop_score','new_resource_edge','resource_fan_out_dev']
print(c4[cols].to_string())
print()
print('=== device_spoofing + impossible_travel (test) ===')
print(ds_it[cols].to_string())
print()
print('=== lateral_movement test ===')
print(lm_test[cols].to_string())
print()
print('=== insider_drift Campaign 1 (cross-dept resource expansion) ===')
print(c1[cols].to_string())
print()

# Summary stats for new_device_edge_count across important groups
print('=== Summary: new_device_edge_count by attack type ===')
import numpy as np
for name, grp in [
    ('insider_drift C4', c4),
    ('device_spoofing (test)', ds_it[ds_it['attack_type']=='device_spoofing']),
    ('impossible_travel (test)', ds_it[ds_it['attack_type']=='impossible_travel']),
    ('lateral_movement (test)', lm_test),
    ('insider_drift C1', c1),
]:
    vals = grp['new_device_edge_count'].values
    print(f'  {name}: {vals.tolist()}  (min={vals.min()}, max={vals.max()})')
