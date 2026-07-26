"""
Inference-only re-scoring using the restored iforest_model.pkl.
No retraining — loads the committed model and rescores all sessions.
"""
import pickle
import numpy as np
import pandas as pd

print('[*] Loading restored iforest_model.pkl...')
with open('src/models/iforest_model.pkl', 'rb') as f:
    meta = pickle.load(f)

iforest      = meta['model']
scaler       = meta['scaler']
feature_cols = meta['feature_cols']

print(f'    Model: {iforest.n_estimators} estimators, {len(feature_cols)} features')

print('[*] Loading session features...')
sf = pd.read_parquet('data/processed/session_features.parquet')
print(f'    {len(sf):,} sessions')

# Inference only — identical to score_all_sessions() in isolation_forest.py
X = sf[feature_cols].fillna(0.0).values.astype('float32')
X_scaled = scaler.transform(X)
raw_scores = iforest.decision_function(X_scaled)
anomaly_scores = -raw_scores   # flip: higher = more anomalous

sf['iforest_score'] = anomaly_scores

print('[*] Saving iforest_scores.parquet...')
out_cols = [
    'session_id', 'entity_id', 'entity_type', 'split', 'is_malicious',
    'attack_type', 'attack_instance_id', 'session_start', 'iforest_score'
]
sf[out_cols].to_parquet('data/processed/iforest_scores.parquet', index=False)

# Quick sanity check
test_norm = sf[(sf['split'] == 'test') & (~sf['is_malicious'])]
test_mal  = sf[(sf['split'] == 'test') &  sf['is_malicious']]
print(f'    Normal test mean   : {test_norm["iforest_score"].mean():.4f}')
print(f'    Malicious test mean: {test_mal["iforest_score"].mean():.4f}')
print('[OK] iforest_scores.parquet regenerated from restored model.')
