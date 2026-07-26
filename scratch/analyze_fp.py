import json
import pandas as pd
from datetime import datetime
import numpy as np

# Load Data
df = pd.read_parquet('data/processed/fused_scores.parquet')
with open('data/processed/split_manifest.json') as f:
    manifest = json.load(f)

# Identify Test Set (same logic as build_features/evaluate_fusion)
test_campaigns = []
for atk, camps in manifest.get('test_campaigns', {}).items():
    test_campaigns.extend(camps)
test_campaigns.extend(manifest.get('insider_drift_test', []))

cutoff = pd.to_datetime(manifest['normal_cutoff_date'])
df['session_start'] = pd.to_datetime(df['session_start'])

# Mark test set
def is_test(row):
    if row['is_malicious'] or row.get('attack_type', 'none') == 'insider_drift':
        return row.get('attack_instance_id') in test_campaigns
    else:
        return row['session_start'] >= cutoff

df['is_test'] = df.apply(is_test, axis=1)
test_df = df[df['is_test']].copy()

# FPs: Normal sessions in test set that are flagged
# "normal" here means is_malicious == False. (insider_drift is benign, so is_malicious=False)
normal_test = test_df[test_df['is_malicious'] == False]
malicious_test = test_df[test_df['is_malicious'] == True]

# Wait, in the evaluation, insider_drift FPs are reported separately from "Normal FP count".
# Let's check: "FP 40/3,163 (1.26%)". 3163 is the number of normal test sessions.
# Does normal_test include insider drift? Let's check sizes.
# test_df size = 3280. malicious_test = 117. normal_test = 3280 - 117 = 3163.
# This means normal_test INCLUDES insider_drift (which is 2 campaigns, around 10 sessions).
fps = normal_test[normal_test['fused_risk_score'] >= 50].copy()
tps = malicious_test[malicious_test['fused_risk_score'] >= 50].copy()

print("=== PART 1: DIAGNOSE THE 40 FALSE POSITIVES ===")
print(f"Total Normal Test: {len(normal_test)}")
print(f"Total FPs (score >= 50): {len(fps)}")

print("\n--- FP DETAILS ---")
# fused_risk_score, tier, hard_rule_detail (if any), graph_boost, transformer_score, if_norm, entity_type, entity_dept
cols_to_print = ['fused_risk_score', 'fusion_tier', 'hard_rule_detail', 'graph_boost', 'transformer_score', 'if_norm', 'entity_type', 'entity_dept', 'attack_type']
# Sort by score descending
fps_sorted = fps.sort_values('fused_risk_score', ascending=False)
for _, row in fps_sorted.iterrows():
    print(f"Score: {row['fused_risk_score']:.1f} | Tier: {row['fusion_tier']} | Rule: {row.get('hard_rule_detail', '')[:20]:20s} | GBoost: {row.get('graph_boost', 0):.2f} | Trans: {row.get('transformer_score', 0):.2f} | IF: {row.get('if_norm', 0):.2f} | Type: {row['entity_type']} | Dept: {row['entity_dept']} | Atk: {row.get('attack_type', 'none')}")

print("\n--- FP BREAKDOWN ---")
print("By Entity Type:")
print(fps['entity_type'].value_counts())
print("\nBy Department:")
print(fps['entity_dept'].value_counts())
print("\nBy Rule / Tier:")
print(fps['fusion_tier'].value_counts())
print(fps['hard_rule_detail'].value_counts())

print("\n--- SCORE DISTRIBUTION ---")
lowest_tp = malicious_test['fused_risk_score'].min()
highest_tn = normal_test[normal_test['fused_risk_score'] < 50]['fused_risk_score'].max()
highest_normal = normal_test['fused_risk_score'].max()
print(f"Lowest True Positive Score: {lowest_tp:.2f}")
print(f"Highest Normal Score (Overall): {highest_normal:.2f}")
print(f"Highest True Negative Score (Below 50): {highest_tn:.2f}")

print("\n=== PART 2: THRESHOLD SENSITIVITY ANALYSIS ===")
print(f"{'Threshold':<10} | {'Precision':<10} | {'Recall':<10} | {'F1':<10} | {'FP Count':<10}")
for t in range(50, 71):
    flagged = test_df[test_df['fused_risk_score'] >= t]
    tp = len(flagged[flagged['is_malicious'] == True])
    fp = len(flagged[flagged['is_malicious'] == False])
    fn = len(malicious_test) - tp
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    print(f"{t:<10} | {precision:<10.4f} | {recall:<10.4f} | {f1:<10.4f} | {fp:<10}")

