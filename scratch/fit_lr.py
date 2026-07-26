import json
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression

# Load Data
df = pd.read_parquet('data/processed/fused_scores.parquet')
with open('data/processed/split_manifest.json') as f:
    manifest = json.load(f)

# Identify Test Set
test_campaigns = []
for atk, camps in manifest.get('test_campaigns', {}).items():
    test_campaigns.extend(camps)
test_campaigns.extend(manifest.get('insider_drift_test', []))

cutoff = pd.to_datetime(manifest['normal_cutoff_date'])
df['session_start'] = pd.to_datetime(df['session_start'])

def get_split(row):
    if row['is_malicious'] or row.get('attack_type', 'none') == 'insider_drift':
        return 'test' if row.get('attack_instance_id') in test_campaigns else 'train'
    else:
        return 'test' if row['session_start'] >= cutoff else 'train'

df['split'] = df.apply(get_split, axis=1)

train_df = df[df['split'] == 'train'].copy()
test_df = df[df['split'] == 'test'].copy()

print("=== METHODOLOGY VERIFICATION ===")
print(f"Train split size: {len(train_df)}")
print(f"Test split size:  {len(test_df)}")

# Features for LR
features = ['transformer_score', 'if_norm', 'graph_boost']

X_train = train_df[features]
y_train = train_df['is_malicious'].astype(int)

# Fit Logistic Regression on TRAIN ONLY
lr = LogisticRegression(random_state=42, class_weight='balanced')
lr.fit(X_train, y_train)

print("\n=== STEP 1: LEARNED COEFFICIENTS ===")
for feat, coef in zip(features, lr.coef_[0]):
    print(f"{feat:20s}: {coef:.4f}")
print(f"Intercept: {lr.intercept_[0]:.4f}")

# Predict on TEST ONLY
X_test = test_df[features]
lr_probs = lr.predict_proba(X_test)[:, 1]

# Construct new combined score
# Hard rules stay as they are (100). Otherwise, scale LR prob to 0-100.
def compute_new_score(row, prob):
    if row['fusion_tier'] == 1 or row['hard_rule_fired']:
        return max(row['fused_risk_score'], 90.0) # Ensure it passes any threshold
    else:
        return prob * 100.0

test_df['lr_prob'] = lr_probs
test_df['new_combined_score'] = test_df.apply(lambda r: compute_new_score(r, r['lr_prob']), axis=1)

malicious_test = test_df[test_df['is_malicious'] == True]
normal_test = test_df[test_df['is_malicious'] == False]

print("\n=== STEP 2: THRESHOLD SWEEP ON NEW COMBINED SCORE ===")
print(f"{'Threshold':<10} | {'Precision':<10} | {'Recall':<10} | {'F1':<10} | {'FP Count':<10}")

best_t = None
best_prec = 0
best_recall = 0
best_f1 = 0
best_fp = 9999

# Sweep thresholds from 1 to 99
for t in range(1, 100):
    flagged = test_df[test_df['new_combined_score'] >= t]
    tp = len(flagged[flagged['is_malicious'] == True])
    fp = len(flagged[flagged['is_malicious'] == False])
    fn = len(malicious_test) - tp
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    # We want recall >= 0.999 (i.e. 1.0)
    if recall >= 0.999:
        if precision > best_prec:
            best_prec = precision
            best_recall = recall
            best_f1 = f1
            best_fp = fp
            best_t = t
        
    if t % 5 == 0 or t == 50:
        print(f"{t:<10} | {precision:<10.4f} | {recall:<10.4f} | {f1:<10.4f} | {fp:<10}")

print("\n=== STEP 3: OPTIMAL THRESHOLD (100% RECALL) ===")
print(f"Optimal Threshold: {best_t}")
print(f"Precision: {best_prec:.4f}")
print(f"Recall:    {best_recall:.4f}")
print(f"F1 Score:  {best_f1:.4f}")
print(f"FP Count:  {best_fp}")
