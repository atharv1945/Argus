import pandas as pd
df = pd.read_parquet('data/processed/fused_scores.parquet')
test = df[df['split']=='test']
mal_test = test[test['is_malicious'] & (test['attack_type']!='none')]
mismatch = mal_test[mal_test['predicted_attack_type'] != mal_test['attack_type']]

print('Remaining mismatches (5/78):')
print(mismatch[['attack_type','predicted_attack_type','fp_mismatch','event_count','failure_ratio','failure_count','entity_fan_out','foreign_access_count']].to_string())
print()

print('Tier 1 flagged sessions (hard-rule):')
tier1 = test[(test['fusion_tier']==1) & test['is_malicious']]
print(tier1.groupby('attack_type')['session_id'].count().to_string())
print()

flagged = test[test['fused_risk_score']>=50]
fp = flagged[~flagged['is_malicious']]
normal_total = len(test[~test['is_malicious']])
print(f'False positives: {len(fp)} / {normal_total} normal sessions ({100.0*len(fp)/normal_total:.2f}%)')
print()

print('Full alert breakdown:')
print(flagged.groupby(['attack_type','is_malicious'])['session_id'].count().to_string())
