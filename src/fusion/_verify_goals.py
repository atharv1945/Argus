import pandas as pd

result = pd.read_parquet('data/processed/fused_scores.parquet')

# Goal 3: Campaign 4 check
c4 = result[result['attack_instance_id'].str.endswith('_004') & (result['attack_type']=='insider_drift')]
print('=== insider_drift Campaign 4 (should all be NOT Tier 1) ===')
cols = ['session_id','fused_risk_score','fusion_tier','hard_rule_fired','hard_rule_detail','new_device_edge_count','event_count']
print(c4[cols].to_string())
print()

# Goal 2: ID C1 vs LM separation
c1 = result[result['attack_instance_id'].str.endswith('_001') & (result['attack_type']=='insider_drift')]
lm_test = result[(result['attack_type']=='lateral_movement') & (result['split']=='test')]
print('=== insider_drift Campaign 1 (should be benign, low score) ===')
print(c1[['session_id','fused_risk_score','fusion_tier','lateral_hop_score','new_device_edge_count','entity_fan_out','ip_entity_fan_in']].to_string())
print()
print('=== lateral_movement (test, should be Tier 1) ===')
print(lm_test[['session_id','fused_risk_score','fusion_tier','hard_rule_detail','new_device_edge_count','entity_fan_out','ip_entity_fan_in']].to_string())
print()

# Goal 4: credential stuffing ip_entity_fan_in verification
cs_test = result[(result['attack_type']=='credential_stuffing') & (result['split']=='test')]
print('=== credential_stuffing (test): ip_entity_fan_in stats ===')
print('  max={}, min={}, mean={:.1f}'.format(
    cs_test['ip_entity_fan_in'].max(),
    cs_test['ip_entity_fan_in'].min(),
    cs_test['ip_entity_fan_in'].mean()
))
print('  Tier 1 fired: {}/{}'.format((cs_test['fusion_tier']==1).sum(), len(cs_test)))
detail_counts = cs_test['hard_rule_detail'].value_counts().to_dict()
print('  hard_rule_detail counts:', detail_counts)
print()

# Normal sessions that got Tier 1 (FPs)
normal_tier1 = result[(~result['is_malicious']) & (result['fusion_tier']==1) & (result['split']=='test')]
print('=== Normal test sessions in Tier 1 (FPs): {} ==='.format(len(normal_tier1)))
if len(normal_tier1) > 0:
    detail = normal_tier1['hard_rule_detail'].value_counts()
    print(detail.head(10).to_string())
