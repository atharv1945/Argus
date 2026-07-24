"""Patch script v2: adjust corroboration thresholds for hard rule."""

target = "src/fusion/anomaly_first_fusion.py"
content = open(target, encoding='utf-8').read()

# Replace the corroboration condition
old = '    # fp_mismatch hard-rule: must be corroborated by new graph edge OR geo jump\n    if fp_mm >= HARD_RULE_FP_MISMATCH:\n        if new_dev >= 2 or countries > 1:\n            rules_fired.append("fp_mismatch+corroborated")'

new = '    # fp_mismatch hard-rule: corroborated if ANY of:\n    #   - new_device_edge_count >= 1 (device not in entity history)\n    #   - distinct_countries > 1  (geo jump — covers impossible_travel)\n    #   - event_count == 1        (single-event flash sessions typical of spoofing/travel)\n    # This excludes routine multi-device users (who have new_dev=0, countries=1, event_count>1)\n    event_ct = int(row.get("event_count", 2))\n    if fp_mm >= HARD_RULE_FP_MISMATCH:\n        if new_dev >= 1 or countries > 1 or event_ct == 1:\n            rules_fired.append("fp_mismatch+corroborated")'

if old in content:
    content = content.replace(old, new)
    open(target, 'w', encoding='utf-8').write(content)
    print("Patch v2 applied successfully.")
else:
    print("ERROR: old string not found")
    idx = content.find('fp_mismatch hard-rule')
    print(repr(content[idx:idx+400]))
