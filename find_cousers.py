import sys
import os
sys.path.append(os.getcwd())
from src.graph.entity_graph import EntityGraph
import pandas as pd
import networkx as nx
import pickle

cases = pd.read_parquet('data/processed/alert_cases.parquet')
raw = pd.read_parquet('data/processed/full_dataset.parquet')
with open('data/processed/entity_graph.pkl', 'rb') as f:
    g = pickle.load(f)

for i, c in cases.iterrows():
    e = c['entity_id']
    s = list(c['all_session_ids'])
    ev = raw[(raw['entity_id'] == e) & (raw['session_id'].isin(s))]
    devs = [row.get('device_id') for _, row in ev.iterrows() if row.get('device_id')]
    co_users = []
    for d in devs:
        if d in g.G:
            co_users.extend([p for p in g.G.predecessors(d) if p != e and g.G.nodes.get(p, {}).get('ntype') == 'entity'])
    if len(co_users) > 0:
        print(f"Found case_id with co-users: {c['case_id']}, Entity: {e}, Co-users: {set(co_users)}")
        break
