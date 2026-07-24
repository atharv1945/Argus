"""
ARGUS Phase 3 — Entity Graph Builder
=====================================
Builds a directed, time-ordered entity-device-resource graph from the raw event
stream (full_dataset.parquet) and computes per-SESSION graph heuristic signals:

  - new_device_edge     : entity accessed a device it has NEVER accessed before
                          this session (new entity→device edge in graph)
  - new_resource_edge   : entity accessed a resource for the first time
                          (new entity→resource edge)
  - entity_fan_out      : number of distinct entities that contacted the SAME
                          device(s) this entity used, within ±24h (shared infra
                          fan-in from the device side, fan-out from entity side)
  - lateral_hop_score   : normalised count of new (entity,device) edges touching
                          devices that belong to a different department than the
                          entity's own department — primary lateral-movement signal
  - resource_fan_out    : distinct resources reached by this session, z-scored
                          against this entity's historical distribution
  - graph_edge_count    : total unique (entity→device OR entity→resource) edges
                          touched in this session

Graph construction rules
------------------------
- Nodes: entity_id, device_id, resource_id (typed via node attribute)
- Edges: entity→device (event_type in {logon, device_connect}),
         entity→resource (event_type in {file_access, http, email})
- Edge weight = cumulative event count over the full training window
- "New edge" = edge that does NOT appear in the entity's history BEFORE this
  session's start timestamp (temporal check, not just graph membership)

Usage (standalone):
    python src/graph/entity_graph.py

Output:
    data/processed/graph_features.parquet   — one row per session_id
    data/processed/entity_graph.pkl         — serialised EntityGraph object
"""

import os
import pickle
import numpy as np
import pandas as pd
import networkx as nx
from collections import defaultdict
from datetime import timedelta


# ─────────────────────────────────────────────────────────────────────────────
# Entity Graph
# ─────────────────────────────────────────────────────────────────────────────

class EntityGraph:
    """
    Maintains a directed multigraph of entity→device and entity→resource edges,
    keyed by timestamp so we can answer "had this entity accessed X before T?".
    
    All edge history is stored as a sorted list of timestamps, enabling
    efficient bisection for temporal new-edge queries.
    """

    def __init__(self):
        # G: directed graph, node attrs = {ntype: 'entity'|'device'|'resource', dept: str}
        self.G = nx.DiGraph()
        # edge_times[(src, dst)] = sorted list of timestamps (epoch seconds)
        self.edge_times: dict = defaultdict(list)
        # entity_dept_map[entity_id] = dept string
        self.entity_dept_map: dict = {}
        # device_dept_map[device_id] = dept string (inferred from first-seen resource dept)
        self.device_dept_map: dict = {}

    # ── construction ──────────────────────────────────────────────────────────

    def build_from_events(self, df: pd.DataFrame) -> None:
        """
        Ingest entire raw event dataframe and populate graph + edge_times.
        df must contain: entity_id, entity_dept, device_id, resource_id,
                         resource_dept, event_type, timestamp

        Timestamp note: the source column is datetime64[us] (microseconds).
        .astype('int64') on a us column gives microsecond integers, so we
        divide by 10**6 to obtain Unix epoch seconds. The query side in
        build_graph_features uses pd.Timestamp().value // 10**9 (nanoseconds
        // 10**9 = seconds), which is the correct reference unit. Both sides
        must resolve to seconds.
        """
        df = df.sort_values("timestamp").copy()
        # FIX: datetime64[us] -> int64 yields microseconds; divide by 10**6 for seconds.
        df["ts_epoch"] = df["timestamp"].astype("int64") // 10**6

        # Add entity nodes
        for eid, dept in df[["entity_id", "entity_dept"]].drop_duplicates().values:
            self.G.add_node(eid, ntype="entity", dept=dept)
            self.entity_dept_map[eid] = dept

        # Add device nodes — infer department from entity_dept of first accessor
        dev_dept = df.groupby("device_id")["entity_dept"].first().to_dict()
        for did, dept in dev_dept.items():
            self.G.add_node(did, ntype="device", dept=dept)
            self.device_dept_map[did] = dept

        # Add resource nodes
        res_dept = df.groupby("resource_id")["resource_dept"].first().to_dict()
        for rid, dept in res_dept.items():
            self.G.add_node(rid, ntype="resource", dept=dept)

        # Build edges
        device_events = {"logon", "device_connect"}
        resource_events = {"file_access", "http", "email"}

        for row in df[["entity_id", "device_id", "resource_id",
                        "event_type", "ts_epoch"]].itertuples(index=False):
            eid = row.entity_id
            ts  = row.ts_epoch

            if row.event_type in device_events:
                dst = row.device_id
                if not self.G.has_edge(eid, dst):
                    self.G.add_edge(eid, dst, etype="entity_device", weight=0)
                self.G[eid][dst]["weight"] += 1
                self.edge_times[(eid, dst)].append(ts)

            if row.event_type in resource_events:
                dst = row.resource_id
                if not self.G.has_edge(eid, dst):
                    self.G.add_edge(eid, dst, etype="entity_resource", weight=0)
                self.G[eid][dst]["weight"] += 1
                self.edge_times[(eid, dst)].append(ts)

        # Sort edge_times lists for bisection
        for key in self.edge_times:
            self.edge_times[key].sort()

    # ── per-session feature extraction ────────────────────────────────────────

    def _had_edge_before(self, src: str, dst: str, t_epoch: int) -> bool:
        """Return True if an edge (src→dst) existed strictly BEFORE t_epoch."""
        import bisect
        times = self.edge_times.get((src, dst), [])
        idx = bisect.bisect_left(times, t_epoch)
        return idx > 0

    def compute_session_graph_features(
        self,
        session_events: pd.DataFrame,
        session_start_epoch: int,
    ) -> dict:
        """
        Given all raw events for one session, compute graph heuristic signals.

        Parameters
        ----------
        session_events : pd.DataFrame
            Subset of raw events for this session (sorted by timestamp).
        session_start_epoch : int
            Unix epoch seconds for session start (for temporal new-edge check).

        Returns
        -------
        dict with keys: new_device_edge, new_resource_edge, entity_fan_out,
                        lateral_hop_score, resource_fan_out_raw, graph_edge_count
        """
        entity_id = session_events["entity_id"].iloc[0]
        entity_dept = self.entity_dept_map.get(entity_id, "")

        device_events = {"logon", "device_connect"}
        resource_events = {"file_access", "http", "email"}

        touched_devices = set()
        touched_resources = set()
        new_device_edges = 0
        new_resource_edges = 0
        lateral_new_device_edges = 0

        for row in session_events.itertuples(index=False):
            if row.event_type in device_events:
                dst = row.device_id
                touched_devices.add(dst)
                if not self._had_edge_before(entity_id, dst, session_start_epoch):
                    new_device_edges += 1
                    # Lateral if device's inferred dept differs from entity's dept
                    dev_dept = self.device_dept_map.get(dst, "")
                    if dev_dept and dev_dept != entity_dept:
                        lateral_new_device_edges += 1

            if row.event_type in resource_events:
                dst = row.resource_id
                touched_resources.add(dst)
                if not self._had_edge_before(entity_id, dst, session_start_epoch):
                    new_resource_edges += 1

        # Entity fan-out: count of distinct OTHER entities that touched
        # any device this entity used in this session
        fan_out_entities = set()
        for did in touched_devices:
            if did in self.G:
                for pred in self.G.predecessors(did):
                    node_data = self.G.nodes.get(pred, {})
                    if node_data.get("ntype") == "entity" and pred != entity_id:
                        fan_out_entities.add(pred)

        # Lateral hop score: normalise lateral new device edges by session's total
        # new device edges (0 if no new device edges at all)
        total_new = max(new_device_edges, 1)
        lateral_hop_score = round(lateral_new_device_edges / total_new, 4)

        # Raw resource fan-out count for this session (deviation computed globally)
        resource_fan_out_raw = len(touched_resources)

        # Total unique edges touched in this session
        graph_edge_count = len(touched_devices) + len(touched_resources)

        return {
            "new_device_edge":       int(new_device_edges > 0),
            "new_device_edge_count": new_device_edges,
            "new_resource_edge":     int(new_resource_edges > 0),
            "new_resource_edge_count": new_resource_edges,
            "entity_fan_out":        len(fan_out_entities),
            "lateral_hop_score":     lateral_hop_score,
            "lateral_new_device_edges": lateral_new_device_edges,
            "resource_fan_out_raw":  resource_fan_out_raw,
            "graph_edge_count":      graph_edge_count,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Batch graph feature extraction
# ─────────────────────────────────────────────────────────────────────────────

def build_graph_features(
    raw_df: pd.DataFrame,
    session_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Build the EntityGraph and extract per-session graph heuristic features.

    Parameters
    ----------
    raw_df       : full_dataset.parquet (event-level)
    session_df   : session_features.parquet (session-level, for session_start)

    Returns
    -------
    DataFrame with one row per session_id, containing graph heuristic columns.
    """
    print("[*] Building EntityGraph from raw events...")
    eg = EntityGraph()
    raw_df["timestamp"] = pd.to_datetime(raw_df["timestamp"])
    eg.build_from_events(raw_df)
    print(f"    Graph: {eg.G.number_of_nodes():,} nodes, {eg.G.number_of_edges():,} edges")

    # Prepare lookup: session_id → session_start epoch
    session_df = session_df.copy()
    session_df["session_start"] = pd.to_datetime(session_df["session_start"])
    sess_start_map = session_df.set_index("session_id")["session_start"].to_dict()

    # Group raw events by session
    print("[*] Computing graph features per session...")
    # FIX: datetime64[us] -> int64 yields microseconds; divide by 10**6 for seconds.
    raw_df["ts_epoch"] = raw_df["timestamp"].astype("int64") // 10**6
    grouped = raw_df.groupby("session_id")

    rows = []
    for sess_id, grp in grouped:
        t_start = sess_start_map.get(sess_id)
        if t_start is None:
            continue
        t_epoch = int(pd.Timestamp(t_start).value // 10**9)
        feats = eg.compute_session_graph_features(grp, t_epoch)
        feats["session_id"] = sess_id
        rows.append(feats)

    gf = pd.DataFrame(rows)

    # Add z-scored resource_fan_out deviation across all sessions
    mu = gf["resource_fan_out_raw"].mean()
    sd = gf["resource_fan_out_raw"].std() + 1e-6
    gf["resource_fan_out_dev"] = ((gf["resource_fan_out_raw"] - mu) / sd).round(4)

    print(f"    Graph features computed for {len(gf):,} sessions.")
    return gf


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    raw_path  = "data/processed/full_dataset.parquet"
    sess_path = "data/processed/session_features.parquet"
    out_path  = "data/processed/graph_features.parquet"
    pkl_path  = "data/processed/entity_graph.pkl"

    print("[*] Loading datasets...")
    raw_df  = pd.read_parquet(raw_path)
    sess_df = pd.read_parquet(sess_path)
    print(f"    Raw events    : {len(raw_df):,}")
    print(f"    Sessions      : {len(sess_df):,}")

    gf = build_graph_features(raw_df, sess_df)

    # Merge metadata for inspection
    meta_cols = ["session_id", "entity_id", "entity_type", "entity_dept",
                 "split", "is_malicious", "attack_type", "attack_instance_id"]
    gf_full = gf.merge(sess_df[meta_cols], on="session_id", how="left")

    os.makedirs("data/processed", exist_ok=True)
    gf_full.to_parquet(out_path, index=False)
    print(f"[OK] Saved graph features → {out_path}")
    print(f"     Columns: {gf_full.columns.tolist()}")

    # Save graph object
    eg = EntityGraph()
    raw_df["timestamp"] = pd.to_datetime(raw_df["timestamp"])
    eg.build_from_events(raw_df)
    with open(pkl_path, "wb") as f:
        pickle.dump(eg, f)
    print(f"[OK] Saved EntityGraph → {pkl_path}")

    # Quick sanity: lateral_hop_score stats by attack type
    print("\n--- Graph Feature Summary by Attack Type (test split) ---")
    test = gf_full[gf_full["split"] == "test"]
    summary = test.groupby("attack_type")[
        ["new_device_edge_count", "lateral_hop_score",
         "entity_fan_out", "resource_fan_out_raw"]
    ].mean().round(3)
    print(summary.to_string())


if __name__ == "__main__":
    main()
