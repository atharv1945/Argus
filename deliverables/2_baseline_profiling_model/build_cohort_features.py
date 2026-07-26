"""
ARGUS Phase 3 — Shared-IP Cohort Feature Builder
=================================================
Computes per-session the number of distinct entity_ids that attempted
authentication (logon events) from the SAME geo_ip within a ±1 hour window
around the session's start time.

This is the primary behaviorally-correct signal for credential_stuffing:
a real stuffing campaign has many distinct victims targeted from one IP block,
creating a fan-in pattern from the attacker's vantage point.

Key feature
-----------
  ip_entity_fan_in : int
      Count of distinct entity_ids that logged in (or attempted) from the same
      geo_ip as this session within ±1 hour of the session start.
      - Normal single-user sessions: 1 (only themselves)
      - Credential stuffing (8 victims, 1 IP): 8
      - Corporate NAT/proxy (many legit users same IP): varies, but without
        correlated failures this alone does NOT trigger Tier 1.

Usage (standalone):
    python -m src.fusion.build_cohort_features

Output:
    data/processed/cohort_features.parquet   — one row per session_id
"""

import os
import numpy as np
import pandas as pd


def build_ip_cohort_features(
    raw_df: pd.DataFrame,
    session_df: pd.DataFrame,
    window_hours: float = 1.0,
) -> pd.DataFrame:
    """
    Compute ip_entity_fan_in for each session.

    Parameters
    ----------
    raw_df       : full_dataset.parquet (event-level), must have
                   entity_id, geo_ip, session_id, timestamp, event_type
    session_df   : session_features.parquet (session-level), must have
                   session_id, session_start
    window_hours : half-width of the lookback/lookahead window in hours

    Returns
    -------
    DataFrame with columns: session_id, ip_entity_fan_in
    """
    print("[*] Building IP cohort features...")

    # Filter to logon events (authentication attempts)
    raw_df = raw_df.copy()
    raw_df["timestamp"] = pd.to_datetime(raw_df["timestamp"])

    auth = raw_df[raw_df["event_type"].isin(["logon", "auth_attempt"])][
        ["entity_id", "geo_ip", "session_id", "timestamp"]
    ].copy()

    if len(auth) == 0:
        print("    [!] No logon/auth events found — returning zeros.")
        return pd.DataFrame({
            "session_id": session_df["session_id"].values,
            "ip_entity_fan_in": 0,
        })

    # Primary IP per session: geo_ip on the first logon event of each session
    sess_ip = (
        auth.sort_values("timestamp")
        .groupby("session_id", sort=False)[["geo_ip", "entity_id"]]
        .first()
        .reset_index()
        .rename(columns={"geo_ip": "sess_ip", "entity_id": "sess_entity"})
    )

    # Session start times
    sess_df_t = session_df[["session_id", "session_start"]].copy()
    sess_df_t["session_start"] = pd.to_datetime(sess_df_t["session_start"])
    sess_ip = sess_ip.merge(sess_df_t, on="session_id", how="left")

    # Build numpy arrays for vectorised window queries.
    # auth["timestamp"] is datetime64[us] → .values.astype("int64") gives MICROSECONDS.
    # pd.Timestamp().value gives NANOSECONDS. Convert us→ns by multiplying by 1000.
    auth_times  = auth["timestamp"].values.astype("int64") * 1000   # us→ns
    auth_ips    = auth["geo_ip"].values
    auth_ents   = auth["entity_id"].values

    delta_ns = int(window_hours * 3600 * 1e9)

    results = []
    for _, row in sess_ip.iterrows():
        ip      = row["sess_ip"]
        t_start = row["session_start"]

        if pd.isna(ip) or pd.isna(t_start):
            results.append(0)
            continue

        t_ns   = int(pd.Timestamp(t_start).value)
        lo, hi = t_ns - delta_ns, t_ns + delta_ns

        # Boolean mask: same IP AND within time window
        mask = (auth_ips == ip) & (auth_times >= lo) & (auth_times <= hi)
        n_ents = len(set(auth_ents[mask]))
        results.append(n_ents)

    sess_ip["ip_entity_fan_in"] = results

    # Sessions without logon events → default to 0 (not in sess_ip)
    out = session_df[["session_id"]].merge(
        sess_ip[["session_id", "ip_entity_fan_in"]],
        on="session_id",
        how="left",
    )
    out["ip_entity_fan_in"] = out["ip_entity_fan_in"].fillna(0).astype(int)

    print(f"    ip_entity_fan_in stats: "
          f"max={out['ip_entity_fan_in'].max()}, "
          f"mean={out['ip_entity_fan_in'].mean():.2f}, "
          f"sessions with fan_in>=3: {(out['ip_entity_fan_in']>=3).sum()}")

    return out[["session_id", "ip_entity_fan_in"]]


def main():
    raw_path  = "data/processed/full_dataset.parquet"
    sess_path = "data/processed/session_features.parquet"
    out_path  = "data/processed/cohort_features.parquet"

    print("[*] Loading datasets...")
    raw_df  = pd.read_parquet(raw_path)
    sess_df = pd.read_parquet(sess_path)

    cohort_df = build_ip_cohort_features(raw_df, sess_df)

    os.makedirs("data/processed", exist_ok=True)
    cohort_df.to_parquet(out_path, index=False)
    print(f"[OK] Saved cohort features → {out_path}")
    print(f"     Columns: {cohort_df.columns.tolist()}, rows: {len(cohort_df):,}")

    # Quick diagnostic: fan_in distribution by attack type
    meta = sess_df[["session_id", "attack_type", "split"]].copy()
    merged = cohort_df.merge(meta, on="session_id", how="left")
    print("\n--- ip_entity_fan_in mean by attack type (test split) ---")
    test = merged[merged["split"] == "test"]
    print(test.groupby("attack_type")["ip_entity_fan_in"].agg(["mean", "max", "count"]).round(2).to_string())


if __name__ == "__main__":
    main()
