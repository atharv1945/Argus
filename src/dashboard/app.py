"""
ARGUS Phase 6 — Analyst Dashboard
===================================
Streamlit entry point.

Run:
    streamlit run src/dashboard/app.py

Views:
  1. Header: drift banner + pipeline metrics
  2. Alert Queue: risk-ranked case table (alert_cases.parquet)
  3. Entity Drill-down: session timeline + analyst note
  4. Subgraph Visualizer: entity-device-resource graph (NetworkX/matplotlib)
  5. Feedback: TP/FP buttons writing to data/feedback/feedback.csv
"""

import os
import sys
import json
import csv
import math
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import numpy as np
import streamlit as st
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx

# ── Ensure src/ is on path ──────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.explain.generate_note import generate_note_for_session, generate_note_for_case

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ARGUS Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Data paths ───────────────────────────────────────────────────────────────
DATA = ROOT / "data" / "processed"
FEEDBACK_DIR = ROOT / "data" / "feedback"
FEEDBACK_FILE = FEEDBACK_DIR / "feedback.csv"

# ── Styling ───────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Tier badge colors */
.tier1 { background:#dc2626; color:white; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:0.85em; }
.tier2 { background:#d97706; color:white; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:0.85em; }
.tier3 { background:#2563eb; color:white; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:0.85em; }
.metric-card { background:#1e1e2e; border-radius:8px; padding:12px 16px; margin:4px; border:1px solid #333; }
.note-box { background:#0f0f1a; border:1px solid #334; border-radius:6px; padding:12px; font-family:monospace; font-size:0.88em; white-space:pre-wrap; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Data loading (cached)
# ─────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=300)
def load_data():
    cases  = pd.read_parquet(DATA / "alert_cases.parquet")
    fused  = pd.read_parquet(DATA / "fused_scores.parquet")
    raw    = pd.read_parquet(DATA / "full_dataset.parquet")
    raw["timestamp"] = pd.to_datetime(raw["timestamp"])

    with open(DATA / "fusion_results.json") as f:
        results = json.load(f)
    with open(DATA / "drift_baseline.json") as f:
        drift_baseline = json.load(f)

    return cases, fused, raw, results, drift_baseline


@st.cache_resource
def load_graph():
    """Load entity graph (heavier — cached as resource across sessions)."""
    from src.graph.entity_graph import EntityGraph
    raw = pd.read_parquet(DATA / "full_dataset.parquet")
    raw["timestamp"] = pd.to_datetime(raw["timestamp"])
    g = EntityGraph()
    g.build_from_events(raw)
    return g


def get_drift_level(drift_baseline: dict, fused: pd.DataFrame) -> tuple[str, str, str]:
    """
    Compute drift level by comparing test alert rate to train baseline.
    Returns (level, colour, description).
    """
    train_rate = float(drift_baseline.get("alert_rate", 0.095))
    test = fused[fused["split"] == "test"]
    if len(test) == 0:
        return "UNKNOWN", "#6b7280", "Insufficient test data"
    test_alert_rate = (test["fused_risk_score"] >= 50).mean()
    ratio = test_alert_rate / max(train_rate, 1e-6)

    if ratio < 1.5:
        return "NONE", "#22c55e", f"Test alert rate {test_alert_rate:.2%} vs train {train_rate:.2%} (ratio {ratio:.2f}x)"
    elif ratio < 3.0:
        return "MODERATE", "#f59e0b", f"Test alert rate {test_alert_rate:.2%} vs train {train_rate:.2%} (ratio {ratio:.2f}x) — monitor"
    else:
        return "SIGNIFICANT", "#ef4444", f"Test alert rate {test_alert_rate:.2%} vs train {train_rate:.2%} (ratio {ratio:.2f}x) — investigate"


def ensure_feedback_store():
    FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
    if not FEEDBACK_FILE.exists():
        with open(FEEDBACK_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "case_id", "entity_id", "predicted_attack_type", "verdict", "analyst_note"])


def write_feedback(case_id: str, entity_id: str, attack_type: str, verdict: str, note: str = ""):
    ensure_feedback_store()
    with open(FEEDBACK_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now(timezone.utc).isoformat(),
            case_id, entity_id, attack_type, verdict, note
        ])


def load_feedback() -> pd.DataFrame:
    if not FEEDBACK_FILE.exists():
        return pd.DataFrame(columns=["timestamp", "case_id", "entity_id", "predicted_attack_type", "verdict", "analyst_note"])
    return pd.read_csv(FEEDBACK_FILE)


# ─────────────────────────────────────────────────────────────────────────────
# Subgraph builder
# ─────────────────────────────────────────────────────────────────────────────

def build_entity_subgraph(entity_id: str, g, raw: pd.DataFrame, session_ids: list) -> nx.DiGraph:
    """Extract entity's subgraph: entity → devices/resources touched in these sessions."""
    sub = nx.DiGraph()
    entity_events = raw[(raw["entity_id"] == entity_id) & (raw["session_id"].isin(session_ids))]

    # Add entity node
    sub.add_node(entity_id, ntype="entity", label=entity_id)

    for _, row in entity_events.iterrows():
        dev = row.get("device_id", "")
        res = row.get("resource_id", "")
        if dev:
            sub.add_node(dev, ntype="device", label=dev[:18])
            sub.add_edge(entity_id, dev, etype="uses_device")
        if res and row.get("event_type") not in ("logon", "logoff"):
            sub.add_node(res, ntype="resource", label=res[:18])
            sub.add_edge(dev or entity_id, res, etype="accesses")

    # Add other entities that share devices (fan-out)
    touched_devs = [n for n, d in sub.nodes(data=True) if d.get("ntype") == "device"]
    for dev in touched_devs:
        if dev in g.G:
            for pred in g.G.predecessors(dev):
                if pred != entity_id:
                    node_data = g.G.nodes.get(pred, {})
                    if node_data.get("ntype") == "entity":
                        sub.add_node(pred, ntype="entity_other", label=pred[:14])
                        sub.add_edge(pred, dev, etype="shared_device")

    return sub


def draw_subgraph(sub: nx.DiGraph, title: str = "") -> plt.Figure:
    """Draw entity subgraph with colour coding by node type."""
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("#0f0f1a")
    ax.set_facecolor("#0f0f1a")

    node_colors = []
    node_sizes  = []
    labels      = {}
    for node, data in sub.nodes(data=True):
        nt = data.get("ntype", "unknown")
        labels[node] = data.get("label", node)
        if nt == "entity":
            node_colors.append("#ef4444")
            node_sizes.append(900)
        elif nt == "entity_other":
            node_colors.append("#f97316")
            node_sizes.append(600)
        elif nt == "device":
            node_colors.append("#3b82f6")
            node_sizes.append(500)
        elif nt == "resource":
            node_colors.append("#22c55e")
            node_sizes.append(400)
        else:
            node_colors.append("#6b7280")
            node_sizes.append(300)

    if len(sub.nodes) == 0:
        ax.text(0.5, 0.5, "No graph data for this session", ha="center", va="center",
                color="#6b7280", fontsize=14, transform=ax.transAxes)
        ax.axis("off")
        return fig

    try:
        pos = nx.spring_layout(sub, seed=42, k=2.5)
    except Exception:
        pos = nx.shell_layout(sub)

    nx.draw_networkx_nodes(sub, pos, node_color=node_colors, node_size=node_sizes, ax=ax, alpha=0.9)
    nx.draw_networkx_edges(sub, pos, edge_color="#4b5563", arrows=True,
                           arrowsize=18, ax=ax, alpha=0.7, connectionstyle="arc3,rad=0.05")
    nx.draw_networkx_labels(sub, pos, labels=labels, ax=ax, font_size=7, font_color="white")

    # Legend
    legend_patches = [
        mpatches.Patch(color="#ef4444", label="Target entity"),
        mpatches.Patch(color="#f97316", label="Co-using entity"),
        mpatches.Patch(color="#3b82f6", label="Device"),
        mpatches.Patch(color="#22c55e", label="Resource"),
    ]
    ax.legend(handles=legend_patches, loc="upper right", facecolor="#1e1e2e",
              labelcolor="white", framealpha=0.8, fontsize=8)
    ax.set_title(title, color="white", fontsize=10)
    ax.axis("off")
    plt.tight_layout()
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# Main app
# ─────────────────────────────────────────────────────────────────────────────

def main():
    cases, fused, raw, results, drift_baseline = load_data()
    ensure_feedback_store()

    # ── Sidebar ──────────────────────────────────────────────────────────────
    with st.sidebar:
        st.image("https://img.shields.io/badge/ARGUS-Security-red?style=for-the-badge", use_container_width=False)
        st.title("🛡️ ARGUS")
        st.caption("Adaptive Risk & Graph-based Unified Security")

        view = st.radio("View", ["Alert Queue", "Entity Drill-Down", "Analyst Feedback"], index=0)

        st.divider()
        st.caption("**Data split filter**")
        split_filter = st.selectbox("Split", ["test", "train", "all"], index=0)
        show_benign  = st.checkbox("Include benign/not-flagged cases", value=False)

        st.divider()
        st.caption(f"Pipeline: Precision {results['overall']['precision']:.4f} | "
                   f"Recall {results['overall']['recall']:.4f} | "
                   f"F1 {results['overall']['f1']:.4f}")

    # ── Drift Banner ─────────────────────────────────────────────────────────
    drift_level, drift_color, drift_desc = get_drift_level(drift_baseline, fused)
    drift_emoji = {"NONE": "✅", "MODERATE": "⚠️", "SIGNIFICANT": "🚨"}.get(drift_level, "ℹ️")
    st.markdown(
        f'<div style="background:{drift_color}22; border-left:4px solid {drift_color}; '
        f'padding:8px 16px; border-radius:4px; margin-bottom:12px;">'
        f'<b>{drift_emoji} Drift Monitor:</b> <code>{drift_level}</code> — {drift_desc}'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ── Header Metrics ────────────────────────────────────────────────────────
    col1, col2, col3, col4, col5 = st.columns(5)
    test_cases = cases[cases["split"] == "test"]
    flagged_cases = test_cases[test_cases["max_fused_risk_score"] >= 50]
    with col1:
        st.metric("Test Cases", len(flagged_cases))
    with col2:
        t1 = (flagged_cases["tier_1_count"] > 0).sum()
        st.metric("Tier 1 (Hard Rule)", t1, delta=None)
    with col3:
        t2 = ((flagged_cases["tier_1_count"] == 0) & (flagged_cases["tier_2_count"] > 0)).sum()
        st.metric("Tier 2 (Graph-Boosted)", t2)
    with col4:
        st.metric("Precision", f"{results['overall']['precision']:.3f}")
    with col5:
        st.metric("Recall", f"{results['overall']['recall']:.3f}")

    st.divider()

    # ─────────────────────────────────────────────────────────────────────────
    # VIEW: Alert Queue
    # ─────────────────────────────────────────────────────────────────────────
    if view == "Alert Queue":
        st.header("🚨 Risk-Ranked Alert Queue")

        # Filter cases
        view_cases = cases.copy()
        if split_filter != "all":
            view_cases = view_cases[view_cases["split"] == split_filter]
        if not show_benign:
            view_cases = view_cases[view_cases["max_fused_risk_score"] >= 50]

        view_cases = view_cases.sort_values("max_fused_risk_score", ascending=False).reset_index(drop=True)

        # Attack type filter
        all_types = ["All"] + sorted(view_cases["predicted_attack_type"].dropna().unique().tolist())
        atk_filter = st.selectbox("Filter by attack type", all_types, index=0)
        if atk_filter != "All":
            view_cases = view_cases[view_cases["predicted_attack_type"] == atk_filter]

        # Tier filter
        tier_options = {"All tiers": None, "Tier 1 only": 1, "Tier 2 only": 2}
        tier_sel = st.selectbox("Filter by tier", list(tier_options.keys()), index=0)
        if tier_options[tier_sel] == 1:
            view_cases = view_cases[view_cases["tier_1_count"] > 0]
        elif tier_options[tier_sel] == 2:
            view_cases = view_cases[(view_cases["tier_1_count"] == 0) & (view_cases["tier_2_count"] > 0)]

        st.caption(f"Showing **{len(view_cases)}** cases")

        # Load feedback for status column
        feedback_df = load_feedback()
        reviewed_ids = set(feedback_df["case_id"].tolist()) if len(feedback_df) > 0 else set()

        # Build display table
        def tier_label(row):
            if row["tier_1_count"] > 0:
                return "🔴 Tier 1"
            elif row["tier_2_count"] > 0:
                return "🟡 Tier 2"
            return "🔵 Tier 3"

        display = view_cases[[
            "case_id", "entity_id", "entity_type", "entity_dept",
            "predicted_attack_type", "max_fused_risk_score", "session_count",
            "first_seen", "last_seen", "is_malicious"
        ]].copy()
        display["tier"] = view_cases.apply(tier_label, axis=1)
        display["reviewed"] = display["case_id"].apply(lambda x: "✅" if x in reviewed_ids else "")
        display["risk_score"] = display["max_fused_risk_score"].astype(int)
        display["first_seen"]  = pd.to_datetime(display["first_seen"]).dt.strftime("%Y-%m-%d %H:%M")
        display["last_seen"]   = pd.to_datetime(display["last_seen"]).dt.strftime("%Y-%m-%d %H:%M")

        show_cols = ["reviewed", "tier", "entity_id", "entity_dept", "predicted_attack_type",
                     "risk_score", "session_count", "first_seen", "last_seen"]

        st.dataframe(
            display[show_cols].rename(columns={
                "reviewed": "✓", "tier": "Tier", "entity_id": "Entity",
                "entity_dept": "Dept", "predicted_attack_type": "Attack Type",
                "risk_score": "Risk", "session_count": "Sessions",
                "first_seen": "First Seen", "last_seen": "Last Seen"
            }),
            use_container_width=True,
            height=500,
        )

        # Quick drill-in button
        st.divider()
        st.subheader("Quick Drill-in")
        sel_case_id = st.selectbox("Select a case to inspect", [""] + view_cases["case_id"].tolist())
        if sel_case_id:
            sel_case = view_cases[view_cases["case_id"] == sel_case_id].iloc[0]
            _render_drilldown(sel_case, fused, raw)

    # ─────────────────────────────────────────────────────────────────────────
    # VIEW: Entity Drill-Down
    # ─────────────────────────────────────────────────────────────────────────
    elif view == "Entity Drill-Down":
        st.header("🔍 Entity Drill-Down")

        # Entity selector
        all_entities = sorted(cases["entity_id"].unique().tolist())
        search_entity = st.selectbox("Select entity", all_entities, index=0)

        entity_cases = cases[cases["entity_id"] == search_entity].sort_values(
            "max_fused_risk_score", ascending=False
        )
        entity_sessions = fused[fused["entity_id"] == search_entity].sort_values("session_start")

        col_info, col_timeline = st.columns([1, 2])
        with col_info:
            st.subheader("Entity Profile")
            if len(entity_cases) > 0:
                ec = entity_cases.iloc[0]
                st.markdown(f"**ID**: `{search_entity}`")
                st.markdown(f"**Type**: {ec.get('entity_type', 'N/A')}")
                st.markdown(f"**Dept**: {ec.get('entity_dept', 'N/A')}")
                st.markdown(f"**Alert cases**: {len(entity_cases)}")
                st.markdown(f"**Max risk score**: {int(entity_cases['max_fused_risk_score'].max())}")
            st.markdown(f"**Total sessions**: {len(entity_sessions)}")

        with col_timeline:
            st.subheader("Session Risk Timeline")
            if len(entity_sessions) > 0:
                fig, ax = plt.subplots(figsize=(8, 3))
                fig.patch.set_facecolor("#0f0f1a")
                ax.set_facecolor("#0f0f1a")

                ses = entity_sessions.copy()
                ses["session_start"] = pd.to_datetime(ses["session_start"])
                colors = ses["fused_risk_score"].apply(
                    lambda s: "#ef4444" if s >= 90 else ("#f59e0b" if s >= 55 else "#22c55e")
                )
                ax.scatter(ses["session_start"], ses["fused_risk_score"],
                           c=colors, s=60, zorder=3, alpha=0.85)
                ax.axhline(50, color="#f59e0b", linestyle="--", linewidth=0.8, alpha=0.7, label="Alert threshold")
                ax.set_xlabel("Date", color="white", fontsize=8)
                ax.set_ylabel("Risk Score", color="white", fontsize=8)
                ax.tick_params(colors="white", labelsize=7)
                ax.spines[:].set_color("#4b5563")
                ax.set_ylim(0, 105)
                ax.legend(fontsize=7, labelcolor="white", facecolor="#1e1e2e")
                plt.xticks(rotation=30)
                plt.tight_layout()
                st.pyplot(fig)
            else:
                st.info("No session data for this entity.")

        st.divider()

        # Case selector for drill-down
        if len(entity_cases) > 0:
            case_labels = [
                f"{row['case_id']} — risk {int(row['max_fused_risk_score'])} — {row['predicted_attack_type']}"
                for _, row in entity_cases.iterrows()
            ]
            sel_label = st.selectbox("Select case for detail", case_labels)
            sel_case = entity_cases.iloc[case_labels.index(sel_label)]
            _render_drilldown(sel_case, fused, raw)

    # ─────────────────────────────────────────────────────────────────────────
    # VIEW: Analyst Feedback
    # ─────────────────────────────────────────────────────────────────────────
    elif view == "Analyst Feedback":
        st.header("📝 Analyst Feedback Log")
        feedback_df = load_feedback()

        if len(feedback_df) > 0:
            st.dataframe(feedback_df, use_container_width=True)
            tp = (feedback_df["verdict"] == "TRUE_POSITIVE").sum()
            fp = (feedback_df["verdict"] == "FALSE_POSITIVE").sum()
            st.metric("True Positives marked", tp)
            st.metric("False Positives marked", fp)
            if tp + fp > 0:
                st.metric("Analyst precision estimate", f"{tp/(tp+fp):.1%}")
        else:
            st.info("No feedback submitted yet. Use the alert queue or drill-down to submit TP/FP verdicts.")

        # Export button
        if len(feedback_df) > 0:
            st.download_button(
                "⬇️ Export feedback CSV",
                feedback_df.to_csv(index=False),
                file_name="argus_analyst_feedback.csv",
                mime="text/csv",
            )


# ─────────────────────────────────────────────────────────────────────────────
# Shared drill-down renderer
# ─────────────────────────────────────────────────────────────────────────────

def _render_drilldown(sel_case, fused: pd.DataFrame, raw: pd.DataFrame):
    """Render case detail: analyst note + subgraph + feedback buttons."""
    case_id  = sel_case["case_id"]
    eid      = sel_case["entity_id"]
    all_ids  = list(sel_case["all_session_ids"])

    # Get anchor session (max risk)
    case_sessions = fused[fused["session_id"].isin(all_ids)]
    if len(case_sessions) == 0:
        st.warning("No session data found for this case.")
        return

    anchor = case_sessions.loc[case_sessions["fused_risk_score"].idxmax()]

    col_note, col_graph = st.columns([1, 1])

    # ── Analyst Note ──────────────────────────────────────────────────────────
    with col_note:
        st.subheader("📋 Analyst Note")
        st.caption(f"Case `{case_id}` | Anchor session: `{anchor['session_id']}`")

        # Case summary
        st.markdown(f"""
| Field | Value |
|-------|-------|
| **Entity** | `{eid}` ({sel_case.get('entity_type','?')} / {sel_case.get('entity_dept','?')}) |
| **Attack type** | {sel_case.get('predicted_attack_type','?')} |
| **Risk score** | {int(sel_case.get('max_fused_risk_score',0))} / 100 |
| **Sessions** | {int(sel_case.get('session_count',1))} ({int(sel_case.get('suppressed_count',0))} suppressed) |
| **First seen** | {str(sel_case.get('first_seen',''))[:19]} |
| **Last seen** | {str(sel_case.get('last_seen',''))[:19]} |
""")

        # Generated analyst note
        try:
            note_text = generate_note_for_session(anchor, fused)
        except Exception as e:
            note_text = f"[Error generating note: {e}]"

        st.markdown('<div class="note-box">' + note_text.replace("\n", "<br>") + '</div>',
                    unsafe_allow_html=True)

        # Feedback buttons
        st.subheader("Verdict")
        fb_col1, fb_col2 = st.columns(2)
        note_input = st.text_input("Analyst comment (optional)", key=f"note_{case_id}")

        with fb_col1:
            if st.button("✅ True Positive", key=f"tp_{case_id}", type="primary"):
                write_feedback(case_id, eid, sel_case.get("predicted_attack_type",""), "TRUE_POSITIVE", note_input)
                st.success("Marked as True Positive ✅")

        with fb_col2:
            if st.button("❌ False Positive", key=f"fp_{case_id}"):
                write_feedback(case_id, eid, sel_case.get("predicted_attack_type",""), "FALSE_POSITIVE", note_input)
                st.warning("Marked as False Positive ❌")

    # ── Subgraph ──────────────────────────────────────────────────────────────
    with col_graph:
        st.subheader("🕸️ Entity Subgraph")
        tier = "Tier 1" if int(sel_case.get("tier_1_count", 0)) > 0 else "Tier 2"
        st.caption(f"{tier} — Entity `{eid}` across {len(all_ids)} session(s)")

        with st.spinner("Building subgraph..."):
            try:
                g = load_graph()
                sub = build_entity_subgraph(eid, g, raw, all_ids)
                n_nodes = sub.number_of_nodes()
                n_edges = sub.number_of_edges()
                fig = draw_subgraph(sub, title=f"{eid}: {n_nodes} nodes, {n_edges} edges")
                st.pyplot(fig)
                st.caption(
                    f"🔴 Target entity &nbsp; 🟠 Co-using entity &nbsp; 🔵 Device &nbsp; 🟢 Resource"
                )
            except Exception as e:
                st.error(f"Subgraph error: {e}")

    # ── Session detail table ──────────────────────────────────────────────────
    st.subheader("Session Details")
    show_cols = [
        "session_id", "attack_type", "predicted_attack_type", "fp_mismatch",
        "geo_velocity_violation", "event_count", "failure_ratio",
        "new_device_edge_count", "lateral_hop_score",
        "transformer_score", "iforest_score", "fused_risk_score", "fusion_tier",
        "hard_rule_detail"
    ]
    avail = [c for c in show_cols if c in case_sessions.columns]
    st.dataframe(case_sessions[avail], use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
