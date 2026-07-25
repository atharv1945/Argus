"""
ARGUS — Analyst Dashboard  (SOC Edition)
=========================================
Dark-mode security-operations-center dashboard built on Streamlit.

Run:
    streamlit run src/dashboard/app.py

Views (tabs):
  1. 🚨 Alert Queue  — risk-ranked card table + live drill-down panel
  2. 📊 Analytics    — 4 Altair charts (timeline / distribution / scores / drift)
  3. 📝 Feedback     — analyst TP/FP log + export
"""

from __future__ import annotations

import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import altair as alt
import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
import streamlit as st

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.explain.generate_note import generate_note_for_session   # noqa: E402

# ── Page config (must be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="ARGUS · Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Paths ─────────────────────────────────────────────────────────────────────
DATA         = ROOT / "data" / "processed"
FEEDBACK_DIR = ROOT / "data" / "feedback"
FEEDBACK_FILE = FEEDBACK_DIR / "feedback.csv"

# ── Constants ─────────────────────────────────────────────────────────────────
ACCENT      = "#06B6D4"   # cyan-500
TIER1_COLOR = "#EF4444"   # red-500
TIER2_COLOR = "#F59E0B"   # amber-500
TIER3_COLOR = "#10B981"   # emerald-500
MUTED_COLOR = "#6B7280"   # gray-500
BG_CARD     = "#111827"   # gray-900
BG_DEEP     = "#0B0F1A"
BORDER      = "#1F2937"   # gray-800

# MITRE ATT&CK technique mapping (UI only — no model change)
MITRE: dict[str, tuple[str, str]] = {
    "brute_force":                ("T1110",     "Brute Force"),
    "credential_stuffing":        ("T1110.004", "Credential Stuffing"),
    "credential_misuse":          ("T1078",     "Valid Accounts"),
    "impossible_travel":          ("T1078",     "Valid Accounts"),
    "device_spoofing":            ("T1200",     "Hardware Additions"),
    "lateral_movement":           ("T1021",     "Remote Services"),
    "low_and_slow_exfiltration":  ("T1030",     "Data Transfer Limits"),
    "insider_drift":              ("T1078.004", "Cloud Accounts"),
    "none":                       ("",          "—"),
}

# ── Global CSS ────────────────────────────────────────────────────────────────
CSS = f"""
<style>
/* ---- Google Fonts ---- */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* ---- Base / reset ---- */
html, body, [class*="css"] {{
    font-family: 'Inter', sans-serif;
}}

/* ---- Hide Streamlit chrome ---- */
#MainMenu, footer {{ visibility: hidden; }}

/* ---- Header bar ---- */
.argus-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 24px;
    background: linear-gradient(135deg, #0E1420 0%, #131B2E 100%);
    border-bottom: 1px solid {BORDER};
    border-radius: 8px;
    margin-bottom: 16px;
}}
.argus-logo {{
    display: flex;
    align-items: center;
    gap: 10px;
}}
.argus-logo-text {{
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    color: {ACCENT};
}}
.argus-logo-sub {{
    font-size: 0.72rem;
    color: #6B7280;
    letter-spacing: 0.05em;
    font-weight: 300;
}}
.argus-header-right {{
    display: flex;
    align-items: center;
    gap: 20px;
}}
.status-chip {{
    display: flex;
    align-items: center;
    gap: 6px;
    background: #052e16;
    border: 1px solid #166534;
    border-radius: 20px;
    padding: 4px 12px;
    font-size: 0.78rem;
    color: #86efac;
    font-weight: 500;
}}
.status-dot {{
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #22c55e;
    animation: pulse 2s infinite;
}}
@keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50%       {{ opacity: 0.4; }}
}}
.header-alert-count {{
    font-size: 0.78rem;
    color: #9CA3AF;
}}
.header-alert-count span {{
    font-size: 1rem;
    font-weight: 700;
    color: {TIER1_COLOR};
}}

/* ---- KPI cards ---- */
.kpi-row {{
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
}}
.kpi-card {{
    flex: 1;
    min-width: 160px;
    background: {BG_CARD};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 14px 18px;
    position: relative;
    overflow: hidden;
}}
.kpi-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
}}
.kpi-card.accent::before   {{ background: {ACCENT}; }}
.kpi-card.red::before      {{ background: {TIER1_COLOR}; }}
.kpi-card.amber::before    {{ background: {TIER2_COLOR}; }}
.kpi-card.green::before    {{ background: {TIER3_COLOR}; }}
.kpi-card.muted::before    {{ background: {MUTED_COLOR}; }}
.kpi-label {{
    font-size: 0.72rem;
    color: #6B7280;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 500;
    margin-bottom: 6px;
}}
.kpi-value {{
    font-size: 1.65rem;
    font-weight: 700;
    color: #E5E7EB;
    line-height: 1;
}}
.kpi-sub {{
    font-size: 0.7rem;
    color: #6B7280;
    margin-top: 4px;
}}

/* ---- Drift badge ---- */
.drift-none         {{ background:#052e16; border:1px solid #166534; color:#86efac; border-radius:6px; padding:6px 12px; font-size:0.8rem; font-weight:600; }}
.drift-moderate     {{ background:#451a03; border:1px solid #92400e; color:#fcd34d; border-radius:6px; padding:6px 12px; font-size:0.8rem; font-weight:600; }}
.drift-significant  {{ background:#450a0a; border:1px solid #991b1b; color:#fca5a5; border-radius:6px; padding:6px 12px; font-size:0.8rem; font-weight:600; }}

/* ---- Tier badges ---- */
.tier-t1 {{ background:{TIER1_COLOR}22; border:1px solid {TIER1_COLOR}66; color:{TIER1_COLOR}; border-radius:4px; padding:2px 8px; font-size:0.75rem; font-weight:700; font-family:'JetBrains Mono',monospace; white-space:nowrap; }}
.tier-t2 {{ background:{TIER2_COLOR}22; border:1px solid {TIER2_COLOR}66; color:{TIER2_COLOR}; border-radius:4px; padding:2px 8px; font-size:0.75rem; font-weight:700; font-family:'JetBrains Mono',monospace; white-space:nowrap; }}
.tier-t3 {{ background:{TIER3_COLOR}22; border:1px solid {TIER3_COLOR}66; color:{TIER3_COLOR}; border-radius:4px; padding:2px 8px; font-size:0.75rem; font-weight:700; font-family:'JetBrains Mono',monospace; white-space:nowrap; }}

/* ---- Attack type tag ---- */
.atk-tag {{
    background: {ACCENT}18;
    border: 1px solid {ACCENT}44;
    color: {ACCENT};
    border-radius: 4px;
    padding: 2px 7px;
    font-size: 0.72rem;
    font-weight: 500;
    white-space: nowrap;
}}

/* ---- MITRE chip ---- */
.mitre-chip {{
    background: #1c1c2e;
    border: 1px solid #374151;
    color: #9CA3AF;
    border-radius: 3px;
    padding: 1px 5px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    white-space: nowrap;
}}

/* ---- Entity ID ---- */
.eid {{ font-family:'JetBrains Mono',monospace; font-size:0.82rem; color:#E5E7EB; font-weight:500; }}

/* ---- Risk score display ---- */
.risk-t1 {{ font-size:1.1rem; font-weight:800; color:{TIER1_COLOR}; font-family:'JetBrains Mono',monospace; }}
.risk-t2 {{ font-size:1.1rem; font-weight:800; color:{TIER2_COLOR}; font-family:'JetBrains Mono',monospace; }}
.risk-t3 {{ font-size:1.1rem; font-weight:800; color:{TIER3_COLOR}; font-family:'JetBrains Mono',monospace; }}

/* ---- Note box (analyst note) ---- */
.note-box {{
    background: #0f131c;
    border: 1px solid #1F2937;
    border-left: 3px solid {ACCENT};
    border-radius: 6px;
    padding: 14px 16px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    white-space: pre-wrap;
    color: #D1D5DB;
    line-height: 1.6;
    max-height: 200px;
    overflow-y: auto;
    resize: vertical;
}}

/* ---- Case summary table ---- */
.case-table {{ width:100%; border-collapse:collapse; font-size:0.82rem; color:#D1D5DB; }}
.case-table td {{ padding:5px 8px; border-bottom:1px solid #1F2937; vertical-align:top; }}
.case-table td:first-child {{ color:#6B7280; white-space:nowrap; font-weight:500; width:40%; }}
.case-table code {{ font-family:'JetBrains Mono',monospace; font-size:0.78rem; background:#1F2937; padding:1px 4px; border-radius:3px; }}

/* ---- Drill-down panel ---- */
.drill-panel {{
    background: {BG_CARD};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 16px;
    min-height: 300px;
}}
.drill-panel-empty {{
    background: {BG_CARD};
    border: 1px dashed {BORDER};
    border-radius: 10px;
    padding: 40px 24px;
    text-align: center;
    color: #4B5563;
    min-height: 300px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}}

/* ---- Section titles ---- */
.section-title {{
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #6B7280;
    font-weight: 600;
    margin-bottom: 8px;
    padding-bottom: 6px;
    border-bottom: 1px solid {BORDER};
}}
</style>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=300)
def load_data():
    cases = pd.read_parquet(DATA / "alert_cases.parquet")
    fused = pd.read_parquet(DATA / "fused_scores.parquet")
    raw   = pd.read_parquet(DATA / "full_dataset.parquet")
    raw["timestamp"] = pd.to_datetime(raw["timestamp"])

    with open(DATA / "fusion_results.json") as f:
        results = json.load(f)
    with open(DATA / "drift_baseline.json") as f:
        drift_baseline = json.load(f)

    return cases, fused, raw, results, drift_baseline


@st.cache_resource
def load_graph():
    from src.graph.entity_graph import EntityGraph
    raw = pd.read_parquet(DATA / "full_dataset.parquet")
    raw["timestamp"] = pd.to_datetime(raw["timestamp"])
    g = EntityGraph()
    g.build_from_events(raw)
    return g


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_drift_level(drift_baseline: dict, fused: pd.DataFrame) -> tuple[str, str, str]:
    train_rate   = float(drift_baseline.get("alert_rate", 0.095))
    n_baseline   = int(drift_baseline.get("n_sessions", 0))
    baseline_filter = drift_baseline.get("baseline_filter", "raw train")
    test         = fused[fused["split"] == "test"]
    if len(test) == 0:
        return "UNKNOWN", MUTED_COLOR, "Insufficient test data"
    test_normal  = test[~test["is_malicious"]] if "is_malicious" in test.columns else test
    test_alert_rate = (test_normal["fused_risk_score"] >= 55).mean()
    ratio        = test_alert_rate / max(train_rate, 1e-6)
    desc = f"Test alert rate {test_alert_rate:.2%} vs train {train_rate:.2%} (ratio {ratio:.2f}×) — {n_baseline:,} sessions ({baseline_filter})"
    if ratio < 1.5:
        return "NONE",        "#22c55e", desc
    elif ratio < 3.0:
        return "MODERATE",    "#f59e0b", desc + " — monitor"
    else:
        return "SIGNIFICANT", "#ef4444", desc + " — investigate"


def tier_of(row) -> int:
    if row["tier_1_count"] > 0:   return 1
    if row["tier_2_count"] > 0:   return 2
    return 3


def risk_color(score: float) -> str:
    if score >= 90: return TIER1_COLOR
    if score >= 55: return TIER2_COLOR
    return TIER3_COLOR


def ensure_feedback_store():
    FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
    if not FEEDBACK_FILE.exists():
        with open(FEEDBACK_FILE, "w", newline="") as f:
            csv.writer(f).writerow(
                ["timestamp", "case_id", "entity_id", "predicted_attack_type", "verdict", "analyst_note"]
            )


def write_feedback(case_id, entity_id, attack_type, verdict, note=""):
    ensure_feedback_store()
    with open(FEEDBACK_FILE, "a", newline="") as f:
        csv.writer(f).writerow(
            [datetime.now(timezone.utc).isoformat(), case_id, entity_id, attack_type, verdict, note]
        )


def load_feedback() -> pd.DataFrame:
    if not FEEDBACK_FILE.exists():
        return pd.DataFrame(columns=["timestamp", "case_id", "entity_id", "predicted_attack_type", "verdict", "analyst_note"])
    return pd.read_csv(FEEDBACK_FILE)


# ─────────────────────────────────────────────────────────────────────────────
# Subgraph (matplotlib — dark themed)
# ─────────────────────────────────────────────────────────────────────────────

def build_entity_subgraph(entity_id, g, raw, session_ids) -> nx.DiGraph:
    sub = nx.DiGraph()
    entity_events = raw[(raw["entity_id"] == entity_id) & (raw["session_id"].isin(session_ids))]
    sub.add_node(entity_id, ntype="entity", label=entity_id)
    for _, row in entity_events.iterrows():
        dev = row.get("device_id", "")
        res = row.get("resource_id", "")
        if dev:
            sub.add_node(dev, ntype="device", label=str(dev)[:18])
            sub.add_edge(entity_id, dev, etype="uses_device")
        if res and row.get("event_type") not in ("logon", "logoff"):
            sub.add_node(res, ntype="resource", label=str(res)[:18])
            sub.add_edge(dev or entity_id, res, etype="accesses")
    touched_devs = [n for n, d in sub.nodes(data=True) if d.get("ntype") == "device"]
    for dev in touched_devs:
        if dev in g.G:
            for pred in g.G.predecessors(dev):
                if pred != entity_id and g.G.nodes.get(pred, {}).get("ntype") == "entity":
                    sub.add_node(pred, ntype="entity_other", label=str(pred)[:14])
                    sub.add_edge(pred, dev, etype="shared_device")
    return sub


def draw_subgraph(sub: nx.DiGraph, title: str = "") -> plt.Figure:
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor(BG_DEEP)
    ax.set_facecolor(BG_DEEP)

    COLOR_MAP = {"entity": TIER1_COLOR, "entity_other": "#F97316",
                 "device": ACCENT, "resource": TIER3_COLOR}
    SIZE_MAP  = {"entity": 900, "entity_other": 600, "device": 500, "resource": 400}

    node_colors, node_sizes, labels = [], [], {}
    for node, data in sub.nodes(data=True):
        nt = data.get("ntype", "unknown")
        labels[node] = data.get("label", str(node))
        node_colors.append(COLOR_MAP.get(nt, MUTED_COLOR))
        node_sizes.append(SIZE_MAP.get(nt, 300))

    if not sub.nodes:
        ax.text(0.5, 0.5, "No graph data for this session",
                ha="center", va="center", color="#4B5563", fontsize=13, transform=ax.transAxes)
        ax.axis("off")
        return fig

    try:
        pos = nx.spring_layout(sub, seed=42, k=2.5)
    except Exception:
        pos = nx.shell_layout(sub)

    nx.draw_networkx_nodes(sub, pos, node_color=node_colors, node_size=node_sizes, ax=ax, alpha=0.92)
    nx.draw_networkx_edges(sub, pos, edge_color="#374151", arrows=True,
                           arrowsize=16, ax=ax, alpha=0.7, connectionstyle="arc3,rad=0.05")
    nx.draw_networkx_labels(sub, pos, labels=labels, ax=ax, font_size=7, font_color="white")

    legend_patches = [
        mpatches.Patch(color=TIER1_COLOR, label="Target entity"),
        mpatches.Patch(color="#F97316",   label="Co-using entity"),
        mpatches.Patch(color=ACCENT,      label="Device"),
        mpatches.Patch(color=TIER3_COLOR, label="Resource"),
    ]
    ax.legend(handles=legend_patches, loc="upper right", facecolor="#111827",
              labelcolor="white", framealpha=0.9, fontsize=8, edgecolor=BORDER)
    ax.set_title(title, color="#9CA3AF", fontsize=9, pad=8)
    ax.axis("off")
    plt.tight_layout(pad=0.5)
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# Chart helpers (Altair — dark themed)
# ─────────────────────────────────────────────────────────────────────────────

_ALT_CONFIG = dict(
    background=BG_CARD,
    axis=alt.AxisConfig(labelColor="#9CA3AF", titleColor="#9CA3AF",
                        gridColor="#1F2937", domainColor="#374151", tickColor="#374151"),
    legend=alt.LegendConfig(labelColor="#E5E7EB", titleColor="#9CA3AF",
                            fillColor=BG_CARD, strokeColor=BORDER, padding=8),
    title=alt.TitleConfig(color="#E5E7EB", fontSize=13, fontWeight="normal"),
    view=alt.ViewConfig(strokeWidth=0, fill=BG_CARD),
)

TIER_COLOR_SCALE = alt.Scale(
    domain=["Tier 1", "Tier 2", "Tier 3"],
    range=[TIER1_COLOR, TIER2_COLOR, TIER3_COLOR],
)

ATK_COLORS = {
    "brute_force":               TIER1_COLOR,
    "credential_stuffing":       TIER1_COLOR,
    "credential_misuse":         TIER1_COLOR,
    "impossible_travel":         TIER1_COLOR,
    "device_spoofing":           TIER2_COLOR,
    "lateral_movement":          TIER2_COLOR,
    "low_and_slow_exfiltration": "#A78BFA",   # purple for LS
    "insider_drift":             MUTED_COLOR,
    "none":                      MUTED_COLOR,
}


def chart_alert_timeline(fused: pd.DataFrame) -> alt.Chart:
    """Daily flagged session counts by tier — line chart."""
    df = fused[fused["split"] == "test"].copy()
    df["date"] = pd.to_datetime(df["session_start"]).dt.date
    df["tier_label"] = df.apply(
        lambda r: "Tier 1" if r["fusion_tier"] == 1 else ("Tier 2" if r["fusion_tier"] == 2 else "Tier 3"),
        axis=1,
    )
    df = df[df["fused_risk_score"] >= 50]
    daily = df.groupby(["date", "tier_label"]).size().reset_index(name="count")
    daily["date"] = pd.to_datetime(daily["date"])

    return (
        alt.Chart(daily, title="Alert Volume Over Time (test split, flagged sessions)")
        .mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2)
        .encode(
            x=alt.X("date:T", title="Date", axis=alt.Axis(format="%b %d", labelAngle=-30)),
            y=alt.Y("count:Q", title="Flagged Sessions", stack="zero"),
            color=alt.Color("tier_label:N", scale=TIER_COLOR_SCALE, title="Tier"),
            tooltip=[
                alt.Tooltip("date:T", title="Date", format="%Y-%m-%d"),
                alt.Tooltip("tier_label:N", title="Tier"),
                alt.Tooltip("count:Q", title="Sessions"),
            ],
        )
        .properties(height=220)
        .configure(**_ALT_CONFIG)
    )


def chart_attack_distribution(cases: pd.DataFrame) -> alt.Chart:
    """Attack-type session count — horizontal bar chart."""
    df = cases[cases["split"] == "test"].copy()
    df = df[df["is_malicious"] == True]
    agg = (
        df.groupby("predicted_attack_type")["session_count"]
        .sum()
        .reset_index()
        .sort_values("session_count", ascending=True)
    )
    agg["color"] = agg["predicted_attack_type"].map(ATK_COLORS).fillna(MUTED_COLOR)
    agg["mitre"] = agg["predicted_attack_type"].map(lambda x: MITRE.get(x, ("",""))[0])
    agg["label"] = agg["predicted_attack_type"].str.replace("_", " ").str.title()

    return (
        alt.Chart(agg, title="Attack-Type Session Distribution (test split, malicious)")
        .mark_bar(cornerRadiusTopRight=3, cornerRadiusBottomRight=3)
        .encode(
            y=alt.Y("label:N", title=None, sort="-x"),
            x=alt.X("session_count:Q", title="Sessions"),
            color=alt.Color("label:N",
                            scale=alt.Scale(domain=agg["label"].tolist(),
                                            range=agg["color"].tolist()),
                            legend=None),
            tooltip=[
                alt.Tooltip("label:N",        title="Attack Type"),
                alt.Tooltip("mitre:N",        title="MITRE"),
                alt.Tooltip("session_count:Q", title="Sessions"),
            ],
        )
        .properties(height=220)
        .configure(**_ALT_CONFIG)
    )


def chart_score_distribution(fused: pd.DataFrame, split: str = "test") -> alt.Chart:
    """Fused risk score histogram with tier threshold lines."""
    df = fused[fused["split"] == split][["fused_risk_score", "is_malicious"]].copy()
    df["label"] = df["is_malicious"].map({True: "Malicious", False: "Normal"})

    hist = (
        alt.Chart(df)
        .mark_bar(opacity=0.7, binSpacing=0)
        .encode(
            x=alt.X("fused_risk_score:Q", bin=alt.Bin(maxbins=40),
                    title="Fused Risk Score", scale=alt.Scale(domain=[0, 100])),
            y=alt.Y("count():Q", title="Sessions", stack=None),
            color=alt.Color(
                "label:N",
                scale=alt.Scale(domain=["Malicious", "Normal"],
                                range=[TIER1_COLOR, ACCENT]),
                title="Session type",
            ),
            tooltip=[alt.Tooltip("fused_risk_score:Q", bin=True), "count():Q"],
        )
    )

    # Threshold lines
    thresholds = pd.DataFrame([
        {"score": 50, "label": "Alert (50)"},
        {"score": 90, "label": "Tier 1 (90)"},
    ])
    lines = (
        alt.Chart(thresholds)
        .mark_rule(strokeDash=[5, 3], strokeWidth=1.5)
        .encode(
            x="score:Q",
            color=alt.Color("label:N",
                            scale=alt.Scale(domain=["Alert (50)", "Tier 1 (90)"],
                                            range=[TIER2_COLOR, TIER1_COLOR]),
                            title="Threshold"),
            tooltip=["label:N"],
        )
    )

    return (
        (hist + lines)
        .properties(title="Fused Risk Score Distribution", height=220)
        .configure(**_ALT_CONFIG)
    )


def render_drift_gauge(level: str, color: str, description: str):
    """HTML/SVG drift status gauge."""
    pct_map = {"NONE": 15, "MODERATE": 55, "SIGNIFICANT": 90, "UNKNOWN": 0}
    pct = pct_map.get(level, 0)

    # SVG arc gauge (semicircle)
    r = 50
    cx, cy = 60, 60
    stroke_width = 10
    # Background arc: full 180°
    # Foreground arc: pct/100 × 180°
    # Draw using strokeDasharray trick on a circle
    circumference = 3.14159 * r  # half-circle circumference ≈ π*r
    dash = pct / 100 * circumference
    gap  = circumference - dash

    label_class = f"drift-{level.lower()}" if level in ("NONE", "MODERATE", "SIGNIFICANT") else "drift-none"

    st.markdown(f"""
<div style="display:flex;align-items:center;gap:20px;padding:12px 16px;
     background:{BG_CARD};border:1px solid {BORDER};border-radius:10px;">
  <svg width="120" height="70" viewBox="0 0 120 70" style="overflow:visible">
    <!-- Background arc -->
    <path d="M10,60 A50,50 0 0,1 110,60" fill="none"
          stroke="#1F2937" stroke-width="{stroke_width}" stroke-linecap="round"/>
    <!-- Foreground arc -->
    <path d="M10,60 A50,50 0 0,1 110,60" fill="none"
          stroke="{color}" stroke-width="{stroke_width}" stroke-linecap="round"
          stroke-dasharray="{dash:.1f} {gap*10:.1f}"
          opacity="0.9"/>
    <!-- Label -->
    <text x="60" y="68" text-anchor="middle" font-size="11" fill="#9CA3AF"
          font-family="Inter,sans-serif">DRIFT</text>
  </svg>
  <div>
    <div style="margin-bottom:6px;">
      <span class="{label_class}">{level}</span>
    </div>
    <div style="font-size:0.72rem;color:#6B7280;max-width:260px;line-height:1.4;">
      {description}
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# UI Sections
# ─────────────────────────────────────────────────────────────────────────────

def render_header_bar(active_cases: int, tier1_count: int):
    st.markdown(f"""
<div class="argus-header">
  <div class="argus-logo">
    <span style="font-size:2rem;">🛡️</span>
    <div>
      <div class="argus-logo-text">ARGUS</div>
      <div class="argus-logo-sub">Adaptive Risk &amp; Graph-based Unified Security</div>
    </div>
  </div>
  <div class="argus-header-right">
    <div class="status-chip">
      <div class="status-dot"></div>
      Monitoring Active
    </div>
    <div class="header-alert-count">
      Active Alerts &nbsp;<span>{active_cases}</span>
    </div>
    <div class="header-alert-count" style="color:#6B7280;font-size:0.72rem;">
      Tier 1: <span style="color:{TIER1_COLOR};font-size:0.9rem;">{tier1_count}</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


def render_kpi_cards(cases: pd.DataFrame, fused: pd.DataFrame,
                     results: dict, drift_level: str, drift_color: str, split_filter: str = "test"):
    target_cases  = cases if split_filter == "all" else cases[cases["split"] == split_filter]
    flagged       = target_cases[target_cases["max_fused_risk_score"] >= 50]
    tier1_count   = int((flagged["tier_1_count"] > 0).sum())
    
    target_sessions = fused if split_filter == "all" else fused[fused["split"] == split_filter]
    norm_target   = target_sessions[~target_sessions["is_malicious"]]
    fp_count      = int((norm_target["fused_risk_score"] >= 50).sum())
    fp_rate       = fp_count / max(len(norm_target), 1)
    
    mal_target    = target_sessions[target_sessions["is_malicious"]]
    tp_count      = int((mal_target["fused_risk_score"] >= 50).sum())
    fn_count      = len(mal_target) - tp_count
    
    prec = tp_count / max(tp_count + fp_count, 1) if (tp_count + fp_count) > 0 else 0.0
    rec  = tp_count / max(tp_count + fn_count, 1) if (tp_count + fn_count) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

    drift_class = {"NONE": "green", "MODERATE": "amber", "SIGNIFICANT": "red"}.get(drift_level, "muted")
    drift_icon  = {"NONE": "✅", "MODERATE": "⚠️", "SIGNIFICANT": "🚨"}.get(drift_level, "ℹ️")

    st.markdown(f"""
<div class="kpi-row">
  <div class="kpi-card accent">
    <div class="kpi-label">Sessions Monitored</div>
    <div class="kpi-value">{len(target_sessions):,}</div>
    <div class="kpi-sub">{split_filter} split</div>
  </div>
  <div class="kpi-card red">
    <div class="kpi-label">Active Tier 1 Alerts</div>
    <div class="kpi-value" style="color:{TIER1_COLOR};">{tier1_count}</div>
    <div class="kpi-sub">hard-rule triggered</div>
  </div>
  <div class="kpi-card amber">
    <div class="kpi-label">Normal FP Rate</div>
    <div class="kpi-value" style="color:{TIER2_COLOR if fp_rate > 0.01 else TIER3_COLOR};">{fp_rate:.2%}</div>
    <div class="kpi-sub">{fp_count} / {len(norm_target):,} normal sessions</div>
  </div>
  <div class="kpi-card green">
    <div class="kpi-label">Detection Recall</div>
    <div class="kpi-value" style="color:{TIER3_COLOR};">{rec:.3f}</div>
    <div class="kpi-sub">Precision {prec:.3f} · F1 {f1:.3f}</div>
  </div>
  <div class="kpi-card {drift_class}">
    <div class="kpi-label">Drift Status</div>
    <div class="kpi-value" style="color:{drift_color};font-size:1.1rem;">{drift_icon} {drift_level}</div>
    <div class="kpi-sub">drift monitor</div>
  </div>
</div>
""", unsafe_allow_html=True)


def build_queue_display(view_cases: pd.DataFrame, feedback_ids: set) -> pd.DataFrame:
    """Build the styled display DataFrame for the alert queue."""
    def tier_label(row):
        if row["tier_1_count"] > 0: return "T1 — CRITICAL"
        if row["tier_2_count"] > 0: return "T2 — HIGH"
        return "T3 — MEDIUM"

    df = view_cases[[
        "case_id", "entity_id", "entity_type", "entity_dept",
        "predicted_attack_type", "max_fused_risk_score", "session_count",
        "first_seen", "last_seen", "tier_1_count", "tier_2_count",
    ]].copy()

    df["Tier"]         = df.apply(tier_label, axis=1)
    df["Risk"]         = df["max_fused_risk_score"].astype(int)
    df["Entity"]       = df["entity_id"]
    df["Dept"]         = df["entity_dept"]
    df["Attack Type"]  = df["predicted_attack_type"].str.replace("_", " ").str.title()
    df["MITRE"]        = df["predicted_attack_type"].map(lambda x: MITRE.get(x, ("",""))[0])
    df["Sessions"]     = df["session_count"].astype(int)
    df["First Seen"]   = pd.to_datetime(df["first_seen"]).dt.strftime("%m-%d %H:%M")
    df["✓"]            = df["case_id"].apply(lambda x: "✅" if x in feedback_ids else "")

    return df[["✓", "Tier", "Risk", "Entity", "Dept", "Attack Type", "MITRE", "Sessions", "First Seen"]]


# ─────────────────────────────────────────────────────────────────────────────
# Drill-down renderer
# ─────────────────────────────────────────────────────────────────────────────

def render_drilldown(sel_case, fused: pd.DataFrame, raw: pd.DataFrame):
    case_id  = sel_case["case_id"]
    eid      = sel_case["entity_id"]
    all_ids  = list(sel_case["all_session_ids"])

    case_sessions = fused[fused["session_id"].isin(all_ids)]
    if len(case_sessions) == 0:
        st.warning("No session data for this case.")
        return

    anchor = case_sessions.loc[case_sessions["fused_risk_score"].idxmax()]
    atk    = sel_case.get("predicted_attack_type", "none")
    mitre_code, mitre_name = MITRE.get(atk, ("", ""))
    risk   = int(sel_case.get("max_fused_risk_score", 0))
    t1     = int(sel_case.get("tier_1_count", 0))
    t2     = int(sel_case.get("tier_2_count", 0))
    tier   = "T1 — CRITICAL" if t1 > 0 else ("T2 — HIGH" if t2 > 0 else "T3 — MEDIUM")
    tier_cls = "tier-t1" if t1 > 0 else ("tier-t2" if t2 > 0 else "tier-t3")
    rc     = risk_color(risk)
    atk_display = atk.replace("_", " ").title()

    # ── Header badges
    st.markdown(f"""
<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
  <span class="{tier_cls}">{tier}</span>
  <span class="atk-tag">{atk_display}</span>
  {"<span class='mitre-chip'>" + mitre_code + "</span>" if mitre_code else ""}
  <span style="font-family:'JetBrains Mono',monospace;font-size:1.2rem;font-weight:800;color:{rc};margin-left:auto;">
    {risk}<span style="font-size:0.65rem;color:#6B7280;">/100</span>
  </span>
</div>
""", unsafe_allow_html=True)

    # ── Case summary table
    st.markdown(f"""
<table class="case-table">
  <tr><td>Entity</td>         <td><code>{eid}</code> &nbsp;({sel_case.get('entity_type','?')} / {sel_case.get('entity_dept','?')})</td></tr>
  <tr><td>Case ID</td>        <td><code>{case_id}</code></td></tr>
  <tr><td>MITRE Technique</td><td><code>{mitre_code}</code> — {mitre_name}</td></tr>
  <tr><td>Sessions</td>       <td>{int(sel_case.get('session_count',1))} ({int(sel_case.get('suppressed_count',0))} suppressed)</td></tr>
  <tr><td>Window</td>         <td>{str(sel_case.get('first_seen',''))[:19]} → {str(sel_case.get('last_seen',''))[:19]}</td></tr>
</table>
""", unsafe_allow_html=True)

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    # ── Analyst note
    st.markdown("<div class='section-title'>Analyst Note</div>", unsafe_allow_html=True)
    try:
        note_text = generate_note_for_session(anchor, fused)
    except Exception as e:
        note_text = f"[Error generating note: {e}]"
    st.markdown(
        '<div class="note-box">' + note_text.replace("\n", "<br>") + "</div>",
        unsafe_allow_html=True,
    )

    # ── Feedback
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>Verdict</div>", unsafe_allow_html=True)
    note_input = st.text_input("Analyst comment (optional)", key=f"note_{case_id}",
                               placeholder="Add context or notes...")
    fb1, fb2 = st.columns(2)
    with fb1:
        if st.button("✅ True Positive", key=f"tp_{case_id}", type="primary", use_container_width=True):
            write_feedback(case_id, eid, atk, "TRUE_POSITIVE", note_input)
            st.success("Marked True Positive ✅")
    with fb2:
        if st.button("❌ False Positive", key=f"fp_{case_id}", use_container_width=True):
            write_feedback(case_id, eid, atk, "FALSE_POSITIVE", note_input)
            st.warning("Marked False Positive ❌")

    # ── Subgraph
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>Entity Subgraph</div>", unsafe_allow_html=True)
    with st.spinner("Building subgraph…"):
        try:
            g   = load_graph()
            sub = build_entity_subgraph(eid, g, raw, all_ids)
            fig = draw_subgraph(sub, title=f"{eid} — {sub.number_of_nodes()} nodes, {sub.number_of_edges()} edges")
            st.pyplot(fig, width='stretch')
            st.caption("🔴 Target entity · 🟠 Co-using entity · 🔵 Device · 🟢 Resource")
        except Exception as e:
            st.error(f"Subgraph error: {e}")

    # ── Session table
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>Session Details</div>", unsafe_allow_html=True)
    show_cols = [
        "session_id", "fusion_tier", "fused_risk_score", "transformer_score",
        "iforest_score", "hard_rule_detail", "fp_mismatch", "geo_velocity_violation",
        "event_count", "failure_ratio", "new_device_edge_count", "lateral_hop_score",
    ]
    avail = [c for c in show_cols if c in case_sessions.columns]
    st.dataframe(
        case_sessions[avail].sort_values("fused_risk_score", ascending=False),
        width="stretch",
        column_config={
            "fused_risk_score": st.column_config.ProgressColumn(
                "Risk Score", min_value=0, max_value=100, format="%d"
            ),
            "session_id": st.column_config.TextColumn("Session ID", width="medium"),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main app
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # Inject CSS
    st.markdown(CSS, unsafe_allow_html=True)

    cases, fused, raw, results, drift_baseline = load_data()
    ensure_feedback_store()

    drift_level, drift_color, drift_desc = get_drift_level(drift_baseline, fused)

    # ── Sidebar — filters only ────────────────────────────────────────────────
    with st.sidebar:
        st.markdown(f"<div style='font-size:1.3rem;font-weight:700;color:{ACCENT};letter-spacing:0.1em;'>🛡️ ARGUS</div>", unsafe_allow_html=True)
        st.caption("Adaptive Risk & Graph-based Unified Security")
        st.divider()

        st.markdown("<div class='section-title'>Filters</div>", unsafe_allow_html=True)
        split_filter = st.selectbox("Data split", ["test", "train", "all"], index=0)

        all_types = ["All"] + sorted(
            cases[cases["split"] == split_filter if split_filter != "all" else cases.index.notna()]
            ["predicted_attack_type"].dropna().unique().tolist()
        )
        atk_filter = st.selectbox("Attack type", all_types, index=0)

        tier_options = {"All tiers": None, "Tier 1 only": 1, "Tier 2 only": 2}
        tier_sel     = st.selectbox("Tier", list(tier_options.keys()), index=0)

        st.divider()

        # System metrics strip
        ov = results["overall"]
        st.markdown(f"""
<div style="font-size:0.72rem;color:#6B7280;line-height:1.8;">
  <div>Precision &nbsp;<b style="color:#E5E7EB;">{ov['precision']:.4f}</b></div>
  <div>Recall &nbsp;&nbsp;&nbsp;<b style="color:#E5E7EB;">{ov['recall']:.4f}</b></div>
  <div>F1 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b style="color:#E5E7EB;">{ov['f1']:.4f}</b></div>
</div>
""", unsafe_allow_html=True)

    # ── Apply filters ─────────────────────────────────────────────────────────
    view_cases = cases.copy()
    if split_filter != "all":
        view_cases = view_cases[view_cases["split"] == split_filter]
    if atk_filter != "All":
        view_cases = view_cases[view_cases["predicted_attack_type"] == atk_filter]
    if tier_options[tier_sel] == 1:
        view_cases = view_cases[view_cases["tier_1_count"] > 0]
    elif tier_options[tier_sel] == 2:
        view_cases = view_cases[(view_cases["tier_1_count"] == 0) & (view_cases["tier_2_count"] > 0)]

    view_cases = view_cases.sort_values("max_fused_risk_score", ascending=False).reset_index(drop=True)

    # ── Computed stats for header ─────────────────────────────────────────────
    target_cases = cases if split_filter == "all" else cases[cases["split"] == split_filter]
    flagged      = target_cases[target_cases["max_fused_risk_score"] >= 50]
    tier1_total  = int((flagged["tier_1_count"] > 0).sum())

    # ── Header bar ────────────────────────────────────────────────────────────
    render_header_bar(active_cases=len(flagged), tier1_count=tier1_total)

    # ── KPI row ───────────────────────────────────────────────────────────────
    render_kpi_cards(cases, fused, results, drift_level, drift_color, split_filter)

    # ── Main tabs ─────────────────────────────────────────────────────────────
    tab_queue, tab_analytics, tab_feedback = st.tabs([
        "🚨  Alert Queue",
        "📊  Analytics",
        "📝  Feedback Log",
    ])

    # ═════════════════════════════════════════════════════════════════════════
    # TAB 1 — Alert Queue  (two columns: queue | drill-down)
    # ═════════════════════════════════════════════════════════════════════════
    with tab_queue:
        feedback_df  = load_feedback()
        reviewed_ids = set(feedback_df["case_id"].tolist()) if len(feedback_df) > 0 else set()

        queue_display = build_queue_display(view_cases, reviewed_ids)

        col_queue, col_drill = st.columns([3, 2], gap="medium")

        with col_queue:
            st.markdown(
                f"<div class='section-title'>Risk-Ranked Alert Queue &nbsp;"
                f"<span style='color:#E5E7EB;font-weight:700;'>{len(view_cases)}</span> cases</div>",
                unsafe_allow_html=True,
            )

            # Clickable dataframe (Streamlit ≥1.35 multi-row selection)
            event = st.dataframe(
                queue_display,
                width="stretch",
                height=520,
                selection_mode="multi-row",
                on_select="rerun",
                key="alert_queue_table",
                column_config={
                    "Risk": st.column_config.ProgressColumn(
                        "Risk",
                        min_value=0, max_value=100, format="%d",
                        help="Fused risk score 0–100"
                    ),
                    "✓": st.column_config.TextColumn("✓", width="small"),
                    "Tier": st.column_config.TextColumn("Tier", width="medium"),
                },
            )

            selected_rows = event.selection.rows if hasattr(event, "selection") else []

        with col_drill:
            st.markdown(
                "<div class='section-title'>Entity Drill-Down</div>",
                unsafe_allow_html=True,
            )

            if selected_rows:
                for i, sel_idx in enumerate(selected_rows):
                    sel_case = view_cases.iloc[sel_idx]
                    st.markdown(
                        f"<div style='font-size:0.75rem;color:#6B7280;margin-bottom:8px;'>"
                        f"Selected: <code style='color:{ACCENT};'>{sel_case['case_id']}</code></div>",
                        unsafe_allow_html=True,
                    )
                    render_drilldown(sel_case, fused, raw)
                    if i < len(selected_rows) - 1:
                        st.markdown("<hr style='border:1px solid #1F2937; margin: 30px 0;'/>", unsafe_allow_html=True)
            else:
                st.markdown("""
<div class="drill-panel-empty">
  <div style="font-size:2rem;margin-bottom:12px;">👆</div>
  <div style="font-size:0.85rem;color:#4B5563;">
    Click a row in the alert queue<br>to open the entity drill-down
  </div>
</div>
""", unsafe_allow_html=True)

    # ═════════════════════════════════════════════════════════════════════════
    # TAB 2 — Analytics
    # ═════════════════════════════════════════════════════════════════════════
    with tab_analytics:
        st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

        # Row 1: Timeline | Attack distribution
        row1_left, row1_right = st.columns(2, gap="medium")
        with row1_left:
            try:
                st.altair_chart(chart_alert_timeline(fused), width='stretch')
            except Exception as e:
                st.error(f"Timeline chart error: {e}")

        with row1_right:
            try:
                st.altair_chart(chart_attack_distribution(cases), width='stretch')
            except Exception as e:
                st.error(f"Distribution chart error: {e}")

        # Row 2: Score distribution | Drift gauge
        row2_left, row2_right = st.columns(2, gap="medium")
        with row2_left:
            try:
                split_sel = st.radio(
                    "Split for score distribution",
                    ["test", "train"],
                    horizontal=True,
                    key="score_dist_split",
                )
                st.altair_chart(chart_score_distribution(fused, split_sel), width='stretch')
            except Exception as e:
                st.error(f"Score distribution error: {e}")

        with row2_right:
            st.markdown("<div class='section-title'>Drift Status</div>", unsafe_allow_html=True)
            render_drift_gauge(drift_level, drift_color, drift_desc)

            st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

            # Mini per-attack-type recall table
            st.markdown("<div class='section-title'>Per-Class Detection Recall</div>", unsafe_allow_html=True)
            if "per_class_recall" in results:
                recall_rows = []
                for atk, m in results["per_class_recall"].items():
                    mitre_c = MITRE.get(atk, ("",""))[0]
                    recall_rows.append({
                        "Attack Type": atk.replace("_", " ").title(),
                        "MITRE": mitre_c,
                        "Recall": float(m.get("recall", 0)),
                        "Flagged": int(m.get("flagged", 0)),
                        "Total": int(m.get("total", 0)),
                    })
                if recall_rows:
                    rdf = pd.DataFrame(recall_rows).sort_values("Recall")
                    st.dataframe(
                        rdf,
                        width="stretch",
                        hide_index=True,
                        column_config={
                            "Recall": st.column_config.ProgressColumn(
                                "Recall", min_value=0, max_value=1, format="%.3f"
                            ),
                        },
                    )


    # ═════════════════════════════════════════════════════════════════════════
    # TAB 3 — Feedback
    # ═════════════════════════════════════════════════════════════════════════
    with tab_feedback:
        st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
        feedback_df = load_feedback()

        if len(feedback_df) > 0:
            tp = (feedback_df["verdict"] == "TRUE_POSITIVE").sum()
            fp = (feedback_df["verdict"] == "FALSE_POSITIVE").sum()

            fb_c1, fb_c2, fb_c3 = st.columns(3)
            with fb_c1:
                st.metric("True Positives",  tp)
            with fb_c2:
                st.metric("False Positives", fp)
            with fb_c3:
                if tp + fp > 0:
                    st.metric("Analyst Precision", f"{tp / (tp + fp):.1%}")

            st.divider()
            st.dataframe(feedback_df, width='stretch', hide_index=True)

            st.download_button(
                "⬇️ Export feedback CSV",
                feedback_df.to_csv(index=False),
                file_name="argus_analyst_feedback.csv",
                mime="text/csv",
            )
        else:
            st.info(
                "No feedback submitted yet. Click a row in the Alert Queue → "
                "scroll to Verdict → submit a TP or FP verdict."
            )


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
