"""
MITRE ATT&CK
============
Detections mapped to ATT&CK techniques: heatmap, per-tactic summary and
an ATT&CK Navigator layer export.
"""

import json

import plotly.express as px
import streamlit as st

import ui
from config.settings import REPORTS_DIR


def render_mitre_attack():
    """Render the ATT&CK view."""
    ui.md(ui.page_header("ATT&CK mapping", "Every finding mapped to adversary tactics and techniques.", "grid"))

    if not st.session_state.mitre_mappings:
        if getattr(st.session_state, "is_static_scan", False):
            ui.md(ui.empty_state("box", "Static scan complete",
                                 "Dynamic ATT&CK mapping needs execution tracing from a full memory dump (.raw, .mem)."))
        else:
            ui.md(ui.empty_state("grid", "No mappings available", "Run threat detection to map findings to ATT&CK."))
        return

    mapper, mappings = st.session_state.mitre_mapper, st.session_state.mitre_mappings
    heat = mapper.generate_heatmap_data(mappings)
    tactics = mapper.get_tactic_summary(mappings)
    ui.md(ui.stat_grid([
        ui.stat_card("Techniques", heat["technique_count"], "blue", "Unique techniques", "grid", 0),
        ui.stat_card("Tactics", len(tactics), "purple", "Kill-chain stages touched", "layers", 1),
        ui.stat_card("Detections", heat["total_detections"], "orange", "Mapped findings", "alert", 2),
    ], 3))

    ui.md(ui.section("Kill chain", "Tactics observed in this snapshot, in attack order"))
    ui.md(ui.kill_chain(mapper.TACTICS_ORDER, {t: d["technique_count"] for t, d in tactics.items()}))

    ui.md(ui.section("Technique heatmap", "Bubble size and colour show confidence"))
    rows = heat["data"]
    if rows:
        fig = px.scatter(rows, x="tactic", y="technique_name", size="score", color="score", size_max=34,
                         hover_data=["technique_id", "score"],
                         color_continuous_scale=[ui.tone_hex("low"), ui.tone_hex("medium"), ui.tone_hex("high"), ui.tone_hex("critical")])
        ui.style_figure(fig, max(340, 38 * len(rows) + 120))
        fig.update_xaxes(tickangle=-30, title=None)
        fig.update_yaxes(title=None, autorange="reversed")
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    ui.md(ui.section("Tactic summary"))
    ui.md(ui.data_table([
        {"Tactic": ui.Raw(ui.badge(t, "info")), "Techniques": ", ".join(d["techniques"]), "Count": d["technique_count"],
         "Events": d["total_events"], "Max score": ui.Raw(ui.meter(d["highest_score"], "high"))}
        for t, d in tactics.items()], caption="Techniques grouped by tactic", mono=("Techniques",)))

    ui.md(ui.section("ATT&CK Navigator", "Import the layer at mitre-attack.github.io/attack-navigator"))
    if st.button("Export Navigator layer", icon=":material/download:", key="nav_export"):
        layer = mapper.generate_attack_navigator_layer(mappings)
        path = REPORTS_DIR / "mitre_navigator_layer.json"
        with open(path, "w") as f:
            json.dump(layer, f, indent=2)
        st.success(f"Layer exported to {path}")
