"""
IOC Center
==========
Extracted indicators of compromise with search, type filtering,
confidence meters and export to JSON / CSV / STIX 2.1 / OpenIOC.
"""

import plotly.express as px
import streamlit as st

import ui
from config.settings import IOCS_DIR


def render_ioc_center():
    """Render the IOC Center view."""
    ui.md(ui.page_header("IOC center", "Indicators extracted from processes, network, services and strings.", "fingerprint"))

    if not st.session_state.iocs:
        if getattr(st.session_state, "is_static_scan", False):
            ui.md(ui.empty_state("box", "Static scan complete",
                                 "Advanced IOC extraction needs a full memory dump (.raw, .mem) to analyze active memory structures."))
        else:
            ui.md(ui.empty_state("fingerprint", "No IOCs yet", "Run an analysis to extract indicators."))
        return

    summary = st.session_state.ioc_engine.get_ioc_summary()
    ui.md(ui.stat_grid([
        ui.stat_card("Total IOCs", summary["total_iocs"], "blue", "All indicators", "fingerprint", 0),
        ui.stat_card("High confidence", summary["high_confidence"], "critical", "Act on these first", "alert", 1),
        ui.stat_card("Medium", summary["medium_confidence"], "medium", "Worth validating", "activity", 2),
        ui.stat_card("Low", summary["low_confidence"], "ok", "Context only", "layers", 3),
    ], 4))

    ui.md(ui.section("Distribution by type"))
    by_type = [{"Type": k, "Count": v} for k, v in summary["by_type"].items()]
    if by_type:
        fig = px.bar(by_type, x="Type", y="Count", color_discrete_sequence=[ui.tone_hex("info")])
        fig.update_traces(marker_cornerradius=8, hovertemplate="%{x}: %{y}<extra></extra>")
        ui.style_figure(fig, 280)
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    ui.md(ui.section("Indicators"))
    f1, f2 = st.columns([3, 2], gap="medium")
    with f1:
        query = st.text_input("Search", placeholder="Search value, source or type", label_visibility="collapsed")
    with f2:
        types = sorted({i.ioc_type for i in st.session_state.iocs})
        type_filter = st.multiselect("Type", types, placeholder="All types", label_visibility="collapsed")

    q = query.strip().lower()
    items = [i for i in st.session_state.iocs
             if (not type_filter or i.ioc_type in type_filter)
             and (not q or q in i.value.lower() or q in i.source.lower() or q in i.ioc_type.lower())]
    items.sort(key=lambda i: i.confidence, reverse=True)
    rows = [{"Type": ui.Raw(ui.badge(i.ioc_type, "info")), "Value": i.value,
             "Confidence": ui.Raw(ui.meter(i.confidence, "critical" if i.confidence >= 80 else "medium" if i.confidence >= 60 else "ok")),
             "Source": i.source} for i in items]
    ui.md(ui.data_table(rows, caption="Extracted indicators of compromise", mono=("Value",)))

    ui.md(ui.section("Export", "Share indicators with your tools"))
    engine, iocs = st.session_state.ioc_engine, st.session_state.iocs
    exports = [
        ("JSON", ":material/data_object:", engine.export_to_json, "iocs_export.json"),
        ("CSV", ":material/table:", engine.export_to_csv, "iocs_export.csv"),
        ("STIX 2.1", ":material/shield:", engine.export_to_stix, "iocs_export_stix.json"),
        ("OpenIOC", ":material/code:", engine.export_to_openioc, "iocs_openioc.xml"),
    ]
    cols = st.columns(4, gap="medium")
    for col, (label, ico, fn, fname) in zip(cols, exports):
        with col:
            if st.button(label, icon=ico, width="stretch", key=f"exp_{label}"):
                try:
                    path = fn(str(IOCS_DIR / fname), iocs)
                    st.success(f"Exported to {path}")
                except ImportError:
                    st.error("The stix2 library is not installed.")
                except Exception as e:
                    st.error(f"Export failed: {e}")
