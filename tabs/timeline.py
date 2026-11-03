"""
Timeline
========
Chronological reconstruction of process, network and service events.
"""

import plotly.express as px
import streamlit as st

import ui


def render_timeline():
    """Render the Timeline view."""
    ui.md(ui.page_header("Timeline", "What happened, and in what order.", "clock"))

    if not st.session_state.timeline:
        if getattr(st.session_state, "is_static_scan", False):
            ui.md(ui.empty_state("box", "Static scan complete",
                                 "Timeline reconstruction needs timestamped process and network data from a full memory dump."))
        else:
            ui.md(ui.empty_state("clock", "No timeline data", "Run an analysis to reconstruct events."))
        return

    timeline = st.session_state.timeline
    summary = st.session_state.timeline_builder.get_timeline_summary()
    categories = summary.get("by_category", {})
    sig = summary.get("by_significance", {})
    ui.md(ui.stat_grid([
        ui.stat_card("Events", summary.get("total_events", 0), "blue", "Reconstructed", "clock", 0),
        ui.stat_card("Categories", len(categories), "purple", "Event types", "layers", 1),
        ui.stat_card("Critical", sig.get("critical", 0), "critical", "Highest significance", "alert", 2),
    ], 3))

    ui.md(ui.section("Event distribution"))
    cats = [{"Category": c, "Count": n} for c, n in categories.items()]
    if cats:
        fig = px.bar(cats, x="Category", y="Count", color_discrete_sequence=[ui.tone_hex("info")])
        fig.update_traces(marker_cornerradius=8, hovertemplate="%{x}: %{y}<extra></extra>")
        ui.style_figure(fig, 260)
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    ui.md(ui.section("Event stream", "Evidence of activity, in chronological order"))
    view = st.segmented_control("Show", ["Notable", "All events"], default="Notable", key="tl_view",
                                label_visibility="collapsed")
    sig = lambda e: str(e.significance).lower()  # noqa: E731
    if view == "All events":
        stream = list(timeline)
    else:
        stream = [e for e in timeline if sig(e) in {"critical", "high"}]
        if not stream:  # nothing severe: fall back to everything above routine
            stream = [e for e in timeline if sig(e) in {"critical", "high", "medium"}]
    ui.md(ui.timeline_view([
        {"time": e.timestamp, "title": f"{e.process_name or e.event_type}" + (f" · PID {e.process_id}" if e.process_id is not None else ""),
         "sig": e.significance, "category": e.category, "desc": e.description[:200]} for e in stream]))
    with st.expander("View as table"):
        ui.md(ui.data_table([
            {"Time": e.timestamp, "Type": e.event_type, "Category": ui.Raw(ui.badge(e.category, "info")),
             "Process": e.process_name or "N/A", "PID": str(e.process_id) if e.process_id is not None else "N/A",
             "Significance": ui.Raw(ui.badge(e.significance, ui.sev_tone(e.significance))),
             "Description": e.description[:140]} for e in timeline],
            caption="Reconstructed event timeline", mono=("Time", "PID")))
