"""
History
=======
Trends across every stored investigation: score over time, severity mix
per run and a full table, with CSV download.
"""

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import ui


def _compute_trend_direction(scores):
    """Compare the average of the first half vs second half of a series."""
    if len(scores) < 2:
        return "insufficient_data"
    mid = len(scores) // 2
    first_half = scores[:mid] or scores
    second_half = scores[mid:]
    first_avg = sum(first_half) / len(first_half)
    second_avg = sum(second_half) / len(second_half)
    if first_avg == 0:
        return "stable" if second_avg == 0 else "increasing"
    if second_avg > first_avg * 1.15:
        return "increasing"
    if second_avg < first_avg * 0.85:
        return "decreasing"
    return "stable"


_TREND = {
    "increasing": ("Rising", "critical"),
    "decreasing": ("Falling", "ok"),
    "stable": ("Stable", "info"),
    "insufficient_data": ("Not enough data", "neutral"),
}


def render_history_trends():
    """Render the History view."""
    ui.md(ui.page_header("History", "Threat trends across every stored investigation.", "trend"))

    db = st.session_state.get("db_manager")
    if db is None:
        ui.md(ui.empty_state("database", "Database unavailable", "Historical trends can't be loaded right now."))
        return
    try:
        history = db.get_report_history(limit=200)
    except Exception as e:
        st.error(f"Failed to load history: {e}")
        return
    if not history:
        ui.md(ui.empty_state("trend", "No history yet",
                             "Run an analysis (demo or a real memory dump) and it will appear here automatically."))
        return

    df = pd.DataFrame(history)
    df["generated_at_dt"] = pd.to_datetime(df["generated_at"], errors="coerce", utc=True)
    df = df.sort_values("generated_at_dt")
    scores = df["threat_score"].fillna(0).tolist()
    label, tone = _TREND[_compute_trend_direction(scores)]

    ui.md(ui.stat_grid([
        ui.stat_card("Investigations", len(df), "blue", "Stored runs", "database", 0),
        ui.stat_card("Avg threat score", f"{df['threat_score'].mean():.1f}", "orange", "Across all runs", "activity", 1),
        ui.stat_card("Trend", label, tone, "First vs. second half", "trend", 2),
        ui.stat_card("Critical findings", int(df["critical_count"].sum()), "critical", "All time", "alert", 3),
    ], 4))

    ui.md(ui.section("Threat score over time"))
    fig = go.Figure(go.Scatter(
        x=df["generated_at_dt"], y=df["threat_score"], mode="lines+markers", name="Threat score",
        line=dict(color=ui.tone_hex(tone if tone != "neutral" else "info"), width=3, shape="spline"),
        marker=dict(size=9), text=df["snapshot_name"], fill="tozeroy",
        fillcolor="rgba(10,132,255,0.08)", hovertemplate="<b>%{text}</b><br>Score: %{y}<br>%{x}<extra></extra>"))
    ui.style_figure(fig, 320)
    fig.update_yaxes(range=[0, max(100, float(df["threat_score"].max()) + 10)], title="Threat score")
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    ui.md(ui.section("Findings by severity"))
    labels = df["snapshot_name"].astype(str) + " (" + df["generated_at_dt"].dt.strftime("%Y-%m-%d") + ")"
    bar = go.Figure()
    for col, name, t in (("critical_count", "Critical", "critical"), ("high_count", "High", "high"),
                         ("medium_count", "Medium", "medium"), ("low_count", "Low", "low")):
        bar.add_trace(go.Bar(x=labels, y=df[col], name=name, marker=dict(color=ui.tone_hex(t), cornerradius=6)))
    bar.update_layout(barmode="stack")
    ui.style_figure(bar, 340, legend=True)
    st.plotly_chart(bar, width="stretch", config={"displayModeBar": False})

    ui.md(ui.section("All investigations"))
    table = df.sort_values("generated_at_dt", ascending=False)
    ui.md(ui.data_table([
        {"Date": r.generated_at_dt.strftime("%Y-%m-%d %H:%M") if pd.notna(r.generated_at_dt) else "",
         "Snapshot": r.snapshot_name, "Verdict": ui.Raw(ui.badge(r.verdict, ui.tone_for_verdict(r.verdict))),
         "Score": ui.Raw(ui.meter(r.threat_score, ui.tone_for_verdict(r.verdict))),
         "Threats": r.total_threats, "Critical": r.critical_count, "High": r.high_count,
         "IOCs": r.ioc_count, "Top technique": r.top_mitre_technique}
        for r in table.itertuples()], caption="Investigation history", mono=("Date",)))

    export = table[["generated_at_dt", "snapshot_name", "verdict", "threat_score", "confidence_score", "total_threats",
                    "critical_count", "high_count", "ioc_count", "top_mitre_technique"]]
    st.download_button("Download CSV", export.to_csv(index=False).encode("utf-8"),
                       file_name="investigation_history.csv", mime="text/csv", icon=":material/download:")
