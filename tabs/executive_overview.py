"""
Overview
========
Verdict ring, headline metrics, key facts, severity mix, top findings
and recommended next steps for the loaded case.
"""

import streamlit as st
import plotly.graph_objects as go

import ui


def render_executive_overview():
    """Render the Overview view."""
    ui.md(ui.page_header("Overview", "Verdict, key facts and the findings that matter most.", "grid"))

    report = st.session_state.report_data
    if not st.session_state.analysis_complete or report is None:
        ui.md(ui.empty_state("shield", "No analysis loaded",
                             "Load the demo scenario or upload a memory dump from the sidebar to see results."))
        return

    verdict = (report.executive_verdict or "CLEAN").upper()
    tone = ui.tone_for_verdict(verdict)

    left, right = st.columns([5, 7], gap="large")
    with left:
        ui.md(ui.card(ui.score_ring(report.threat_score, verdict, tone)))
    with right:
        ui.md(ui.stat_grid([
            ui.stat_card("Detections", report.total_threats, tone, "Distinct techniques fired", "alert", 0),
            ui.stat_card("Confidence", f"{report.confidence_score:.0f}%", "blue", "Evidence strength", "check", 1),
            ui.stat_card("IOCs", report.total_iocs, "purple", "Indicators extracted", "fingerprint", 2),
            ui.stat_card("Memory health", f"{report.memory_health_score:.0f}%",
                         "ok" if report.memory_health_score >= 70 else "high" if report.memory_health_score >= 40 else "critical", "Higher is better", "cpu", 3),
        ], 2))

    ui.md(ui.section("Key facts"))
    c1, c2 = st.columns([7, 5], gap="large")
    with c1:
        ui.md(ui.card(f"<h4>Executive summary</h4><p>{ui.esc(report.executive_summary)}</p>"))
    with c2:
        ui.md(ui.card(ui.kv([
            ("Most dangerous process", ui.Raw(f'<code>{ui.esc(report.most_dangerous_process)}</code>')),
            ("Most dangerous IP", ui.Raw(f'<code>{ui.esc(report.most_dangerous_ip)}</code>')),
            ("Top technique", report.top_mitre_technique),
        ])))

    ui.md(ui.section("Severity mix", "How findings are distributed"))
    counts = [("Critical", report.critical_count, "critical"), ("High", report.high_count, "high"),
              ("Medium", report.medium_count, "medium"), ("Low", report.low_count, "low")]
    if sum(c for _, c, _ in counts) == 0:
        ui.md(ui.empty_state("check", "All clear", "No detections were raised for this snapshot."))
    else:
        g1, g2 = st.columns([4, 6], gap="large", vertical_alignment="center")
        with g1:
            fig = go.Figure(go.Pie(
                labels=[n for n, _, _ in counts], values=[c for _, c, _ in counts], hole=0.72, sort=False,
                marker=dict(colors=[ui.tone_hex(t) for _, _, t in counts], line=dict(width=0)),
                textinfo="none", hovertemplate="%{label}: %{value}<extra></extra>"))
            fig.add_annotation(text=f"<b>{sum(c for _, c, _ in counts)}</b>", showarrow=False, font=dict(size=34, color=ui.tone_hex("neutral")))
            ui.style_figure(fig, 250)
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
        with g2:
            ui.md(ui.severity_bar(counts))

    ui.md(ui.section("Top findings", "Highest-impact detections first"))
    if report.threat_findings:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        top = sorted(report.threat_findings, key=lambda f: (order.get(str(f.get("severity", "")).lower(), 9), -float(f.get("confidence", 0) or 0)))[:5]
        ui.md("".join(ui.finding_card(
            f.get("severity", "info"), f.get("title", ""), (f.get("description") or "")[:180],
            [ui.chip(f"{float(f.get('confidence', 0) or 0):.0f}% confidence", "activity"), ui.chip(str(f.get("engine", "heuristic")), "cpu")], i)
            for i, f in enumerate(top)))
        st.button("View all findings", icon=":material/arrow_forward:", on_click=ui.goto("hunter"), key="ov_all")
    else:
        ui.md(ui.empty_state("check", "No findings", "Nothing suspicious was detected."))

    if report.recommendations:
        ui.md(ui.section("Recommended next steps"))
        items = "".join(f"<li><span>{i + 1}</span><div>{ui.esc(r)}</div></li>" for i, r in enumerate(report.recommendations[:6]))
        ui.md(ui.card(f'<ul class="reclist">{items}</ul>'))
