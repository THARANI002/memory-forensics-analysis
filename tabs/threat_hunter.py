"""
Threat Hunter
=============
Filter every detection by severity, technique and confidence, then drill
into evidence, related IOCs and remediation guidance.
"""

import streamlit as st

import ui


def render_threat_hunter():
    """Render the Threat Hunter view."""
    ui.md(ui.page_header("Threat hunter", "Filter detections and drill into the evidence behind each one.", "radar"))

    if not st.session_state.analysis_complete:
        ui.md(ui.empty_state("radar", "Nothing to hunt yet", "Complete an analysis first to view threat detections."))
        return

    detections = [d for d in st.session_state.threat_detections if d.detected]
    c1, c2, c3 = st.columns(3, gap="medium")
    with c1:
        severity_filter = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"],
                                         default=["Critical", "High", "Medium"])
    with c2:
        technique_filter = st.multiselect("Technique", sorted({d.technique for d in detections}), default=[])
    with c3:
        min_confidence = st.slider("Minimum confidence", 0, 100, 30)

    filtered = [
        d for d in detections
        if (not severity_filter or d.severity.capitalize() in severity_filter)
        and (not technique_filter or d.technique in technique_filter)
        and d.confidence >= min_confidence
    ]

    ui.md(ui.section(f"{len(filtered)} detection{'s' if len(filtered) != 1 else ''}", f"of {len(detections)} total"))
    if not filtered:
        ui.md(ui.empty_state("check", "No threats match these filters", "Loosen the severity or confidence filters to see more."))
        return

    for i, d in enumerate(filtered):
        ui.md(ui.finding_card(
            d.severity, d.technique, d.description,
            [ui.chip(d.technique_id, "flag"), ui.chip(d.tactic, "layers"),
             ui.chip(f"{d.confidence:.0f}% confidence", "activity")], i))
        with st.expander("Evidence, indicators and remediation"):
            if d.evidence:
                for ev in d.evidence[:5]:
                    st.json(ev, expanded=False)
                if len(d.evidence) > 5:
                    st.caption(f"+ {len(d.evidence) - 5} more evidence items")
            if d.iocs:
                ui.md(ui.data_table([{"Type": ui.Raw(ui.badge(x.get("type", ""), "info")), "Value": x.get("value", "")}
                                     for x in d.iocs], caption="Related indicators", mono=("Value",)))
            if d.remediation:
                ui.md(ui.card(f"<h4>Remediation</h4><p>{ui.esc(d.remediation)}</p>"))
