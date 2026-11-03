"""
Reports
=======
Configure and generate the forensic report (PDF, HTML or JSON) with a live preview.
"""

import copy

import streamlit as st

import ui


def render_reports():
    """Render the Reports view."""
    ui.md(ui.page_header("Reports", "Configure, preview and export the final report.", "file"))

    report = st.session_state.report_data
    if not report:
        ui.md(ui.empty_state("file", "No report yet", "Run an analysis to generate report data."))
        return

    ui.md(ui.section("Configuration"))
    c1, c2 = st.columns(2, gap="large")
    with c1:
        report_title = st.text_input("Report title", value=report.title)
        analyst_name = st.text_input("Analyst name", value=report.analyst)
    with c2:
        case_number = st.text_input("Case number", value=report.case_number)
        include = st.multiselect(
            "Include sections",
            ["Executive Summary", "Threat Findings", "IOCs", "MITRE Mapping", "Timeline", "Process Tree", "Recommendations"],
            default=["Executive Summary", "Threat Findings", "IOCs", "MITRE Mapping", "Recommendations"])

    def _build_export():
        export = copy.deepcopy(report)
        export.title, export.analyst, export.case_number = report_title, analyst_name, case_number
        if "Executive Summary" not in include:
            export.executive_summary = ""
        if "Threat Findings" not in include:
            export.threat_findings = []
        if "IOCs" not in include:
            export.ioc_list = []
        if "MITRE Mapping" not in include:
            export.mitre_mapping = []
        if "Timeline" not in include:
            export.timeline_summary = {}
        if "Process Tree" not in include:
            export.process_tree_summary = {}
        if "Recommendations" not in include:
            export.recommendations = []
        return export

    ui.md(ui.section("Generate", "Reports are saved to the data directory"))
    cols = st.columns(3, gap="medium")
    formats = [("PDF", "pdf", ":material/picture_as_pdf:", "application/pdf"),
               ("HTML", "html", ":material/html:", "text/html"),
               ("JSON", "json", ":material/data_object:", "application/json")]
    for col, (label, fmt, ico, mime) in zip(cols, formats):
        with col:
            if st.button(f"Generate {label}", icon=ico, width="stretch", key=f"gen_{fmt}"):
                with st.spinner(f"Generating {label} report…"):
                    try:
                        paths = st.session_state.report_engine.generate_report(_build_export(), format=fmt)
                    except Exception as e:
                        paths = {}
                        st.error(f"{label} generation failed: {e}")
                if fmt in paths:
                    with open(paths[fmt], "rb") as f:
                        data = f.read()
                    st.success(f"{label} report ready.")
                    st.download_button(f"Download {label}", data, file_name=f"forensics_report.{fmt}", mime=mime,
                                       icon=":material/download:", key=f"dl_{fmt}")
                elif not paths:
                    pass
                else:
                    st.error(f"{label} generation failed.")

    ui.md(ui.section("Preview"))
    verdict = (report.executive_verdict or "CLEAN").upper()
    p1, p2 = st.columns([5, 7], gap="large")
    with p1:
        ui.md(ui.card("<h4>Summary</h4>" + ui.kv([
            ("Title", report_title), ("Case", case_number), ("Analyst", analyst_name or "—"),
            ("Threat score", f"{report.threat_score:.1f} / 100"), ("Confidence", f"{report.confidence_score:.1f}%"),
            ("Verdict", ui.Raw(ui.badge(verdict, ui.tone_for_verdict(verdict)))),
        ])))
    with p2:
        ui.md(ui.stat_grid([
            ui.stat_card("Critical", report.critical_count, "critical", "", "alert", 0),
            ui.stat_card("High", report.high_count, "high", "", "alert", 1),
            ui.stat_card("Medium", report.medium_count, "medium", "", "alert", 2),
            ui.stat_card("Low", report.low_count, "low", "", "alert", 3),
        ], 4))
    if "Recommendations" in include and report.recommendations:
        items = "".join(f"<li><span>{i + 1}</span><div>{ui.esc(r)}</div></li>" for i, r in enumerate(report.recommendations))
        ui.md(ui.section("Recommendations"))
        ui.md(ui.card(f'<ul class="reclist">{items}</ul>'))
    elif "Recommendations" not in include:
        st.caption("Recommendations section is excluded from the report.")
