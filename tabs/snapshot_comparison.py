"""
Snapshots
=========
Compare the current snapshot with a stored baseline and surface new,
missing and hidden processes plus DLL, service and network deltas.
"""

import streamlit as st

import ui


def _risk(delta: float) -> str:
    return "CRITICAL" if delta >= 70 else "HIGH" if delta >= 50 else "MEDIUM" if delta >= 25 else "LOW"


def render_snapshot_comparison():
    """Render the Snapshots view."""
    ui.md(ui.page_header("Snapshots", "Compare this capture against a known-good baseline.", "compare"))

    if not st.session_state.analysis_complete:
        ui.md(ui.empty_state("compare", "Nothing to compare yet", "Complete an analysis first to enable snapshot comparison."))
        return

    acq = st.session_state.acquisition
    snap = st.session_state.current_snapshot or {}
    meta = snap.get("metadata", {})
    col1, col2 = st.columns(2, gap="large")

    with col1:
        ui.md(ui.card("<h4>Current snapshot</h4>" + ui.kv([
            ("ID", ui.Raw(f"<code>{ui.esc(snap.get('snapshot_id', ''))}</code>")),
            ("Name", meta.get("name") or str(meta.get("file_path", "")).split("/")[-1]),
            ("Size", f"{meta.get('file_size', 0) / (1024**2):.1f} MB"),
            ("SHA-256", ui.Raw(f"<code>{ui.esc(str(meta.get('sha256_hash', ''))[:16])}…</code>")),
        ])))

    with col2:
        baselines = [b for b in acq.list_acquisitions() if b.get("is_baseline")]
        if baselines:
            baseline_map = {b.get("snapshot_id", b.get("name", "unknown")): b for b in baselines}
            selected = st.selectbox("Baseline", options=list(baseline_map.keys()),
                                    format_func=lambda sid: f"{baseline_map[sid].get('name', 'Unknown')} ({sid[:10]})")
            st.session_state.selected_baseline_snapshot_id = selected
            b = baseline_map.get(selected, {})
            ui.md(ui.card("<h4>Baseline snapshot</h4>" + ui.kv([
                ("ID", ui.Raw(f"<code>{ui.esc(b.get('snapshot_id', ''))}</code>")),
                ("Name", b.get("name", "")),
                ("Created", b.get("acquisition_time", "")),
                ("Stored findings", len(b.get("aggregated_findings") or [])),
            ])))
        else:
            ui.md(ui.card("<h4>Baseline snapshot</h4><p>No baseline yet. Mark a clean capture as the reference to measure drift against.</p>"))
            if st.button("Set current as baseline", icon=":material/flag:", key="set_baseline"):
                sid = snap.get("snapshot_id")
                if sid:
                    updated = acq.mark_as_baseline(sid, findings=st.session_state.aggregated_findings, metadata=meta)
                    if updated:
                        st.session_state.selected_baseline_snapshot_id = sid
                        st.session_state.current_snapshot.setdefault("metadata", {})["is_baseline"] = True
                        st.success("Current snapshot saved as baseline.")
                        st.rerun()
                    else:
                        st.error("Unable to mark the current snapshot as baseline.")
                else:
                    st.error("No current snapshot available to mark as baseline.")

    st.write("")
    if st.button("Compare snapshots", icon=":material/difference:", type="primary", key="do_compare"):
        with st.spinner("Comparing snapshots…"):
            try:
                snapshot_findings = snap.get("aggregated_findings") or st.session_state.aggregated_findings or []
                baseline_findings, baseline_id = [], "baseline-clean"
                sel = st.session_state.get("selected_baseline_snapshot_id")
                if sel:
                    bm = acq.get_acquisition(sel)
                    if bm:
                        baseline_findings = bm.get("aggregated_findings") or []
                        baseline_id = bm.get("snapshot_id", sel)
                comp = st.session_state.snapshot_comparator.compare_snapshots(
                    baseline_results=baseline_findings, snapshot_results=snapshot_findings,
                    baseline_id=baseline_id, snapshot_id=snap.get("snapshot_id", "current"))
                delta = comp.threat_delta_score
                data = {
                    "new_processes": len(comp.new_processes), "missing_processes": len(comp.missing_processes),
                    "hidden_processes": len(comp.hidden_processes), "dll_changes": len(comp.dll_changes),
                    "new_services": len(comp.new_services), "new_drivers": len(comp.new_drivers),
                    "network_changes": len(comp.network_changes), "threat_delta_score": round(delta, 1),
                    "risk_level": _risk(delta),
                }
            except Exception as err:
                st.warning(f"Comparison engine error: {err}. Showing a summary from current findings.")
                n = len(st.session_state.aggregated_findings or [])
                data = {"new_processes": n, "missing_processes": 0, "hidden_processes": 0, "dll_changes": 0,
                        "new_services": 0, "new_drivers": 0, "network_changes": 0, "threat_delta_score": 0.0,
                        "risk_level": "UNKNOWN"}
            st.session_state.comparison_result = data

    res = st.session_state.comparison_result
    if res:
        ui.md(ui.section("Comparison results"))
        risk = res.get("risk_level", "N/A")
        ui.md(ui.stat_grid([
            ui.stat_card("Threat delta", res.get("threat_delta_score", 0), ui.tone_for_verdict(risk), "Change vs. baseline", "trend", 0),
            ui.stat_card("New processes", res.get("new_processes", 0), "high", "Not in baseline", "cpu", 1),
            ui.stat_card("DLL changes", res.get("dll_changes", 0), "medium", "Loaded modules", "layers", 2),
            ui.stat_card("Risk level", risk, ui.tone_for_verdict(risk), "Derived from delta", "alert", 3),
        ], 4))
        ui.md(ui.section("Detected changes"))
        labels = [("New processes", "new_processes"), ("Missing processes", "missing_processes"),
                  ("Hidden processes", "hidden_processes"), ("DLL changes", "dll_changes"),
                  ("New services", "new_services"), ("New drivers", "new_drivers"), ("Network changes", "network_changes")]
        ui.md(ui.data_table([{"Category": l, "Count": res.get(k, 0)} for l, k in labels], caption="Changes between snapshots"))
