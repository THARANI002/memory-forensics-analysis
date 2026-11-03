"""
Enterprise Memory Forensics Platform - Streamlit Dashboard
===========================================================
Main application entry point. Handles page setup, sidebar
controls, memory acquisition/analysis orchestration, and wires
up the 7 analysis tabs.
"""

import os
import sys
import json
import hashlib
import tempfile
import shutil
import zipfile
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

import streamlit as st
import pandas as pd

# Add src to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

# Import core modules with safe fallbacks
try:
    from config.settings import *
except ImportError:
    # Fallback settings
    PAGE_TITLE = "Enterprise Memory Forensics Platform"
    PAGE_ICON = "🛡️"
    LAYOUT = "wide"
    INITIAL_SIDEBAR_STATE = "expanded"

try:
    from core.acquisition import MemoryAcquisition
    from core.analysis_engine import AnalysisOrchestrator, VolatilityEngine, YARAAnalyzer, AnalysisSession
    from core.snapshot_comparison import SnapshotComparisonEngine
    from core.threat_detection import ThreatDetectionEngine, DetectionResult
    from core.aggregation_engine import VirusTotalStyleAggregator
    from core.ioc_engine import IOCEngine, IOC
    from core.threat_intel import ThreatIntelligenceEngine
    from core.mitre_attack import MITREAttackMapper
    from core.timeline import TimelineReconstructor
    from core.process_tree import ProcessTreeBuilder
    from core.reporting import ReportEngine, ReportData
    from core.analytics import HistoricalAnalytics, InvestigationStats
    from core.database_manager import DatabaseManager
except ImportError as e:
    st.error(f"⚠️ Core module import error: {e}")
    st.stop()

# Import demo data with fallback
try:
    from core.demo_data import (
        DEMO_PROCESSES, DEMO_CONNECTIONS, DEMO_SERVICES,
        DEMO_COMMAND_LINES, DEMO_STRINGS, DEMO_SNAPSHOT_META,
        DEMO_EXECUTIVE_SUMMARY, DEMO_RECOMMENDATIONS,
    )
except ImportError:
    DEMO_PROCESSES = []
    DEMO_CONNECTIONS = []
    DEMO_SERVICES = []
    DEMO_COMMAND_LINES = []
    DEMO_STRINGS = []
    DEMO_SNAPSHOT_META = {}
    DEMO_EXECUTIVE_SUMMARY = "Demo data not available"
    DEMO_RECOMMENDATIONS = []

# Import tabs with safe fallback
try:
    from tabs import (
        render_executive_overview,
        render_snapshot_comparison,
        render_threat_hunter,
        render_ioc_center,
        render_mitre_attack,
        render_process_tree,
        render_timeline,
        render_reports,
        render_history_trends,
    )
except ImportError as e:
    st.error(f"⚠️ Tab import error: {e}")
    # Define fallback render functions
    def render_executive_overview(): st.warning("Executive Overview tab not available")
    def render_snapshot_comparison(): st.warning("Snapshot Comparison tab not available")
    def render_threat_hunter(): st.warning("Threat Hunter tab not available")
    def render_ioc_center(): st.warning("IOC Center tab not available")
    def render_mitre_attack(): st.warning("MITRE ATT&CK tab not available")
    def render_process_tree(): st.warning("Processes tab not available")
    def render_timeline(): st.warning("Timeline tab not available")
    def render_reports(): st.warning("Reports tab not available")
    def render_history_trends(): st.warning("History & Trends tab not available")

# Page configuration
st.set_page_config(
    page_title=PAGE_TITLE,
    page_icon=":material/shield:",
    layout=LAYOUT,
    initial_sidebar_state=INITIAL_SIDEBAR_STATE,
)

# Design system (CSS tokens, components, icons)
import ui  # noqa: E402



def init_session_state():
    """Initialize Streamlit session state with all required keys."""
    defaults = {
        "analysis_complete": False,
        "is_static_scan": False,
        "current_snapshot": None,
        "baseline_snapshot": None,
        "engine_results": [],
        "threat_detections": [],
        "aggregated_findings": [],
        "iocs": [],
        "timeline": [],
        "process_tree": None,
        "mitre_mappings": [],
        "comparison_result": None,
        "selected_baseline_snapshot_id": None,
        "report_data": None,
        "uploaded_file_info": None,
        "analysis_status": "idle",
        "analysis_error": None,
        "analysis_progress": "",
        "demo_loaded": False,
    }
    
    # Initialize core objects with error handling
    try:
        if "acquisition" not in st.session_state:
            st.session_state.acquisition = MemoryAcquisition()
    except Exception:
        st.session_state.acquisition = None
    
    try:
        if "orchestrator" not in st.session_state:
            st.session_state.orchestrator = AnalysisOrchestrator()
    except Exception:
        st.session_state.orchestrator = None
    
    try:
        if "detection_engine" not in st.session_state:
            st.session_state.detection_engine = ThreatDetectionEngine()
    except Exception:
        st.session_state.detection_engine = None
    
    try:
        if "ioc_engine" not in st.session_state:
            st.session_state.ioc_engine = IOCEngine()
    except Exception:
        st.session_state.ioc_engine = None
    
    try:
        if "mitre_mapper" not in st.session_state:
            st.session_state.mitre_mapper = MITREAttackMapper()
    except Exception:
        st.session_state.mitre_mapper = None
    
    try:
        if "timeline_builder" not in st.session_state:
            st.session_state.timeline_builder = TimelineReconstructor()
    except Exception:
        st.session_state.timeline_builder = None
    
    try:
        if "tree_builder" not in st.session_state:
            st.session_state.tree_builder = ProcessTreeBuilder()
    except Exception:
        st.session_state.tree_builder = None
    
    try:
        if "report_engine" not in st.session_state:
            st.session_state.report_engine = ReportEngine()
    except Exception:
        st.session_state.report_engine = None
    
    try:
        if "snapshot_comparator" not in st.session_state:
            st.session_state.snapshot_comparator = SnapshotComparisonEngine()
    except Exception:
        st.session_state.snapshot_comparator = None
    
    try:
        if "db_manager" not in st.session_state:
            st.session_state.db_manager = DatabaseManager()
    except Exception:
        st.session_state.db_manager = None
    
    try:
        if "aggregator" not in st.session_state:
            st.session_state.aggregator = VirusTotalStyleAggregator()
    except Exception:
        st.session_state.aggregator = None
    
    try:
        if "analytics" not in st.session_state:
            st.session_state.analytics = HistoricalAnalytics()
    except Exception:
        st.session_state.analytics = None
    
    # Set defaults for any missing keys
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _populate_report(report_data, detections, iocs, mappings):
    """Fill the list-type fields of a ReportData from analysis results (shared by demo and real runs)."""
    report_data.threat_findings = [
        {
            "title": d.technique, "description": d.description, "severity": d.severity,
            "confidence": d.confidence, "engine": getattr(d, "detection_source", "heuristic"),
        }
        for d in detections if getattr(d, "detected", False)
    ]
    report_data.ioc_list = [
        {"type": getattr(i, "ioc_type", "unknown"), "value": getattr(i, "value", ""),
         "confidence": getattr(i, "confidence", 0), "source": getattr(i, "source", "unknown")}
        for i in iocs
    ]
    report_data.mitre_mapping = [
        {"technique_id": getattr(m, "technique_id", ""), "technique_name": getattr(m, "technique_name", ""),
         "tactic": getattr(m, "tactic", ""), "confidence": getattr(m, "confidence", 0)}
        for m in mappings
    ]
    if not report_data.recommendations:
        report_data.recommendations = sorted({
            d.remediation for d in detections
            if getattr(d, "detected", False) and getattr(d, "remediation", "")
        })


def _map_detections(mapper, detections):
    """Map detections to ATT&CK, falling back from the name slug to the technique ID."""
    out = []
    if mapper is None:
        return out
    for det in detections:
        if not getattr(det, "detected", False):
            continue
        try:
            maps = mapper.map_detection(det.technique.lower().replace(" ", "_"), det.evidence)
            if not maps and getattr(det, "technique_id", ""):
                maps = mapper.map_detection(det.technique_id, det.evidence)
            out.extend(maps)
        except Exception:
            continue
    return out


def safe_execute(func, fallback=None, *args, **kwargs):
    """Safely execute a function with error handling."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        return fallback


def _flatten_process_tree(nodes):
    """Recursively flatten a process tree."""
    flat = []
    try:
        for node in nodes:
            flat.append(node)
            if hasattr(node, 'children') and node.children:
                flat.extend(_flatten_process_tree(node.children))
    except Exception:
        pass
    return flat


def load_demo_data():
    """Load demo data with safe error handling."""
    try:
        # Check if demo data exists
        if not DEMO_PROCESSES:
            st.warning("⚠️ Demo data not available. Please check the demo_data.py file.")
            return
        
        st.session_state.analysis_progress = "Loading demo data..."
        
        # Run detection
        detections = []
        try:
            if st.session_state.detection_engine:
                detections = st.session_state.detection_engine.run_all_detections(
                    processes=DEMO_PROCESSES,
                    connections=DEMO_CONNECTIONS,
                    services=DEMO_SERVICES,
                    command_lines=DEMO_COMMAND_LINES,
                )
        except Exception as e:
            st.warning(f"Detection engine error: {e}")
            detections = []
        
        # Build process tree
        process_tree = []
        try:
            if st.session_state.tree_builder:
                process_tree = st.session_state.tree_builder.build_tree(DEMO_PROCESSES)
        except Exception:
            process_tree = []
        
        # Build timeline
        timeline = []
        try:
            if st.session_state.timeline_builder:
                cmd_by_pid = {c["pid"]: c["command_line"] for c in DEMO_COMMAND_LINES}
                timeline_procs = [dict(p, command_line=cmd_by_pid.get(p.get("pid"), "")) for p in DEMO_PROCESSES]
                timeline = st.session_state.timeline_builder.build_timeline(
                    processes=timeline_procs,
                    network=DEMO_CONNECTIONS,
                    services=DEMO_SERVICES,
                )
                st.session_state.timeline_builder.escalate_from_detections(detections)
        except Exception:
            timeline = []
        
        # Extract IOCs
        iocs = []
        try:
            if st.session_state.ioc_engine:
                iocs = st.session_state.ioc_engine.extract_all_iocs(
                    processes=DEMO_PROCESSES,
                    connections=DEMO_CONNECTIONS,
                    services=DEMO_SERVICES,
                    strings=DEMO_STRINGS,
                )
        except Exception:
            iocs = []
        
        # Map MITRE
        all_mappings = _map_detections(st.session_state.mitre_mapper, detections)
        
        # Calculate scores
        scores = {"score": 0, "level": "CLEAN", "total_detections": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0}
        try:
            if st.session_state.detection_engine:
                scores = st.session_state.detection_engine.calculate_overall_score(detections)
        except Exception:
            pass
        
        # Build demo findings
        demo_findings = []
        try:
            for proc in DEMO_PROCESSES:
                demo_findings.append({
                    "type": "process",
                    "process_id": proc.get("pid"),
                    "process_name": proc.get("name"),
                    "parent_pid": proc.get("ppid"),
                })
        except Exception:
            pass
        
        # Create report data
        report_data = ReportData(
            title="Memory Forensics Report - DEMO",
            snapshot_id=DEMO_SNAPSHOT_META.get("snapshot_id", "DEMO_001"),
            analyst="Demo Analyst",
            case_number="CASE-DEMO-001",
            investigation_date=datetime.now(timezone.utc).isoformat(),
            threat_score=scores.get("score", 0.0),
            confidence_score=scores.get("score", 0.0) * 0.9,
            memory_health_score=max(0, 100 - scores.get("score", 0.0)),
            executive_verdict=scores.get("level", "CLEAN"),
            verdict_description=f"Demo: {scores.get('level', 'CLEAN')} - {scores.get('total_detections', 0)} threats",
            most_dangerous_process="mimikatz.exe (PID 1776)" if DEMO_PROCESSES else "N/A",
            most_dangerous_ip="45.142.212.100" if DEMO_CONNECTIONS else "N/A",
            top_mitre_technique="T1003.001 - OS Credential Dumping",
            total_threats=scores.get("total_detections", 0),
            critical_count=scores.get("critical_count", 0),
            high_count=scores.get("high_count", 0),
            medium_count=scores.get("medium_count", 0),
            low_count=scores.get("low_count", 0),
            total_iocs=len(iocs),
            threat_findings=[],
            ioc_list=[],
            mitre_mapping=[],
            timeline_summary={},
            process_tree_summary={"total_processes": len(DEMO_PROCESSES), "suspicious": 0},
            detection_results=[],
            recommendations=DEMO_RECOMMENDATIONS,
            executive_summary=DEMO_EXECUTIVE_SUMMARY,
        )
        
        _populate_report(report_data, detections, iocs, all_mappings)
        report_data.process_tree_summary = {"total_processes": len(DEMO_PROCESSES),
                                            "suspicious": len({p for d in detections if d.detected for p in d.process_indicators})}
        report_data.most_dangerous_process = next(
            (d.process_indicators[0] for d in detections if d.detected and d.process_indicators), "N/A")
        _sev = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        _top = max((d for d in detections if d.detected),
                   key=lambda d: (_sev.get(d.severity, 0), d.confidence), default=None)
        if _top is not None:
            _tech = st.session_state.mitre_mapper._techniques.get(_top.technique_id) if st.session_state.mitre_mapper else None
            report_data.top_mitre_technique = f"{_top.technique_id} - {_tech.name if _tech else _top.technique}"

        # Update session state
        st.session_state.current_snapshot = {
            "snapshot_id": DEMO_SNAPSHOT_META.get("snapshot_id", "DEMO_001"),
            "metadata": DEMO_SNAPSHOT_META,
            "aggregated_findings": demo_findings,
        }
        st.session_state.threat_detections = detections
        st.session_state.aggregated_findings = demo_findings
        st.session_state.iocs = iocs
        st.session_state.timeline = timeline
        st.session_state.process_tree = process_tree
        st.session_state.mitre_mappings = all_mappings
        st.session_state.report_data = report_data
        st.session_state.analysis_complete = True
        st.session_state.analysis_status = "complete"
        st.session_state.analysis_progress = "Demo data loaded successfully!"
        st.session_state.demo_loaded = True

        # Save to database so demo runs also show up in History & Trends,
        # not just real-file analyses. Each demo run gets a unique case
        # number/hash so it's tracked as its own historical data point.
        try:
            if st.session_state.db_manager:
                _demo_run_id = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')
                demo_snapshot_meta = dict(DEMO_SNAPSHOT_META)
                demo_snapshot_meta.setdefault("name", "Demo Scenario")
                demo_snapshot_meta["sha256_hash"] = f"demo-{_demo_run_id}"
                demo_snapshot_meta.setdefault("file_size", 0)
                demo_snapshot_meta.setdefault("file_path", "demo://synthetic-scenario")
                demo_snapshot_meta.setdefault("acquisition_tool", "demo")

                report_data.case_number = f"CASE-DEMO-{_demo_run_id}"

                saved = st.session_state.db_manager.save_analysis_results(
                    snapshot_meta=demo_snapshot_meta,
                    detections=detections,
                    iocs=iocs,
                    mitre_mappings=all_mappings,
                    report_data=report_data
                )
                if not saved:
                    st.warning(
                        "⚠️ This run completed but could not be saved to History & Trends "
                        "(database write failed). Check the app logs for details."
                    )
        except Exception as e:
            st.warning(f"Database save warning: {e}")
        
    except Exception as e:
        st.error(f"Error loading demo data: {str(e)}")
        st.session_state.analysis_status = "error"
        st.session_state.analysis_error = str(e)


def _launch_demo():
    """Load the bundled demo scenario (shared by the landing page and the sidebar)."""
    with st.spinner("Loading demo forensics scenario..."):
        load_demo_data()
    if st.session_state.analysis_status == "complete":
        st.session_state["nav"] = ui.NAV_LABEL["overview"]
        st.session_state["_toast"] = "Demo scenario loaded"
        st.rerun()
    else:
        st.error("Failed to load demo data")


def render_topbar():
    """Primary navigation (only the active view is rendered, which keeps the app fast)."""
    st.session_state.setdefault("nav", ui.NAV_LABEL["overview"])
    choice = st.segmented_control(
        "Navigate", [label for _, label in ui.NAV], key="nav",
        label_visibility="collapsed", width="stretch",
    )
    return choice or st.session_state.get("nav") or ui.NAV_LABEL["overview"]


def render_sidebar():
    """Render the sidebar with evidence, options, status and appearance controls."""
    with st.sidebar:
        ui.md(f'<div class="brand"><div class="brand-mark">{ui.icon("shield", 22)}</div>'
              f'<div><div class="brand-name">Memory Forensics</div><div class="brand-sub">v2.5 · DFIR workbench</div></div></div>')

        st.markdown("### Evidence")
        if st.button("Load demo scenario", icon=":material/play_arrow:", width="stretch", key="sb_demo"):
            _launch_demo()
        st.caption("Explore a complete simulated intrusion, no memory dump required.")

        uploaded_file = st.file_uploader(
            "Upload memory dump",
            type=None,
            help="Upload a memory dump (.raw, .mem, .dmp, .bin, .lime, .aff4, .zip)",
        )

        if uploaded_file:
            ext = uploaded_file.name.split(".")[-1].lower() if "." in uploaded_file.name else "unknown"
            is_real_dump = ext in ["raw", "mem", "dump", "lime", "aff4", "vmem", "dmp", "bin", "hpak", "crash"]
            ui.md(ui.card(ui.kv([
                ("File", uploaded_file.name),
                ("Size", f"{uploaded_file.size / (1024**2):.2f} MB"),
                ("Type", f".{ext}"),
            ])))
            if not is_real_dump and ext != "zip":
                st.warning("This doesn't look like a memory dump. Analysis may produce limited results.")

            st.session_state.uploaded_file_info = {
                "name": uploaded_file.name,
                "size": uploaded_file.size,
                "ext": ext,
                "is_real_dump": is_real_dump,
            }

        st.markdown("### Analysis")
        run_volatility = st.checkbox("Volatility 3", value=True)
        run_yara = st.checkbox("YARA rules", value=True)
        run_detection = st.checkbox("Threat detection", value=True)

        status = st.session_state.analysis_status
        dot = {"idle": "var(--text3)", "running": "var(--blue-f)", "complete": "var(--green-f)", "error": "var(--red-f)"}
        label = {"idle": "Ready", "running": "Analyzing…", "complete": "Analysis complete", "error": "Needs attention"}
        ui.md(f'<div class="status" role="status" style="--dot:{dot.get(status, "var(--text3)")}"><i></i>{label.get(status, "Unknown")}</div>')
        if st.session_state.analysis_progress:
            st.caption(st.session_state.analysis_progress)

        if uploaded_file:
            if st.button("Start analysis", icon=":material/bolt:", width="stretch", type="primary", key="sb_start"):
                _run_analysis(uploaded_file, run_volatility, run_yara, run_detection)

        st.markdown("### Recent snapshots")
        try:
            if st.session_state.acquisition:
                recent = st.session_state.acquisition.list_acquisitions()[:5]
                if recent:
                    for snap in recent:
                        name = ui.esc(snap.get("name", "Unknown")[:30])
                        snap_hash = ui.esc(snap.get("sha256_hash", "")[:16])
                        snap_size = snap.get("file_size", 0) / (1024**2)
                        ui.md(f'<div class="snap"><b>{name}</b><span>{snap_hash}… · {snap_size:.0f} MB</span></div>')
                else:
                    st.caption("No snapshots yet.")
        except Exception:
            st.caption("No snapshots available.")

        st.markdown("### Appearance")
        st.segmented_control("Appearance", ["Auto", "Light", "Dark"], default="Auto", key="appearance",
                             label_visibility="collapsed")


def _fmt_proc(text):
    """'2800' -> 'PID 2800'; leave 'name (PID n)' untouched."""
    t = str(text)
    return f"PID {t}" if t.isdigit() else t


@st.cache_data(show_spinner=False)
def _demo_preview_rows():
    """Run the real detection engine on the bundled demo data for the landing-page feed."""
    try:
        dets = ThreatDetectionEngine().run_all_detections(
            processes=DEMO_PROCESSES, connections=DEMO_CONNECTIONS, services=DEMO_SERVICES,
            command_lines=DEMO_COMMAND_LINES)
    except Exception:
        return []
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top = sorted((d for d in dets if d.detected), key=lambda d: (order.get(d.severity, 9), -d.confidence))[:6]
    return [(d.severity, d.technique, (_fmt_proc(d.process_indicators[0]) if d.process_indicators else d.tactic), d.technique_id) for d in top]


def render_landing():
    """Welcome experience shown before any analysis is loaded."""
    ui.md(ui.hero("Memory forensics, simplified",
                  "See what's hiding in " + ui.rotating_words(["memory.", "processes.", "credentials.", "implants."]),
                  "Detect intrusions, extract indicators and map every finding to MITRE ATT&CK, "
                  "all from a single memory image."))
    _, c1, c2, _ = st.columns([2, 2, 2, 2])
    with c1:
        if st.button("Explore the demo", icon=":material/play_arrow:", type="primary", width="stretch", key="hero_demo"):
            _launch_demo()
    with c2:
        st.button("Upload a dump", icon=":material/upload:", width="stretch", key="hero_upload",
                  help="Use the Evidence panel in the sidebar (top-left arrow on mobile).", disabled=False,
                  on_click=lambda: st.session_state.update(upload_hint=True))
    if st.session_state.pop("upload_hint", False):
        st.info("Open the **Evidence** panel in the sidebar and drop in a memory image (.raw, .mem, .dmp, .lime, .aff4, .zip).")

    rows = _demo_preview_rows()
    if rows:
        ui.md(ui.terminal_feed("WIN10-VICTIM · demo scenario", rows))
        st.caption("Real output from the bundled demo scenario, produced by the same detection engine.")

    ui.md(ui.section("Everything an analyst needs", "One workspace, from triage to report"))
    ui.md(ui.feature_grid([
        ui.feature_card("radar", "Evidence-based detection", "Process-tree validation, hidden-process checks, credential theft and living-off-the-land abuse.", "blue", 0),
        ui.feature_card("fingerprint", "IOC extraction", "IPs, hashes, paths and services, exportable to JSON, CSV, STIX 2.1 and OpenIOC.", "purple", 1),
        ui.feature_card("grid", "ATT&CK mapping", "Every finding mapped to a technique, with a heatmap and Navigator layer export.", "teal", 2),
        ui.feature_card("clock", "Timeline", "Process, network and service events reconstructed into one chronological view.", "orange", 3),
        ui.feature_card("file", "Reporting", "Executive-ready PDF, HTML and JSON reports with chain-of-custody context.", "green", 4),
        ui.feature_card("trend", "History", "Every investigation is stored so threat trends stay visible over time.", "red", 5),
    ], 3))

    ui.md(ui.section("How it works"))
    ui.md(ui.steps([
        ("Add evidence", "Upload a memory image or start with the demo scenario."),
        ("Analyze", "Detection, IOC extraction and ATT&CK mapping run automatically."),
        ("Report", "Review findings, compare snapshots and export a report."),
    ]))

    try:
        has_history = bool(st.session_state.db_manager and st.session_state.db_manager.get_report_history(limit=1))
    except Exception:
        has_history = False
    if has_history:
        st.markdown("---")
        render_history_trends()


def _run_analysis(uploaded_file, run_volatility, run_yara, run_detection):
    """Run analysis on uploaded file with comprehensive error handling."""
    st.session_state.analysis_status = "running"
    st.session_state.analysis_error = None
    st.session_state.analysis_progress = "Starting analysis..."
    
    try:
        # Validate file
        if uploaded_file is None:
            raise ValueError("No file uploaded")
        
        if uploaded_file.size == 0:
            raise ValueError("Uploaded file is empty")
        
        # Save uploaded file
        st.session_state.analysis_progress = "Saving file..."
        _safe_filename = Path(uploaded_file.name).name
        _safe_filename = _safe_filename.lstrip("./\\") or "upload"
        from config.settings import MEMORY_DUMPS_DIR
        _dumps_dir = Path(MEMORY_DUMPS_DIR).resolve()
        _dumps_dir.mkdir(parents=True, exist_ok=True)
        dump_path = str((_dumps_dir / _safe_filename).resolve())
        
        with open(dump_path, "wb") as f:
            f.write(uploaded_file.getvalue())
        
        # Acquire memory
        st.session_state.analysis_progress = "Acquiring memory dump..."
        if st.session_state.acquisition is None:
            raise RuntimeError("Memory acquisition module not available")
        
        result = st.session_state.acquisition.acquire_memory(
            file_path=dump_path,
            name=uploaded_file.name,
            analyst="DFIR Analyst",
            system_info=st.session_state.acquisition.get_system_info()
        )
        
        if not result.get("success", False):
            errors = result.get("errors", ["Unknown acquisition error"])
            raise RuntimeError(f"Acquisition failed: {', '.join(errors)}")
        
        st.session_state.current_snapshot = result
        
        # Check if ZIP
        ext = uploaded_file.name.split(".")[-1].lower() if "." in uploaded_file.name else "unknown"
        is_zip = ext == "zip"
        
        if is_zip:
            st.session_state.is_static_scan = True
            st.session_state.analysis_progress = "Analyzing ZIP archive..."
            session = _analyze_zip(dump_path, result["snapshot_id"])
        else:
            st.session_state.is_static_scan = False
            st.session_state.analysis_progress = "Running memory analysis..."
            if st.session_state.orchestrator is None:
                raise RuntimeError("Analysis orchestrator not available")
            session = st.session_state.orchestrator.run_full_analysis(
                memory_path=dump_path,
                snapshot_id=result["snapshot_id"],
                run_volatility=run_volatility,
                run_yara=run_yara
            )
        
        # Store results
        st.session_state.engine_results = session.engine_results if hasattr(session, 'engine_results') else []
        st.session_state.aggregated_findings = session.aggregated_findings if hasattr(session, 'aggregated_findings') else []
        
        if st.session_state.current_snapshot:
            st.session_state.current_snapshot["aggregated_findings"] = st.session_state.aggregated_findings
        
        # Run threat detection if enabled
        if run_detection:
            _run_threat_detection(uploaded_file, result)
        else:
            st.session_state.analysis_complete = True
            st.session_state.analysis_status = "complete"
            st.session_state.analysis_progress = "Analysis complete!"
            st.success("✅ Analysis complete!")
            st.rerun()
            
    except Exception as e:
        error_msg = str(e)
        st.session_state.analysis_status = "error"
        st.session_state.analysis_error = error_msg
        st.session_state.analysis_progress = f"Error: {error_msg}"
        st.error(f"❌ Analysis failed: {error_msg}")
        st.code(traceback.format_exc())


def _analyze_zip(dump_path, snapshot_id):
    """Analyze a ZIP file with safe error handling."""
    temp_dir = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(dump_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                try:
                    zip_ref.extract(member, temp_dir)
                except Exception:
                    pass
        
        yara_result = None
        if st.session_state.orchestrator and hasattr(st.session_state.orchestrator, 'yara'):
            yara_result = st.session_state.orchestrator.yara.scan_directory_or_file(temp_dir)
        
        session = AnalysisSession(
            session_id=f"SESSION_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            snapshot_id=snapshot_id,
            memory_path=dump_path,
            start_time=datetime.now(timezone.utc).isoformat(),
            status="completed"
        )
        session.engine_results = [yara_result] if yara_result else []
        if st.session_state.orchestrator:
            session.aggregated_findings = st.session_state.orchestrator._aggregate_findings(session.engine_results)
        else:
            session.aggregated_findings = []
        
        return session
        
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass


def _run_threat_detection(uploaded_file, result):
    """Run threat detection with safe error handling."""
    st.session_state.analysis_progress = "Running threat detection..."
    
    try:
        # Extract process/network/service data from findings
        processes = []
        connections = []
        services = []
        command_lines = []
        
        for finding in st.session_state.aggregated_findings:
            try:
                finding_type = finding.get("type", "")
                if finding_type == "process":
                    processes.append({
                        "pid": finding.get("process_id"),
                        "name": finding.get("process_name"),
                        "ppid": finding.get("parent_pid"),
                        "threads": finding.get("threads"),
                        "create_time": finding.get("create_time"),
                        "command_line": finding.get("command_line", ""),
                    })
                elif finding_type == "network":
                    connections.append({
                        "local_address": finding.get("local_address"),
                        "local_port": finding.get("local_port"),
                        "remote_address": finding.get("remote_address"),
                        "remote_port": finding.get("remote_port"),
                        "protocol": finding.get("protocol"),
                        "state": finding.get("state"),
                        "pid": finding.get("process_id"),
                        "process": finding.get("process_name"),
                    })
                elif finding_type == "service":
                    services.append({
                        "service_name": finding.get("service_name"),
                        "display_name": finding.get("display_name"),
                        "type": finding.get("service_type"),
                        "state": finding.get("state"),
                        "binary_path": finding.get("binary_path"),
                        "start": finding.get("start"),
                    })
            except Exception:
                continue
        
        # Run detection
        detections = []
        if st.session_state.detection_engine:
            try:
                detections = st.session_state.detection_engine.run_all_detections(
                    processes=processes,
                    connections=connections,
                    services=services,
                    command_lines=command_lines
                )
            except Exception as e:
                st.warning(f"Detection engine error: {e}")
        
        # Add YARA findings
        try:
            from core.threat_detection import DetectionResult
            for finding in st.session_state.aggregated_findings:
                if finding.get("type") == "yara_match":
                    detections.append(DetectionResult(
                        detected=True,
                        technique=f"YARA: {finding.get('rule_name', 'Unknown')}",
                        technique_id="T1588",
                        tactic="Resource Development",
                        description=f"Matched rule '{finding.get('rule_name')}'",
                        severity=finding.get("severity", "high"),
                        confidence=95.0,
                        evidence=[finding],
                        remediation="Investigate and quarantine if malicious.",
                        detection_source="yara_static_scan"
                    ))
        except Exception:
            pass
        
        st.session_state.threat_detections = detections
        
        # Build process tree
        try:
            if st.session_state.tree_builder:
                st.session_state.process_tree = st.session_state.tree_builder.build_tree(processes)
        except Exception:
            st.session_state.process_tree = []
        
        # Build timeline
        try:
            if st.session_state.timeline_builder:
                timeline = st.session_state.timeline_builder.build_timeline(
                    processes=processes,
                    network=connections,
                    services=services
                )
                st.session_state.timeline_builder.escalate_from_detections(detections)
                st.session_state.timeline = timeline
        except Exception:
            st.session_state.timeline = []
        
        # Extract IOCs (include YARA match evidence so ZIP/static scans
        # produce file-specific IOCs instead of always empty results)
        try:
            yara_strings = []
            for finding in st.session_state.aggregated_findings:
                if finding.get("type") == "yara_match":
                    for key in ("file_matched", "rule_name", "sha256", "md5"):
                        val = finding.get(key)
                        if val:
                            yara_strings.append(str(val))

            if st.session_state.ioc_engine:
                iocs = st.session_state.ioc_engine.extract_all_iocs(
                    processes=processes,
                    connections=connections,
                    services=services,
                    strings=yara_strings
                )
                st.session_state.iocs = iocs
        except Exception:
            st.session_state.iocs = []
        
        # Map MITRE
        st.session_state.mitre_mappings = _map_detections(st.session_state.mitre_mapper, detections)
        
        # Build report
        _build_report(uploaded_file, result, detections)
        
    except Exception as e:
        st.warning(f"Threat detection warning: {e}")
        # Still mark as complete even if detection partially fails
        st.session_state.analysis_complete = True
        st.session_state.analysis_status = "complete"
        st.session_state.analysis_progress = "Analysis complete (with warnings)"
        st.success("✅ Analysis complete!")
        st.rerun()


def _build_report(uploaded_file, result, detections):
    """Build report data with safe error handling."""
    st.session_state.analysis_progress = "Generating report..."
    
    try:
        # Calculate scores
        scores = {"score": 0, "level": "CLEAN", "total_detections": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0}
        try:
            if st.session_state.detection_engine:
                scores = st.session_state.detection_engine.calculate_overall_score(detections)
        except Exception:
            pass
        
        # Calculate dangerous process
        _most_dangerous_process = "N/A"
        _best_score = -1
        _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        
        try:
            for d in [d for d in detections if hasattr(d, 'detected') and d.detected]:
                for ev in (d.evidence if hasattr(d, 'evidence') else []):
                    pname = ev.get("process_name") or ev.get("name") or ev.get("process")
                    pid = ev.get("pid") or ev.get("process_id")
                    if pname:
                        sev = d.severity.lower() if hasattr(d, 'severity') else "medium"
                        score = _sev_rank.get(sev, 0) * 1000 + (d.confidence if hasattr(d, 'confidence') else 0)
                        if score > _best_score:
                            _best_score = score
                            _most_dangerous_process = f"{pname} (PID {pid})" if pid else pname
        except Exception:
            pass
        
        # Most dangerous IP
        _most_dangerous_ip = "N/A"
        try:
            _best_ip_conf = -1
            for ioc in st.session_state.iocs:
                if hasattr(ioc, 'ioc_type') and ioc.ioc_type in ("ip", "ip_address"):
                    if ioc.confidence > _best_ip_conf:
                        _best_ip_conf = ioc.confidence
                        _most_dangerous_ip = ioc.value
        except Exception:
            pass
        
        # Top MITRE
        _top_mitre = "N/A"
        try:
            _best_mitre_conf = -1
            for m in st.session_state.mitre_mappings:
                if hasattr(m, 'confidence') and m.confidence > _best_mitre_conf:
                    _best_mitre_conf = m.confidence
                    _top_mitre = f"{m.technique_id} - {m.technique_name}" if hasattr(m, 'technique_id') else str(m)
        except Exception:
            pass
        
        # Build report data
        report_data = ReportData(
            title=f"Memory Forensics Report - {uploaded_file.name}",
            snapshot_id=result.get("snapshot_id", "UNKNOWN"),
            threat_score=scores.get("score", 0.0),
            confidence_score=scores.get("score", 0.0) * 0.9,
            memory_health_score=max(0, 100 - scores.get("score", 0.0)),
            executive_verdict=scores.get("level", "CLEAN"),
            verdict_description=f"Level: {scores.get('level', 'CLEAN')} - {scores.get('total_detections', 0)} threats",
            most_dangerous_process=_most_dangerous_process,
            most_dangerous_ip=_most_dangerous_ip,
            top_mitre_technique=_top_mitre,
            total_threats=scores.get("total_detections", 0),
            critical_count=scores.get("critical_count", 0),
            high_count=scores.get("high_count", 0),
            medium_count=scores.get("medium_count", 0),
            low_count=scores.get("low_count", 0),
            total_iocs=len(st.session_state.iocs),
            threat_findings=[],
            ioc_list=[],
            mitre_mapping=[],
            timeline_summary=st.session_state.timeline_builder.get_timeline_summary() if st.session_state.timeline_builder else {},
            process_tree_summary={"total_processes": 0, "suspicious": 0},
            detection_results=[],
            recommendations=[],
            executive_summary=f"Analysis of {uploaded_file.name} detected {scores.get('total_detections', 0)} threats.",
        )
        
        # Add threat findings
        try:
            for d in detections:
                if hasattr(d, 'detected') and d.detected:
                    report_data.threat_findings.append({
                        "title": d.technique if hasattr(d, 'technique') else "Unknown",
                        "description": d.description if hasattr(d, 'description') else "",
                        "severity": d.severity if hasattr(d, 'severity') else "medium",
                        "confidence": d.confidence if hasattr(d, 'confidence') else 0,
                        "engine": d.detection_source if hasattr(d, 'detection_source') else "heuristic",
                    })
        except Exception:
            pass
        
        # Add IOCs
        try:
            for ioc in st.session_state.iocs:
                report_data.ioc_list.append({
                    "type": ioc.ioc_type if hasattr(ioc, 'ioc_type') else "unknown",
                    "value": ioc.value if hasattr(ioc, 'value') else "",
                    "confidence": ioc.confidence if hasattr(ioc, 'confidence') else 0,
                    "source": ioc.source if hasattr(ioc, 'source') else "unknown",
                })
        except Exception:
            pass
        
        # Add MITRE mappings
        try:
            for m in st.session_state.mitre_mappings:
                report_data.mitre_mapping.append({
                    "technique_id": m.technique_id if hasattr(m, 'technique_id') else "",
                    "technique_name": m.technique_name if hasattr(m, 'technique_name') else "",
                    "tactic": m.tactic if hasattr(m, 'tactic') else "",
                    "confidence": m.confidence if hasattr(m, 'confidence') else 0,
                })
        except Exception:
            pass
        
        # Add recommendations
        try:
            recs = set()
            for d in detections:
                if hasattr(d, 'detected') and d.detected and hasattr(d, 'remediation') and d.remediation:
                    recs.add(d.remediation)
            report_data.recommendations = list(recs)
        except Exception:
            pass
        
        st.session_state.report_data = report_data
        st.session_state.analysis_complete = True
        st.session_state.analysis_status = "complete"
        st.session_state.analysis_progress = "Analysis complete!"
        
        # Save to database
        try:
            if st.session_state.db_manager:
                saved = st.session_state.db_manager.save_analysis_results(
                    snapshot_meta=result.get("metadata", {}),
                    detections=detections,
                    iocs=st.session_state.iocs,
                    mitre_mappings=st.session_state.mitre_mappings,
                    report_data=report_data
                )
                if not saved:
                    st.warning(
                        "⚠️ This analysis completed but could not be saved to History & Trends "
                        "(database write failed). Check the app logs for details."
                    )
        except Exception as e:
            st.warning(f"Database save warning: {e}")
        
        st.success("✅ Analysis complete!")
        st.rerun()
        
    except Exception as e:
        # Even if report building fails, mark as complete
        st.session_state.analysis_complete = True
        st.session_state.analysis_status = "complete"
        st.session_state.analysis_progress = "Analysis complete (report generation had issues)"
        st.warning(f"Report generation warning: {e}")
        st.success("✅ Analysis complete!")
        st.rerun()


def main():
    """Main application entry point."""
    init_session_state()
    ui.inject_theme()
    render_sidebar()
    toast = st.session_state.pop("_toast", None)
    if toast:
        st.toast(toast, icon=":material/check_circle:")

    if not st.session_state.analysis_complete:
        render_landing()
        return

    page = render_topbar()
    pages = {
        ui.NAV_LABEL["overview"]: render_executive_overview,
        ui.NAV_LABEL["snapshots"]: render_snapshot_comparison,
        ui.NAV_LABEL["hunter"]: render_threat_hunter,
        ui.NAV_LABEL["iocs"]: render_ioc_center,
        ui.NAV_LABEL["mitre"]: render_mitre_attack,
        ui.NAV_LABEL["processes"]: render_process_tree,
        ui.NAV_LABEL["timeline"]: render_timeline,
        ui.NAV_LABEL["reports"]: render_reports,
        ui.NAV_LABEL["history"]: render_history_trends,
    }
    try:
        pages.get(page, render_executive_overview)()
    except Exception as e:
        st.error(f"Error rendering this view: {e}")
        st.info("Try another view, or reload the demo data.")


if __name__ == "__main__":
    main()