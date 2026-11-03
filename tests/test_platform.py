"""Functional tests for the Enterprise Memory Forensics Platform."""
import copy, json, os, zipfile
import pytest

from core.demo_data import (DEMO_PROCESSES, DEMO_CONNECTIONS, DEMO_SERVICES,
                            DEMO_COMMAND_LINES, DEMO_STRINGS)
from core.threat_detection import ThreatDetectionEngine
from core.ioc_engine import IOCEngine
from core.mitre_attack import MITREAttackMapper
from core.acquisition import MemoryAcquisition
from core.reporting import ReportEngine, ReportData

CLEAN_PIDS = {4, 388, 512, 584, 640, 660, 740, 768, 892, 1024, 1200, 4100, 4400, 4800}


@pytest.fixture
def engine():
    return ThreatDetectionEngine()


def _procs():
    p = copy.deepcopy(DEMO_PROCESSES)
    return p


def test_attack_scenario_is_critical(engine):
    d = engine.run_all_detections(processes=_procs(), connections=DEMO_CONNECTIONS,
                                  services=DEMO_SERVICES, command_lines=DEMO_COMMAND_LINES)
    ids = {x.technique_id for x in d if x.detected}
    for expected in ("T1003", "T1003.001", "T1059.001", "T1105", "T1218.005", "T1036.005", "T1014"):
        assert expected in ids, expected
    assert engine.calculate_overall_score(d)["level"] == "CRITICAL"


def test_clean_system_has_no_false_positives(engine):
    clean = [p for p in _procs() if p["pid"] in CLEAN_PIDS]
    safe_services = [DEMO_SERVICES[0], DEMO_SERVICES[3]]
    chrome = [c for c in DEMO_CONNECTIONS if c["process"] == "chrome.exe"]
    d = engine.run_all_detections(processes=clean, connections=chrome,
                                  services=safe_services, command_lines=[])
    assert [x.technique for x in d if x.detected] == []
    assert engine.calculate_overall_score(d)["level"] == "CLEAN"


def test_task_manager_alone_is_not_lsass_access(engine):
    procs = [p for p in _procs() if p["pid"] in (584, 660, 4800)]
    assert not engine.detect_lsass_access(procs)


def test_duplicate_lsass_is_masquerading(engine):
    procs = [p for p in _procs() if p["name"] == "lsass.exe"]
    res = engine.detect_masquerading(procs)
    assert res and res[0].technique_id == "T1036.005"
    assert any(e["pid"] == 5200 for e in res[0].evidence)  # later instance flagged


def test_hidden_process_flagged_as_rootkit(engine):
    procs = [{"pid": 9, "name": "x.exe", "ppid": 4, "in_psscan": True, "in_pslist": False}]
    assert engine.detect_rootkits(procs)[0].technique_id == "T1014"


def test_scoring_not_diluted_by_noise(engine):
    d = engine.run_all_detections(processes=_procs(), connections=DEMO_CONNECTIONS,
                                  services=DEMO_SERVICES, command_lines=DEMO_COMMAND_LINES)
    strong = [x for x in d if x.severity == "critical"][:1]
    assert engine.calculate_overall_score(strong)["score"] >= 70


def test_ioc_extraction_and_dedup():
    iocs = IOCEngine().extract_all_iocs(processes=_procs(), connections=DEMO_CONNECTIONS,
                                        services=DEMO_SERVICES, strings=DEMO_STRINGS)
    values = {(i.ioc_type, i.value) for i in iocs}
    assert ("ip", "45.142.212.100") in values
    assert len(values) == len(iocs)  # deduplicated
    assert not any(i.value.startswith("10.10.") for i in iocs if i.ioc_type == "ip")  # private IPs skipped


def test_stix_pattern_escapes_quotes():
    from core.ioc_engine import IOC
    pat = IOC(ioc_type="filepath", value="C:\\a'b").stix_pattern
    assert "\\\\" in pat and "\\'" in pat


def test_every_detection_maps_to_mitre(engine):
    m = MITREAttackMapper()
    d = engine.run_all_detections(processes=_procs(), connections=DEMO_CONNECTIONS,
                                  services=DEMO_SERVICES, command_lines=DEMO_COMMAND_LINES)
    for x in d:
        slug = x.technique.lower().replace(" ", "_")
        assert m.map_detection(slug, x.evidence) or m.map_detection(x.technique_id, x.evidence), x.technique


def test_navigator_layer_shape():
    m = MITREAttackMapper()
    mp = m.map_detection("T1003.001", [{"pid": 1}])
    layer = m.generate_attack_navigator_layer(mp)
    assert layer["domain"] == "enterprise-attack" and layer["techniques"][0]["techniqueID"] == "T1003.001"


def test_acquisition_hashes_and_rejects_empty(tmp_path):
    acq = MemoryAcquisition()
    good = tmp_path / "dump.raw"; good.write_bytes(b"A" * 4096)
    res = acq.acquire_memory(str(good), name="t", analyst="pytest")
    assert res["success"] and len(res["metadata"]["sha256_hash"]) == 64
    empty = tmp_path / "e.raw"; empty.write_bytes(b"")
    assert not acq.acquire_memory(str(empty))["success"]


def _report(**kw):
    base = dict(title="T", snapshot_id="S", analyst="a", case_number="C-1",
                threat_score=88.0, confidence_score=80.0, memory_health_score=12.0,
                executive_verdict="CRITICAL", verdict_description="d", most_dangerous_process="x.exe",
                most_dangerous_ip="1.2.3.4", top_mitre_technique="T1003", total_threats=1,
                critical_count=1, high_count=0, medium_count=0, low_count=0, total_iocs=1,
                threat_findings=[{"title": "<script>alert(1)</script>", "description": "d", "severity": "critical",
                                  "confidence": 90, "engine": "h"}],
                ioc_list=[{"type": "ip", "value": "1.2.3.4", "confidence": 80, "source": "s"}],
                mitre_mapping=[], timeline_summary={}, process_tree_summary={}, detection_results=[],
                recommendations=["Isolate host"], executive_summary="sum")
    base.update(kw)
    return ReportData(**base)


@pytest.mark.parametrize("fmt", ["json", "html", "pdf"])
def test_report_formats(fmt):
    paths = ReportEngine().generate_report(_report(), format=fmt)
    assert os.path.getsize(paths[fmt]) > 500


def test_html_report_escapes_xss():
    p = ReportEngine().generate_report(_report(), format="html")["html"]
    html = open(p, encoding="utf-8").read()
    assert "<script>alert(1)</script>" not in html


def test_database_roundtrip():
    from core.database_manager import DatabaseManager
    db = DatabaseManager()
    from core.threat_detection import DetectionResult
    det = DetectionResult(technique="Credential Dumping", technique_id="T1003", tactic="Credential Access",
                          detected=True, confidence=90.0, severity="critical", description="d", evidence=[])
    meta = {"name": "pytest", "sha256_hash": "f" * 64, "file_size": 1, "file_path": "x"}
    assert db.save_analysis_results(meta, [det], [], [], _report(case_number="CASE-DB-1"))
    hist = db.get_report_history()
    assert any(h["snapshot_name"] == "pytest" for h in hist)


def test_empty_case_numbers_do_not_collide():
    from core.database_manager import DatabaseManager
    db = DatabaseManager()
    for i in range(2):
        meta = {"name": f"n{i}", "sha256_hash": str(i) * 64, "file_size": 1, "file_path": "x"}
        assert db.save_analysis_results(meta, [], [], [], _report(case_number=""))


def _app():
    from streamlit.testing.v1 import AppTest
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return AppTest.from_file(os.path.join(root, "app.py"), default_timeout=120).run()


def _load_demo(at):
    next(b for b in at.button if b.key == "hero_demo").click().run()
    return at


def test_demo_app_end_to_end():
    at = _app()
    assert not at.exception
    _load_demo(at)
    assert not at.exception and not at.error
    rd = at.session_state["report_data"]
    assert rd.executive_verdict == "CRITICAL"
    assert rd.threat_findings and rd.ioc_list and rd.mitre_mapping and rd.recommendations


def test_every_page_renders_without_errors():
    import ui
    at = _load_demo(_app())
    for key, label in ui.NAV:
        at.segmented_control(key="nav").set_value(label).run()
        assert not at.exception, key
        assert not at.error, key


@pytest.mark.parametrize("mode", ["Light", "Dark", "Auto"])
def test_appearance_modes(mode):
    at = _load_demo(_app())
    at.segmented_control(key="appearance").set_value(mode).run()
    assert not at.exception


def test_overview_cta_navigates_to_hunter():
    import ui
    at = _load_demo(_app())
    next(b for b in at.button if b.key == "ov_all").click().run()
    assert at.session_state["nav"] == ui.NAV_LABEL["hunter"] and not at.exception


def test_exports_and_reports_buttons_work():
    import ui
    at = _load_demo(_app())
    at.segmented_control(key="nav").set_value(ui.NAV_LABEL["iocs"]).run()
    for k in ("exp_JSON", "exp_CSV", "exp_STIX 2.1", "exp_OpenIOC"):
        next(b for b in at.button if b.key == k).click().run()
        assert not at.error and not at.exception, k
    at.segmented_control(key="nav").set_value(ui.NAV_LABEL["reports"]).run()
    for k in ("gen_pdf", "gen_html", "gen_json"):
        next(b for b in at.button if b.key == k).click().run()
        assert not at.error and not at.exception, k


def test_baseline_roundtrip_changes_nothing_when_identical():
    import ui
    at = _load_demo(_app())
    at.segmented_control(key="nav").set_value(ui.NAV_LABEL["snapshots"]).run()
    next(b for b in at.button if b.key == "set_baseline").click().run()
    at.segmented_control(key="nav").set_value(ui.NAV_LABEL["snapshots"]).run()
    next(b for b in at.button if b.key == "do_compare").click().run()
    res = at.session_state["comparison_result"]
    assert res["new_processes"] == 0 and not at.exception


# ---- design system -----------------------------------------------------------------
def test_components_escape_untrusted_text():
    import ui
    evil = "<img src=x onerror=alert(1)>"
    for html in (ui.finding_card("high", evil, evil, [ui.chip(evil)]),
                 ui.data_table([{"A": evil}]), ui.stat_card(evil, evil), ui.kv([(evil, evil)]),
                 ui.empty_state("search", evil, evil), ui.page_header(evil, evil)):
        assert "<img src=x" not in html


def test_data_table_semantics_and_row_cap():
    import ui
    html = ui.data_table([{"A": i} for i in range(1000)], max_rows=50, caption="Cap")
    assert html.count("<tr>") == 51 and "Showing 50 of 1000" in html
    assert 'scope="col"' in html and "<caption>Cap</caption>" in html


def test_score_ring_is_labelled_for_screen_readers():
    import ui
    html = ui.score_ring(87, "HIGH", "high")
    assert 'role="img"' in html and "87 out of 100" in html


def test_every_icon_renders_and_decorative_icons_are_hidden():
    import ui
    for name in ui.design._ICONS:
        assert "<svg" in ui.icon(name) and 'aria-hidden="true"' in ui.icon(name)
    assert 'aria-label="Alert"' in ui.icon("alert", label="Alert")


def test_theme_css_has_both_palettes_and_reduced_motion():
    import ui
    assert "prefers-reduced-motion" in ui.design._CSS and "focus-visible" in ui.design._CSS
    assert ui.design.LIGHT.keys() == ui.design.DARK.keys()


# ---- dynamic components & evidence-based timeline ----------------------------------
def test_timeline_flags_attack_not_os_processes():
    from core.timeline import TimelineReconstructor
    eng = ThreatDetectionEngine()
    procs = copy.deepcopy(DEMO_PROCESSES)
    dets = eng.run_all_detections(processes=procs, connections=DEMO_CONNECTIONS,
                                  services=DEMO_SERVICES, command_lines=DEMO_COMMAND_LINES)
    cmd = {c["pid"]: c["command_line"] for c in DEMO_COMMAND_LINES}
    tr = TimelineReconstructor()
    tr.build_timeline(processes=[dict(p, command_line=cmd.get(p["pid"], "")) for p in procs])
    tr.escalate_from_detections(dets)
    sig = {e.process_name: e.significance for e in tr.entries if e.event_type and e.process_name}
    for routine in ("System", "smss.exe", "csrss.exe", "services.exe"):
        assert sig[routine] == "low", routine
    for bad in ("mimikatz.exe", "procdump64.exe", "winupdate.exe"):
        assert sig[bad] == "critical", bad


def test_count_up_numbers_keep_an_accessible_value():
    import ui
    html = ui.stat_card("IOCs", 80)
    assert "--to:80" in html and '<span class="sr-only">80</span>' in html
    assert "CRITICAL" in ui.stat_card("Risk", "CRITICAL") and "--to:" not in ui.stat_card("Risk", "CRITICAL")
    assert "--to:90" in ui.stat_card("Conf", "90%") and "cnt pct" in ui.stat_card("Conf", "90%")


def test_kill_chain_lights_only_observed_tactics():
    import ui
    order = ["Recon", "Execution", "Persistence", "Impact"]
    html = ui.kill_chain(order, {"Execution": 2, "Impact": 1})
    assert html.count('class="on') == 2 and "2 of 4 tactics" in html
    assert ui.kill_chain(order, {}).count('class="on') == 0


def test_process_tree_highlights_flagged_and_can_prune():
    import ui
    from core.process_tree import ProcessTreeBuilder
    tree = ProcessTreeBuilder().build_tree(copy.deepcopy(DEMO_PROCESSES))
    flagged = {1776: ["Credential Dumping"]}
    full = ui.process_tree(tree, flagged)
    pruned = ui.process_tree(tree, flagged, only_flagged=True)
    assert "mimikatz.exe" in full and "Credential Dumping" in pruned
    assert "notepad.exe" in full and "notepad.exe" not in pruned
    assert "<details" in full and 'role="tree"' in full


def test_process_tree_escapes_malicious_names():
    import ui
    from core.process_tree import ProcessNode
    evil = "<img src=x onerror=alert(1)>"
    node = ProcessNode(pid=1, name=evil, ppid=0, cmdline=evil)
    assert "<img src=x" not in ui.process_tree([node], {})


def test_timeline_and_terminal_feed_escape_input():
    import ui
    evil = "<script>alert(1)</script>"
    assert "<script>alert" not in ui.timeline_view([{"time": evil, "title": evil, "sig": "high", "category": evil, "desc": evil}])
    assert "<script>alert" not in ui.terminal_feed(evil, [("high", evil, evil, evil)])


def test_severity_bar_percentages():
    import ui
    html = ui.severity_bar([("Critical", 1, "critical"), ("High", 3, "high"), ("Medium", 0, "medium"), ("Low", 0, "low")])
    assert "25% of findings" in html and "75% of findings" in html


def test_processes_view_and_timeline_filter_work():
    import ui
    at = _load_demo(_app())
    at.segmented_control(key="nav").set_value(ui.NAV_LABEL["processes"]).run()
    at.toggle(key="pt_only").set_value(True).run()
    assert not at.exception
    at.segmented_control(key="nav").set_value(ui.NAV_LABEL["timeline"]).run()
    for v in ("All events", "Notable"):
        at.segmented_control(key="tl_view").set_value(v).run()
        assert not at.exception, v
