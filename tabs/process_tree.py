"""
Processes
=========
Interactive, collapsible process tree. Chains that triggered detections are
highlighted so the path from initial execution to payload is easy to follow.
"""

import re

import streamlit as st

import ui

_PID = re.compile(r"PID\s+(\d+)")


def _flagged(detections):
    """Map PID -> technique names, from detection process indicators and evidence."""
    out = {}
    for d in detections:
        if not getattr(d, "detected", False):
            continue
        pids = set()
        for ind in getattr(d, "process_indicators", []) or []:
            pids.update(int(p) for p in _PID.findall(str(ind)))
        for ev in getattr(d, "evidence", []) or []:
            if isinstance(ev, dict) and isinstance(ev.get("pid"), int):
                pids.add(ev["pid"])
        for pid in pids:
            names = out.setdefault(pid, [])
            if d.technique not in names:
                names.append(d.technique)
    return out


def _count(nodes):
    total = 0
    for n in nodes:
        total += 1 + _count(n.children)
    return total


def _walk(nodes):
    for n in nodes:
        yield n
        yield from _walk(n.children)


def render_process_tree():
    """Render the Processes view."""
    ui.md(ui.page_header("Processes", "Follow the chain from first execution to payload.", "cpu"))

    tree = st.session_state.process_tree
    if not st.session_state.analysis_complete or not tree:
        ui.md(ui.empty_state("cpu", "No process data", "Run an analysis that includes a process list to see the tree."))
        return

    flagged = _flagged(st.session_state.threat_detections)
    nodes = list(_walk(tree))
    hidden_techs = {"Rootkit"}
    inject_techs = {"Process Hollowing", "DLL Injection", "Reflective DLL Loading"}
    hidden = sum(1 for n in nodes if getattr(n, "is_hidden", False) or hidden_techs & set(flagged.get(n.pid, [])))
    injected = sum(1 for n in nodes if getattr(n, "is_injected", False) or inject_techs & set(flagged.get(n.pid, [])))
    flagged_count = len({n.pid for n in nodes if n.pid in flagged or getattr(n, "is_hidden", False) or getattr(n, "is_injected", False)})

    ui.md(ui.stat_grid([
        ui.stat_card("Processes", len(nodes), "blue", "In the tree", "cpu", 0),
        ui.stat_card("Flagged", flagged_count, "critical" if flagged_count else "ok", "Tied to detections", "alert", 1),
        ui.stat_card("Hidden", hidden, "high" if hidden else "ok", "Unlinked from process list", "lock", 2),
        ui.stat_card("Injected", injected, "high" if injected else "ok", "Code injection targets", "bug", 3),
    ], 4))

    ui.md(ui.section("Process tree", "Click a row to expand or collapse its children"))
    only = st.toggle("Show only suspicious chains", value=False, key="pt_only")
    ui.md(ui.process_tree(tree, flagged, only_flagged=only))
