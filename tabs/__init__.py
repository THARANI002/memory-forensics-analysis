"""
tabs package
=============
Each of the 7 analysis tabs lives in its own module so they can be
developed, tested, and reviewed independently of app.py.

    executive_overview.py  -> render_executive_overview()
    snapshot_comparison.py -> render_snapshot_comparison()
    threat_hunter.py       -> render_threat_hunter()
    ioc_center.py          -> render_ioc_center()
    mitre_attack.py        -> render_mitre_attack()
    timeline.py            -> render_timeline()
    reports.py             -> render_reports()
    history_trends.py      -> render_history_trends()
"""

from .executive_overview import render_executive_overview
from .snapshot_comparison import render_snapshot_comparison
from .threat_hunter import render_threat_hunter
from .ioc_center import render_ioc_center
from .mitre_attack import render_mitre_attack
from .process_tree import render_process_tree
from .timeline import render_timeline
from .reports import render_reports
from .history_trends import render_history_trends

__all__ = [
    "render_executive_overview",
    "render_snapshot_comparison",
    "render_threat_hunter",
    "render_ioc_center",
    "render_mitre_attack",
    "render_process_tree",
    "render_timeline",
    "render_reports",
    "render_history_trends",
]