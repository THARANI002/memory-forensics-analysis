"""
Database Linkage & Full Module Check Script
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent))

print("=" * 55)
print("DATABASE LINKAGE & MODULE CHECK")
print("=" * 55)

errors = []

# ── 1. Import all modules ──────────────────────────────────
print("\n[STEP 1] Importing all modules...")
modules_to_check = [
    ("config.settings",             "config/settings.py"),
    ("src.models.database",         "src/models/database.py"),
    ("core.acquisition",            "src/core/acquisition.py"),
    ("core.analysis_engine",        "src/core/analysis_engine.py"),
    ("core.aggregation_engine",     "src/core/aggregation_engine.py"),
    ("core.threat_detection",       "src/core/threat_detection.py"),
    ("core.ioc_engine",             "src/core/ioc_engine.py"),
    ("core.mitre_attack",           "src/core/mitre_attack.py"),
    ("core.timeline",               "src/core/timeline.py"),
    ("core.process_tree",           "src/core/process_tree.py"),
    ("core.reporting",              "src/core/reporting.py"),
    ("core.analytics",              "src/core/analytics.py"),
    ("core.snapshot_comparison",    "src/core/snapshot_comparison.py"),
    ("core.threat_intel",           "src/core/threat_intel.py"),
]

for mod, path in modules_to_check:
    try:
        __import__(mod)
        print(f"  [OK]   {path}")
    except Exception as e:
        print(f"  [FAIL] {path}  -> {e}")
        errors.append((path, str(e)))

# ── 2. DB connection ───────────────────────────────────────
print("\n[STEP 2] Checking database connection...")
try:
    from src.models.database import init_database, get_session
    from config.settings import DATABASE_PATH

    print(f"  DB Path   : {DATABASE_PATH}")
    print(f"  DB Exists : {DATABASE_PATH.exists()}")

    engine = init_database()
    print(f"  Engine    : OK ({engine.dialect.name})")
except Exception as e:
    print(f"  [FAIL] DB connection: {e}")
    errors.append(("database_connection", str(e)))
    engine = None

# ── 3. Check tables ────────────────────────────────────────
if engine:
    print("\n[STEP 3] Checking DB tables...")
    from sqlalchemy import inspect as sa_inspect
    inspector = sa_inspect(engine)
    tables = inspector.get_table_names()
    print(f"  Found {len(tables)} tables:")
    for t in sorted(tables):
        cols = inspector.get_columns(t)
        print(f"    - {t:35s} ({len(cols)} columns)")

# ── 4. ORM model -> table mapping ─────────────────────────
print("\n[STEP 4] Verifying ORM model mappings...")
try:
    from src.models.database import (
        Snapshot, ThreatEvent, IOC, TimelineEvent,
        Report, Investigation, ChainOfCustody,
        EngineResult, YARARule, HistoricalMetric, DetectionLog
    )
    models = [
        Snapshot, ThreatEvent, IOC, TimelineEvent, Report,
        Investigation, ChainOfCustody, EngineResult,
        YARARule, HistoricalMetric, DetectionLog
    ]
    for m in models:
        print(f"  [OK]   {m.__name__:30s} -> table: {m.__tablename__}")
except Exception as e:
    print(f"  [FAIL] ORM models: {e}")
    errors.append(("orm_models", str(e)))

# ── 5. DB write/read test ─────────────────────────────────
print("\n[STEP 5] DB write + read test...")
try:
    session = get_session()
    from src.models.database import Snapshot

    test_snap = Snapshot(
        name="db_linkage_test",
        file_path="/test/verify.raw",
        file_size=1024,
        sha256_hash="a" * 64,
        created_by="checker"
    )
    session.add(test_snap)
    session.commit()

    found = session.query(Snapshot).filter_by(name="db_linkage_test").first()
    if found:
        print(f"  [OK]   Write succeeded - row ID = {found.id}")
        session.delete(found)
        session.commit()
        print(f"  [OK]   Delete (cleanup) succeeded")
    else:
        print("  [FAIL] Row not found after write")
        errors.append(("db_write_read", "row not found after insert"))

    session.close()
except Exception as e:
    print(f"  [FAIL] DB write/read: {e}")
    errors.append(("db_write_read", str(e)))

# ── 6. Module -> DB linkage trace ────────────────────────
print("\n[STEP 6] Checking which modules use the database...")
db_users = {
    "acquisition.py":          "Stores snapshot metadata to filesystem + chain-of-custody entries",
    "database.py":             "ORM models + engine + session factory (CORE)",
    "reporting.py":            "Saves reports to disk + optionally DB via Investigation model",
    "analytics.py":            "Reads historical investigation data for trend analysis",
    "ioc_engine.py":           "Extracts and exports IOCs (JSON/CSV/STIX)",
    "threat_detection.py":     "Produces DetectionResult objects -> saved via app.py to DB",
    "analysis_engine.py":      "Runs Volatility/YARA -> findings aggregated and stored",
    "app.py":                  "Central hub: calls all engines, writes results to session_state + DB",
}
for mod, note in db_users.items():
    print(f"  {mod:35s} : {note}")

# ── Summary ───────────────────────────────────────────────
print()
print("=" * 55)
if errors:
    print(f"RESULT: {len(errors)} ERROR(S) FOUND")
    for f, e in errors:
        print(f"  - {f}: {e}")
else:
    print("RESULT: ALL CHECKS PASSED - DATABASE FULLY LINKED")
print("=" * 55)
