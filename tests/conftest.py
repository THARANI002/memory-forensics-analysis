import os, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Isolate all writable state BEFORE any project module is imported.
os.environ["FORENSICS_DATA_DIR"] = tempfile.mkdtemp(prefix="forensics_test_")
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
