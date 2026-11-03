#!/usr/bin/env python3
"""
Database Initialization Script
==============================
Initialize the SQLite database with all required tables.

Usage:
    python scripts/init_db.py
"""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Ensure stdout supports utf-8
if sys.stdout.encoding != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

try:
    from src.models.database import init_database
except ImportError:
    try:
        from models.database import init_database
    except ImportError:
        print("ERROR: Cannot import database module")
        sys.exit(1)

from config.settings import DATABASE_PATH


def main():
    print("=" * 60)
    print("Enterprise Memory Forensics Platform - Database Initialization")
    print("=" * 60)
    
    print(f"\nDatabase path: {DATABASE_PATH}")
    print("Creating tables...")
    
    try:
        engine = init_database()
        print("[OK] Database initialized successfully!")
        
        # List created tables
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        print(f"\n[INFO] Created {len(tables)} tables:")
        for table in sorted(tables):
            columns = inspector.get_columns(table)
            print(f"  - {table} ({len(columns)} columns)")
        
        print("\n[OK] Ready for use!")
        return 0
        
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())