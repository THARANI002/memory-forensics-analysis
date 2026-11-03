"""
Database Manager - Handles saving and loading analysis results to SQLite Database
"""

import os
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pathlib import Path
from sqlalchemy.orm import Session

# Add path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from models.database import (
        get_session, init_database,
        Snapshot, ThreatEvent, IOC, TimelineEvent, Report, Investigation,
        SeverityLevel, ConfidenceLevel, InvestigationStatus
    )
except ImportError:
    from src.models.database import (
        get_session, init_database,
        Snapshot, ThreatEvent, IOC, TimelineEvent, Report, Investigation,
        SeverityLevel, ConfidenceLevel, InvestigationStatus
    )

try:
    from config.settings import DATABASE_PATH
except ImportError:
    DATABASE_PATH = Path(__file__).resolve().parents[2] / "data" / "forensics.db"

from core.reporting import ReportData

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages saving and loading analysis results to the SQLite Database."""
    
    def __init__(self):
        try:
            if not os.path.exists(DATABASE_PATH):
                init_database()
        except Exception as e:
            logger.warning(f"Database init warning: {e}")
    
    def save_analysis_results(self, snapshot_meta: Dict, detections: List, iocs: List, mitre_mappings: List, report_data: ReportData) -> bool:
        """Save a complete analysis run to the database."""
        try:
            session = get_session()
        except Exception as e:
            logger.error(f"Failed to get database session: {e}")
            return False
            
        try:
            # 1. Create Snapshot
            snapshot = session.query(Snapshot).filter(
                Snapshot.sha256_hash == snapshot_meta.get("sha256_hash", "")
            ).first()
            
            if not snapshot:
                snapshot = Snapshot(
                    name=snapshot_meta.get("name", "Unknown"),
                    file_path=snapshot_meta.get("file_path", ""),
                    file_size=snapshot_meta.get("file_size", 0),
                    sha256_hash=snapshot_meta.get("sha256_hash", "unknown"),
                    acquisition_tool=snapshot_meta.get("acquisition_tool", "unknown"),
                    system_info=snapshot_meta.get("system_info", {}),
                    extra_data=snapshot_meta,
                    created_at=datetime.now(timezone.utc)
                )
                session.add(snapshot)
                session.flush()

            # 2. Create Investigation
            inv = session.query(Investigation).filter(
                Investigation.case_number == report_data.case_number
            ).first()
            
            if not inv:
                inv = Investigation(
                    title=report_data.title,
                    case_number=report_data.case_number or f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}-{uuid.uuid4().hex[:6]}",
                    snapshot_id=snapshot.id,
                    status=InvestigationStatus.COMPLETED,
                    analyst=report_data.analyst or "Unknown",
                )
                session.add(inv)
                session.flush()

            # 3. Create Threat Events
            for det in detections:
                try:
                    if not hasattr(det, 'detected') or not det.detected:
                        continue
                    
                    try:
                        sev = SeverityLevel[det.severity.upper()]
                    except (KeyError, AttributeError):
                        sev = SeverityLevel.MEDIUM
                    
                    conf_level = ConfidenceLevel.POSSIBLY_SUSPICIOUS
                    if hasattr(det, 'confidence'):
                        if det.confidence >= 90:
                            conf_level = ConfidenceLevel.CONFIRMED_MALICIOUS
                        elif det.confidence >= 70:
                            conf_level = ConfidenceLevel.HIGHLY_SUSPICIOUS
                        elif det.confidence >= 50:
                            conf_level = ConfidenceLevel.SUSPICIOUS

                    te = ThreatEvent(
                        snapshot_id=snapshot.id,
                        event_type=det.technique if hasattr(det, 'technique') else "Unknown",
                        severity=sev,
                        confidence=det.confidence if hasattr(det, 'confidence') else 0.0,
                        confidence_level=conf_level,
                        title=det.technique if hasattr(det, 'technique') else "Unknown",
                        description=det.description if hasattr(det, 'description') else "",
                        detection_engine=getattr(det, "detection_source", "heuristic"),
                        mitre_technique=det.technique_id if hasattr(det, 'technique_id') else "",
                        raw_evidence=det.evidence if hasattr(det, 'evidence') else {},
                    )
                    session.add(te)
                except Exception as e:
                    logger.warning(f"Failed to save threat event: {e}")
                    continue
            
            # 4. Create IOCs
            for ioc_data in iocs:
                try:
                    ioc = IOC(
                        ioc_type=ioc_data.ioc_type if hasattr(ioc_data, 'ioc_type') else "unknown",
                        value=ioc_data.value if hasattr(ioc_data, 'value') else "",
                        confidence=ioc_data.confidence if hasattr(ioc_data, 'confidence') else 0.0,
                        source=ioc_data.source if hasattr(ioc_data, 'source') else "unknown",
                    )
                    ioc.investigations.append(inv)
                    session.add(ioc)
                except Exception as e:
                    logger.warning(f"Failed to save IOC: {e}")
                    continue

            # 5. Create Report
            try:
                report_record = Report(
                    investigation_id=inv.id,
                    report_type="analysis_run",
                    title=report_data.title,
                    summary=report_data.executive_summary,
                    threat_score=report_data.threat_score,
                    confidence_score=report_data.confidence_score,
                    memory_health_score=report_data.memory_health_score,
                    executive_verdict=report_data.executive_verdict,
                    total_threats=report_data.total_threats,
                    critical_count=report_data.critical_count,
                    high_count=report_data.high_count,
                    medium_count=report_data.medium_count,
                    low_count=report_data.low_count,
                    ioc_count=report_data.total_iocs,
                    top_mitre_technique=report_data.top_mitre_technique,
                    most_dangerous_process=report_data.most_dangerous_process,
                    report_data=report_data.to_dict()
                )
                session.add(report_record)
            except Exception as e:
                logger.warning(f"Failed to save report record: {e}")

            session.commit()
            return True

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save: {e}")
            return False
        finally:
            session.close()

    def get_historical_reports(self) -> List[Dict]:
        try:
            session = get_session()
        except Exception:
            return []
            
        try:
            reports = session.query(Report).order_by(Report.generated_at.desc()).limit(100).all()
            return [
                {
                    "title": r.title,
                    "generated_at": r.generated_at.isoformat(),
                    "threat_score": r.threat_score,
                    "verdict": r.executive_verdict,
                    "total_threats": r.total_threats
                }
                for r in reports
            ]
        except Exception:
            return []
        finally:
            session.close()

    def get_report_history(self, limit: int = 200) -> List[Dict]:
        """
        Fetch full historical trend data across all past investigations,
        joining Report -> Investigation -> Snapshot so callers get one row
        per completed analysis run with everything a trend view needs.

        Returns rows sorted oldest -> newest (best for time-series charts).
        """
        try:
            session = get_session()
        except Exception:
            return []

        try:
            rows = (
                session.query(Report, Investigation, Snapshot)
                .join(Investigation, Report.investigation_id == Investigation.id)
                .outerjoin(Snapshot, Investigation.snapshot_id == Snapshot.id)
                .order_by(Report.generated_at.asc())
                .limit(limit)
                .all()
            )

            history = []
            for report, investigation, snapshot in rows:
                try:
                    history.append({
                        "report_id": report.id,
                        "investigation_id": investigation.id,
                        "case_number": investigation.case_number,
                        "snapshot_name": snapshot.name if snapshot else "Unknown",
                        "generated_at": report.generated_at.isoformat() if report.generated_at else "",
                        "title": report.title,
                        "verdict": report.executive_verdict,
                        "threat_score": report.threat_score or 0.0,
                        "confidence_score": report.confidence_score or 0.0,
                        "memory_health_score": report.memory_health_score or 100.0,
                        "total_threats": report.total_threats or 0,
                        "critical_count": report.critical_count or 0,
                        "high_count": report.high_count or 0,
                        "medium_count": report.medium_count or 0,
                        "low_count": report.low_count or 0,
                        "ioc_count": report.ioc_count or 0,
                        "top_mitre_technique": report.top_mitre_technique or "",
                        "most_dangerous_process": report.most_dangerous_process or "",
                    })
                except Exception as e:
                    logger.warning(f"Skipping malformed history row: {e}")
                    continue

            return history
        except Exception as e:
            logger.error(f"Failed to fetch report history: {e}")
            return []
        finally:
            session.close()