"""
Enterprise Memory Forensics Platform - Database Models
=======================================================
SQLAlchemy ORM models for all platform data.
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pathlib import Path

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime, 
    Boolean, Text, JSON, ForeignKey, Enum, Table
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from sqlalchemy.types import TypeDecorator
import enum

# Import settings - with fallback
try:
    from config.settings import DATABASE_PATH
except ImportError:
    DATABASE_PATH = Path(__file__).resolve().parents[2] / "data" / "forensics.db"

Base = declarative_base()


class JSONEncodedDict(TypeDecorator):
    """JSON-encoded dictionary type."""
    impl = Text
    
    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return None
    
    def process_result_value(self, value, dialect):
        if value is not None:
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}


# =============================================================================
# ENUMS
# =============================================================================

class SeverityLevel(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(enum.Enum):
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    HIGHLY_SUSPICIOUS = "highly_suspicious"
    SUSPICIOUS = "suspicious"
    POSSIBLY_SUSPICIOUS = "possibly_suspicious"
    LIKELY_BENIGN = "likely_benign"


class InvestigationStatus(enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CLOSED = "closed"


# =============================================================================
# ASSOCIATION TABLES
# =============================================================================

investigation_iocs = Table(
    'investigation_iocs',
    Base.metadata,
    Column('investigation_id', Integer, ForeignKey('investigations.id')),
    Column('ioc_id', Integer, ForeignKey('iocs.id'))
)


# =============================================================================
# MODELS - NO RESERVED ATTRIBUTE NAMES
# =============================================================================

class Snapshot(Base):
    __tablename__ = 'snapshots'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    file_path = Column(String(1024), nullable=False)
    file_size = Column(Integer, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    md5_hash = Column(String(32), default="")
    acquisition_tool = Column(String(100), default="unknown")
    acquisition_format = Column(String(50), default="raw")
    acquisition_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    system_info = Column(JSONEncodedDict, default={})
    operating_system = Column(String(100), default="")
    architecture = Column(String(20), default="")
    hostname = Column(String(100), default="")
    is_baseline = Column(Boolean, default=False)
    extra_data = Column(JSONEncodedDict, default={})
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = Column(String(100), default="system")
    
    threat_events = relationship("ThreatEvent", back_populates="snapshot")
    timeline_events = relationship("TimelineEvent", back_populates="snapshot")
    engine_results = relationship("EngineResult", back_populates="snapshot")
    investigations = relationship("Investigation", back_populates="snapshot")
    chain_of_custody = relationship("ChainOfCustody", back_populates="snapshot")


class ThreatEvent(Base):
    __tablename__ = 'threat_events'
    
    id = Column(Integer, primary_key=True)
    snapshot_id = Column(Integer, ForeignKey('snapshots.id'))
    event_type = Column(String(100), nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False)
    confidence = Column(Float, nullable=False)
    confidence_level = Column(Enum(ConfidenceLevel), default=ConfidenceLevel.SUSPICIOUS)
    title = Column(String(255), nullable=False)
    description = Column(Text, default="")
    process_name = Column(String(255), default="")
    process_id = Column(Integer, nullable=True)
    detection_engine = Column(String(50), default="heuristic")
    mitre_technique = Column(String(20), default="")
    mitre_tactic = Column(String(50), default="")
    indicators = Column(JSONEncodedDict, default={})
    raw_evidence = Column(JSONEncodedDict, default={})
    score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    snapshot = relationship("Snapshot", back_populates="threat_events")
    iocs = relationship("IOC", back_populates="threat_event")
    detection_logs = relationship("DetectionLog", back_populates="threat_event")


class IOC(Base):
    __tablename__ = 'iocs'
    
    id = Column(Integer, primary_key=True)
    threat_event_id = Column(Integer, ForeignKey('threat_events.id'), nullable=True)
    ioc_type = Column(String(50), nullable=False)
    value = Column(Text, nullable=False)
    description = Column(Text, default="")
    source = Column(String(100), default="memory_forensics")
    confidence = Column(Float, default=0.0)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    times_seen = Column(Integer, default=1)
    tags = Column(JSONEncodedDict, default=[])
    enrichment_data = Column(JSONEncodedDict, default={})
    virustotal_data = Column(JSONEncodedDict, default={})
    misp_data = Column(JSONEncodedDict, default={})
    otx_data = Column(JSONEncodedDict, default={})
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    threat_event = relationship("ThreatEvent", back_populates="iocs")
    investigations = relationship("Investigation", secondary=investigation_iocs, back_populates="iocs")


class TimelineEvent(Base):
    __tablename__ = 'timeline_events'
    
    id = Column(Integer, primary_key=True)
    snapshot_id = Column(Integer, ForeignKey('snapshots.id'))
    event_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    event_type = Column(String(50), nullable=False)
    category = Column(String(50), nullable=False)
    description = Column(Text, nullable=False)
    process_name = Column(String(255), default="")
    process_id = Column(Integer, nullable=True)
    parent_process = Column(String(255), default="")
    parent_pid = Column(Integer, nullable=True)
    details = Column(JSONEncodedDict, default={})
    significance = Column(String(20), default="medium")
    source = Column(String(50), default="memory_analysis")
    related_events = Column(JSONEncodedDict, default=[])
    iocs = Column(JSONEncodedDict, default=[])
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    snapshot = relationship("Snapshot", back_populates="timeline_events")


class Investigation(Base):
    __tablename__ = 'investigations'
    
    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    case_number = Column(String(50), unique=True, nullable=False)
    status = Column(Enum(InvestigationStatus), default=InvestigationStatus.OPEN)
    snapshot_id = Column(Integer, ForeignKey('snapshots.id'))
    baseline_snapshot_id = Column(Integer, nullable=True)
    analyst = Column(String(100), default="")
    description = Column(Text, default="")
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    snapshot = relationship("Snapshot", foreign_keys=[snapshot_id], back_populates="investigations")
    reports = relationship("Report", back_populates="investigation")
    iocs = relationship("IOC", secondary=investigation_iocs, back_populates="investigations")


class Report(Base):
    __tablename__ = 'reports'
    
    id = Column(Integer, primary_key=True)
    investigation_id = Column(Integer, ForeignKey('investigations.id'))
    report_type = Column(String(50), default="analysis_run")
    file_path = Column(String(1024), default="")
    title = Column(String(255), nullable=False)
    summary = Column(Text, default="")
    threat_score = Column(Float, default=0.0)
    confidence_score = Column(Float, default=0.0)
    memory_health_score = Column(Float, default=100.0)
    executive_verdict = Column(String(50), default="CLEAN")
    total_threats = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    ioc_count = Column(Integer, default=0)
    top_mitre_technique = Column(String(100), default="")
    most_dangerous_process = Column(String(255), default="")
    report_data = Column(JSONEncodedDict, default={})
    generated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    investigation = relationship("Investigation", back_populates="reports")


class ChainOfCustody(Base):
    __tablename__ = 'chain_of_custody'
    
    id = Column(Integer, primary_key=True)
    snapshot_id = Column(Integer, ForeignKey('snapshots.id'))
    action = Column(String(50), nullable=False)
    performed_by = Column(String(100), nullable=False)
    performed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    description = Column(Text, default="")
    hash_before = Column(String(64), default="")
    hash_after = Column(String(64), default="")
    location = Column(String(1024), default="")
    witnesses = Column(JSONEncodedDict, default=[])
    digital_signature = Column(String(512), default="")
    verification_status = Column(String(50), default="verified")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    snapshot = relationship("Snapshot", back_populates="chain_of_custody")


class EngineResult(Base):
    __tablename__ = 'engine_results'
    
    id = Column(Integer, primary_key=True)
    snapshot_id = Column(Integer, ForeignKey('snapshots.id'))
    engine_name = Column(String(50), nullable=False)
    plugin_name = Column(String(100), default="")
    status = Column(String(20), default="success")
    findings_count = Column(Integer, default=0)
    execution_time = Column(Float, default=0.0)
    raw_output = Column(Text, default="")
    error_message = Column(Text, default="")
    parsed_data = Column(JSONEncodedDict, default={})
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    snapshot = relationship("Snapshot", back_populates="engine_results")


class YARARule(Base):
    __tablename__ = 'yara_rules'
    
    id = Column(Integer, primary_key=True)
    rule_name = Column(String(255), nullable=False)
    namespace = Column(String(255), default="")
    file_path = Column(String(1024), default="")
    tags = Column(JSONEncodedDict, default=[])
    rule_meta = Column(JSONEncodedDict, default={})
    rule_hash = Column(String(64), default="")
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class HistoricalMetric(Base):
    __tablename__ = 'historical_metrics'
    
    id = Column(Integer, primary_key=True)
    metric_type = Column(String(50), nullable=False)
    metric_name = Column(String(100), nullable=False)
    value = Column(Float, default=0.0)
    category = Column(String(50), default="")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    metric_data = Column(JSONEncodedDict, default={})
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class DetectionLog(Base):
    __tablename__ = 'detection_logs'
    
    id = Column(Integer, primary_key=True)
    threat_event_id = Column(Integer, ForeignKey('threat_events.id'))
    detection_module = Column(String(100), nullable=False)
    detection_type = Column(String(50), default="heuristic")
    result = Column(JSONEncodedDict, default={})
    is_positive = Column(Boolean, default=False)
    confidence = Column(Float, default=0.0)
    details = Column(JSONEncodedDict, default={})
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    threat_event = relationship("ThreatEvent", back_populates="detection_logs")


# =============================================================================
# DATABASE SESSION MANAGEMENT
# =============================================================================

_engine = None
_SessionLocal = None


def init_database(db_path=None):
    """Initialize the database connection and create tables."""
    global _engine, _SessionLocal
    
    if db_path is None:
        db_path = DATABASE_PATH
    
    # Ensure directory exists
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Create engine
    _engine = create_engine(f'sqlite:///{db_path}', echo=False)
    
    # Create tables
    Base.metadata.create_all(_engine)
    
    # Create session factory
    _SessionLocal = sessionmaker(bind=_engine)
    
    return _engine


def get_session() -> Session:
    """Get a database session."""
    if _SessionLocal is None:
        init_database()
    return _SessionLocal()