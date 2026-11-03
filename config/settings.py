"""
Enterprise Memory Forensics Platform - Configuration
====================================================
Central configuration management for all platform modules.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:  # load .env so configured paths / API keys take effect
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
if load_dotenv:
    load_dotenv(BASE_DIR / ".env", override=False)


def _resolve(value: Optional[str], default: Path) -> Path:
    """Resolve an env-provided path relative to BASE_DIR (never the CWD)."""
    if not value:
        return default
    path = Path(value).expanduser()
    return path if path.is_absolute() else BASE_DIR / path


# FORENSICS_DATA_DIR relocates all writable state (Docker, tests, deployments).
DATA_DIR = _resolve(os.getenv("FORENSICS_DATA_DIR") or os.getenv("DATA_DIR"), BASE_DIR / "data")
MEMORY_DUMPS_DIR = DATA_DIR / "memory_dumps"
SNAPSHOTS_DIR = DATA_DIR / "snapshots"
REPORTS_DIR = DATA_DIR / "reports"
IOCS_DIR = DATA_DIR / "iocs"
CACHE_DIR = DATA_DIR / "cache"
ANALYTICS_DIR = DATA_DIR / "analytics"
RULES_DIR = _resolve(os.getenv("RULES_DIR"), BASE_DIR / "rules" / "yara")

# Ensure directories exist
for dir_path in [DATA_DIR, MEMORY_DUMPS_DIR, SNAPSHOTS_DIR, REPORTS_DIR, IOCS_DIR,
                 CACHE_DIR, ANALYTICS_DIR, RULES_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Database
DATABASE_PATH = DATA_DIR / "forensics.db" if os.getenv("FORENSICS_DATA_DIR") or os.getenv("DATA_DIR") \
    else _resolve(os.getenv("DATABASE_PATH"), DATA_DIR / "forensics.db")


@dataclass
class MemoryAcquisitionConfig:
    """Configuration for memory acquisition module."""
    supported_formats: List[str] = field(default_factory=lambda: [
        "raw", "lime", "aff4", "winpmem", "dumpit", "avml", "vmem", "mem", "hpak", "crash"
    ])
    hash_algorithm: str = "sha256"
    chunk_size: int = 8192
    verify_integrity: bool = True
    store_metadata: bool = True
    chain_of_custody: bool = True
    max_file_size_gb: int = 128


@dataclass
class VolatilityConfig:
    """Configuration for Volatility 3 integration."""
    plugins: List[str] = field(default_factory=lambda: [
        "windows.pslist.PsList",
        "windows.psscan.PsScan",
        "windows.pstree.PsTree",
        "windows.dlllist.DllList",
        "windows.malfind.Malfind",
        "windows.netscan.NetScan",
        "windows.svcscan.SvcScan",
        "windows.callbacks.Callbacks",
        "windows.driverirp.DriverIrp",
        "windows.modscan.ModScan",
        "windows.registry.hivelist.HiveList",
    ])
    timeout: int = 3600
    max_workers: int = 4
    symbol_path: Optional[str] = None


@dataclass
class YARAConfig:
    """Configuration for YARA engine."""
    rule_directories: List[str] = field(default_factory=lambda: [str(RULES_DIR)])
    max_rules: int = 10000
    timeout: int = 300
    include_memory_rules: bool = True
    include_malware_rules: bool = True
    include_shellcode_rules: bool = True
    include_cobalt_strike_rules: bool = True
    external_repositories: List[str] = field(default_factory=lambda: [
        "https://github.com/YARA-Rules/rules",
        "https://github.com/reversinglabs-research/rl-yara-rules",
    ])


@dataclass
class ThreatDetectionConfig:
    """Configuration for threat detection engine."""
    detection_modules: List[str] = field(default_factory=lambda: [
        "process_hollowing",
        "dll_injection",
        "reflective_dll",
        "process_doppelganging",
        "atombombing",
        "process_herpaderping",
        "rootkit_detection",
        "parent_pid_spoofing",
        "command_line_obfuscation",
        "fileless_malware",
        "powershell_abuse",
        "credential_dumping",
        "lsass_access",
        "persistence_mechanisms",
    ])
    confidence_threshold: float = 50.0
    min_engine_confirmations: int = 2
    signature_weight: float = 1.0
    heuristic_weight: float = 0.7
    anomaly_weight: float = 0.5


@dataclass
class ScoringWeights:
    """VirusTotal-style scoring weights."""
    signature_weight: float = 1.0
    heuristic_weight: float = 0.7
    anomaly_weight: float = 0.5
    engine_confirmations: int = 2


@dataclass
class ConfidenceLevels:
    """Confidence level thresholds."""
    confirmed_malicious: float = 90.0
    highly_suspicious: float = 70.0
    suspicious: float = 50.0
    possibly_suspicious: float = 30.0
    likely_benign: float = 0.0


@dataclass
class ThreatIntelConfig:
    """Configuration for threat intelligence integrations."""
    virustotal_api_key: Optional[str] = field(default_factory=lambda: os.getenv("VT_API_KEY"))
    misp_url: Optional[str] = field(default_factory=lambda: os.getenv("MISP_URL"))
    misp_api_key: Optional[str] = field(default_factory=lambda: os.getenv("MISP_API_KEY"))
    alienvault_api_key: Optional[str] = field(default_factory=lambda: os.getenv("OTX_API_KEY"))
    cache_ttl: int = 3600  # seconds
    rate_limit: int = 4  # requests per minute


@dataclass
class MITREConfig:
    """Configuration for MITRE ATT&CK mapping."""
    techniques: List[str] = field(default_factory=lambda: [
        "T1055",      # Process Injection
        "T1055.012",  # Process Hollowing
        "T1055.001",  # Dynamic-link Library Injection
        "T1620",      # Reflective Code Loading
        "T1014",      # Rootkit
        "T1003.001",  # LSASS Memory
        "T1056.001",  # Keylogging
        "T1071",      # Application Layer Protocol
        "T1059.001",  # PowerShell
        "T1003",      # OS Credential Dumping
        "T1547",      # Boot or Logon Autostart Execution
        "T1543",      # Create or Modify System Process
        "T1569",      # System Services
        "T1078",      # Valid Accounts
        "T1105",      # Ingress Tool Transfer
    ])
    generate_heatmap: bool = True
    color_scheme: str = "YlOrRd"


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    formats: List[str] = field(default_factory=lambda: ["pdf", "html", "json"])
    include_executive_summary: bool = True
    include_iocs: bool = True
    include_mitre_mapping: bool = True
    include_timeline: bool = True
    include_memory_comparison: bool = True
    include_recommendations: bool = True
    company_name: str = "Enterprise Security Operations"
    logo_path: Optional[str] = None


# Global Configurations
ACQUISITION_CONFIG = MemoryAcquisitionConfig()
VOLATILITY_CONFIG = VolatilityConfig()
YARA_CONFIG = YARAConfig()
DETECTION_CONFIG = ThreatDetectionConfig()
SCORING_WEIGHTS = ScoringWeights()
CONFIDENCE_LEVELS = ConfidenceLevels()
THREAT_INTEL_CONFIG = ThreatIntelConfig()
MITRE_CONFIG = MITREConfig()
REPORT_CONFIG = ReportConfig()

# MITRE ATT&CK Technique Details
MITRE_TECHNIQUES = {
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "description": "Adversaries may inject code into processes to evade process-based defenses.",
    },
    "T1055.012": {
        "name": "Process Hollowing",
        "tactic": "Defense Evasion",
        "description": "Adversaries may inject malicious code into suspended and hollowed processes.",
    },
    "T1055.001": {
        "name": "Dynamic-link Library Injection",
        "tactic": "Defense Evasion",
        "description": "Adversaries may inject dynamic-link libraries (DLLs) into processes.",
    },
    "T1620": {
        "name": "Reflective Code Loading",
        "tactic": "Defense Evasion",
        "description": "Adversaries may reflectively load code into a process.",
    },
    "T1014": {
        "name": "Rootkit",
        "tactic": "Defense Evasion",
        "description": "Adversaries may use rootkits to hide the presence of programs.",
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may access credentials stored in LSASS memory.",
    },
    "T1056.001": {
        "name": "Keylogging",
        "tactic": "Collection",
        "description": "Adversaries may log user keystrokes to intercept credentials.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands for execution.",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "description": "Adversaries may configure system settings to automatically execute a program.",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "description": "Adversaries may create or modify system processes for persistence.",
    },
    "T1569": {
        "name": "System Services",
        "tactic": "Execution",
        "description": "Adversaries may abuse system services to execute commands.",
    },
}

# Database Schema Version
DB_SCHEMA_VERSION = "1.0.0"

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s | %(name)s | %(levelname)s | %(message)s"

# Streamlit UI
PAGE_TITLE = "Enterprise Memory Forensics Platform"
PAGE_ICON = "🛡️"
LAYOUT = "wide"
INITIAL_SIDEBAR_STATE = "auto"  # expanded on desktop, collapsed on phones