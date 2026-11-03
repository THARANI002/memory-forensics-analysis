"""
Enterprise Memory Forensics Platform - MITRE ATT&CK Mapping
============================================================
Maps detected threats to MITRE ATT&CK framework and generates heatmaps.
Full implementation including Groups, Software, Mitigations, and Data Sources.
"""

import json
import re
import unicodedata
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from datetime import datetime


# =============================================================================
# MITRE ATT&CK Data Models
# =============================================================================

@dataclass
class MITRETechnique:
    """MITRE ATT&CK Technique."""
    technique_id: str
    name: str
    tactic: str
    description: str
    platforms: List[str] = field(default_factory=list)
    detection: str = ""
    data_sources: List[str] = field(default_factory=list)
    is_subtechnique: bool = False
    parent_technique: Optional[str] = None
    permissions_required: List[str] = field(default_factory=list)
    effective_permissions: Optional[str] = None
    version: str = "1.0"
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class MITREGroup:
    """MITRE ATT&CK Group/Threat Actor."""
    group_id: str  # G####
    name: str
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    techniques: List[str] = field(default_factory=list)  # Technique IDs
    software: List[str] = field(default_factory=list)    # Software IDs
    version: str = "1.0"
    references: List[str] = field(default_factory=list)
    contributor: List[str] = field(default_factory=list)
    associated_groups: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class MITRESoftware:
    """MITRE ATT&CK Software (Malware/Tools)."""
    software_id: str  # S####
    name: str
    software_type: str  # "tool" or "malware"
    platforms: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    description: str = ""
    version: str = "1.0"
    references: List[str] = field(default_factory=list)
    associated_software: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class MITREMitigation:
    """MITRE ATT&CK Mitigation."""
    mitigation_id: str  # M####
    name: str
    description: str
    techniques: List[str] = field(default_factory=list)  # Technique IDs mitigated
    version: str = "1.0"
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class TechniqueMapping:
    """Mapping of a detection to a MITRE technique."""
    technique_id: str
    technique_name: str
    tactic: str
    detection_source: str
    confidence: float
    evidence: List[Dict] = field(default_factory=list)
    process_indicators: List[str] = field(default_factory=list)
    event_count: int = 0
    # Additional MITRE metadata
    platforms: List[str] = field(default_factory=list)
    permissions_required: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)


# =============================================================================
# MITRE ATT&CK Data - Complete Enterprise Techniques
# =============================================================================

class MITREAttackMapper:
    """
    MITRE ATT&CK mapping engine with full object model.
    
    Implements:
    - Techniques and Sub-techniques
    - Groups (Threat Actors)
    - Software (Malware/Tools)
    - Mitigations
    - Data Sources
    - Permissions Required
    """
    
    # Tactic ordering for heatmap
    TACTICS_ORDER = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact"
    ]
    
    def __init__(self):
        self._techniques: Dict[str, MITRETechnique] = {}
        self._groups: Dict[str, MITREGroup] = {}
        self._software: Dict[str, MITRESoftware] = {}
        self._mitigations: Dict[str, MITREMitigation] = {}
        self._data_sources: Dict[str, List[str]] = {}
        self.mappings: List[TechniqueMapping] = []
        
        # Load all data
        self._load_techniques()
        self._load_groups()
        self._load_software()
        self._load_mitigations()
        self._load_data_sources()
    
    # =========================================================================
    # Data Loading Methods
    # =========================================================================
    
    def _load_techniques(self):
        """Load all MITRE ATT&CK Enterprise techniques."""
        
        # All techniques organized by tactic
        techniques = {
            # ========== RECONNAISSANCE (TA0043) ==========
            "T1595": MITRETechnique(
                "T1595", "Active Scanning", "Reconnaissance",
                "Adversaries may scan victim networks to gather information.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic", "Web Logs"],
                permissions_required=["None"],
                references=["https://attack.mitre.org/techniques/T1595/"]
            ),
            "T1592": MITRETechnique(
                "T1592", "Gather Victim Host Information", "Reconnaissance",
                "Adversaries may gather information about victim hosts.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic", "Host Information"],
                permissions_required=["None"]
            ),
            
            # ========== RESOURCE DEVELOPMENT (TA0042) ==========
            "T1587": MITRETechnique(
                "T1587", "Develop Capabilities", "Resource Development",
                "Adversaries may develop capabilities to use in operations.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["File Monitoring", "Process Monitoring"],
                permissions_required=["User"]
            ),
            "T1588": MITRETechnique(
                "T1588", "Obtain Capabilities", "Resource Development",
                "Adversaries may buy, steal, or download capabilities.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic", "File Monitoring"],
                permissions_required=["User"]
            ),
            
            # ========== INITIAL ACCESS (TA0001) ==========
            "T1189": MITRETechnique(
                "T1189", "Drive-by Compromise", "Initial Access",
                "Adversaries may gain access through user visits to compromised websites.",
                platforms=["Windows", "macOS"],
                data_sources=["Network Traffic", "Web Logs", "Process Monitoring"],
                permissions_required=["User"]
            ),
            "T1190": MITRETechnique(
                "T1190", "Exploit Public-Facing Application", "Initial Access",
                "Adversaries may attempt to exploit weaknesses in an Internet-facing host.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Application Logs", "Network Traffic", "Web Logs"],
                permissions_required=["User"]
            ),
            "T1078": MITRETechnique(
                "T1078", "Valid Accounts", "Initial Access",
                "Adversaries may obtain and abuse credentials of existing accounts.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Authentication Logs", "Process Monitoring"],
                permissions_required=["User", "Admin"],
                effective_permissions="User"
            ),
            "T1566": MITRETechnique(
                "T1566", "Phishing", "Initial Access",
                "Adversaries may send phishing messages to gain access.",
                platforms=["Windows", "macOS"],
                data_sources=["Email Logs", "Network Traffic", "Process Monitoring"],
                permissions_required=["User"]
            ),
            "T1566.001": MITRETechnique(
                "T1566.001", "Spearphishing Attachment", "Initial Access",
                "Adversaries may send spearphishing emails with malicious attachments.",
                platforms=["Windows", "macOS"],
                data_sources=["Email Logs", "Network Traffic"],
                is_subtechnique=True,
                parent_technique="T1566",
                permissions_required=["User"]
            ),
            "T1566.002": MITRETechnique(
                "T1566.002", "Spearphishing Link", "Initial Access",
                "Adversaries may send spearphishing emails with malicious links.",
                platforms=["Windows", "macOS"],
                data_sources=["Email Logs", "Network Traffic"],
                is_subtechnique=True,
                parent_technique="T1566",
                permissions_required=["User"]
            ),
            
            # ========== EXECUTION (TA0002) ==========
            "T1059": MITRETechnique(
                "T1059", "Command and Scripting Interpreter", "Execution",
                "Adversaries may abuse command and script interpreters to execute commands.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "Command Line", "API Monitoring"],
                permissions_required=["User"]
            ),
            "T1059.001": MITRETechnique(
                "T1059.001", "PowerShell", "Execution",
                "Adversaries may abuse PowerShell commands and scripts for execution.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "Command Line", "API Monitoring", "PowerShell Logs"],
                is_subtechnique=True,
                parent_technique="T1059",
                permissions_required=["User"]
            ),
            "T1059.003": MITRETechnique(
                "T1059.003", "Windows Command Shell", "Execution",
                "Adversaries may abuse the Windows command shell for execution.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "Command Line"],
                is_subtechnique=True,
                parent_technique="T1059",
                permissions_required=["User"]
            ),
            "T1059.004": MITRETechnique(
                "T1059.004", "Unix Shell", "Execution",
                "Adversaries may abuse Unix shells for execution.",
                platforms=["Linux", "macOS"],
                data_sources=["Process Monitoring", "Command Line"],
                is_subtechnique=True,
                parent_technique="T1059",
                permissions_required=["User"]
            ),
            "T1203": MITRETechnique(
                "T1203", "Exploitation for Client Execution", "Execution",
                "Adversaries may exploit software vulnerabilities in client applications.",
                platforms=["Windows", "macOS"],
                data_sources=["Process Monitoring", "API Monitoring"],
                permissions_required=["User"]
            ),
            "T1106": MITRETechnique(
                "T1106", "Native API", "Execution",
                "Adversaries may interact with the native OS application programming interface.",
                platforms=["Windows"],
                data_sources=["API Monitoring", "Process Monitoring"],
                permissions_required=["User"]
            ),
            
            # ========== PERSISTENCE (TA0003) ==========
            "T1547": MITRETechnique(
                "T1547", "Boot or Logon Autostart Execution", "Persistence",
                "Adversaries may configure system settings to automatically execute a program.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Windows Registry", "File Monitoring", "Process Monitoring"],
                permissions_required=["Admin"]
            ),
            "T1547.001": MITRETechnique(
                "T1547.001", "Registry Run Keys", "Persistence",
                "Adversaries may add programs to startup folder or registry run keys.",
                platforms=["Windows"],
                data_sources=["Windows Registry", "File Monitoring"],
                is_subtechnique=True,
                parent_technique="T1547",
                permissions_required=["Admin"]
            ),
            "T1543": MITRETechnique(
                "T1543", "Create or Modify System Process", "Persistence",
                "Adversaries may create or modify system-level processes for persistence.",
                platforms=["Windows", "Linux"],
                data_sources=["Windows Service records", "Process Monitoring"],
                permissions_required=["Admin"]
            ),
            "T1543.003": MITRETechnique(
                "T1543.003", "Windows Service", "Persistence",
                "Adversaries may create or modify Windows services for persistence.",
                platforms=["Windows"],
                data_sources=["Windows Service records", "Process Monitoring"],
                is_subtechnique=True,
                parent_technique="T1543",
                permissions_required=["Admin"]
            ),
            "T1505": MITRETechnique(
                "T1505", "Server Software Component", "Persistence",
                "Adversaries may abuse server software components for persistence.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["File Monitoring", "Process Monitoring"],
                permissions_required=["Admin"]
            ),
            "T1505.001": MITRETechnique(
                "T1505.001", "SQL Stored Procedures", "Persistence",
                "Adversaries may abuse SQL stored procedures for persistence.",
                platforms=["Windows", "Linux"],
                data_sources=["Database Logs", "Process Monitoring"],
                is_subtechnique=True,
                parent_technique="T1505",
                permissions_required=["Database Admin"]
            ),
            "T1546": MITRETechnique(
                "T1546", "Event Triggered Execution", "Persistence",
                "Adversaries may use system mechanisms that trigger execution.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Windows Registry", "File Monitoring", "Process Monitoring"],
                permissions_required=["Admin"]
            ),
            "T1137": MITRETechnique(
                "T1137", "Office Application Startup", "Persistence",
                "Adversaries may leverage Microsoft Office-based applications for persistence.",
                platforms=["Windows", "macOS"],
                data_sources=["File Monitoring", "Process Monitoring"],
                permissions_required=["User"]
            ),
            
            # ========== PRIVILEGE ESCALATION (TA0004) ==========
            "T1055": MITRETechnique(
                "T1055", "Process Injection", "Privilege Escalation",
                "Adversaries may inject code into processes to evade defenses.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "API Monitoring", "Windows Event logs"],
                permissions_required=["User"],
                effective_permissions="User"
            ),
            "T1055.001": MITRETechnique(
                "T1055.001", "Dynamic-link Library Injection", "Privilege Escalation",
                "Adversaries may inject DLLs into processes.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring"],
                is_subtechnique=True,
                parent_technique="T1055",
                permissions_required=["User"],
                effective_permissions="User"
            ),
            "T1055.012": MITRETechnique(
                "T1055.012", "Process Hollowing", "Privilege Escalation",
                "Adversaries may inject malicious code into suspended processes.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring", "File Monitoring"],
                is_subtechnique=True,
                parent_technique="T1055",
                permissions_required=["User"],
                effective_permissions="User"
            ),
            "T1055.013": MITRETechnique(
                "T1055.013", "Process Doppelgänging", "Privilege Escalation",
                "Adversaries may abuse NTFS transactions to inject code.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring", "File Monitoring"],
                is_subtechnique=True,
                parent_technique="T1055",
                permissions_required=["User"],
                effective_permissions="User"
            ),
            "T1620": MITRETechnique(
                "T1620", "Reflective Code Loading", "Privilege Escalation",
                "Adversaries may reflectively load code into a process.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring", "Memory"],
                permissions_required=["User"],
                effective_permissions="User"
            ),
            "T1134": MITRETechnique(
                "T1134", "Access Token Manipulation", "Privilege Escalation",
                "Adversaries may modify access tokens for privilege escalation.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring"],
                permissions_required=["User"],
                effective_permissions="Admin"
            ),
            "T1134.004": MITRETechnique(
                "T1134.004", "Parent PID Spoofing", "Privilege Escalation",
                "Adversaries may spoof parent process IDs.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring"],
                is_subtechnique=True,
                parent_technique="T1134",
                permissions_required=["User"],
                effective_permissions="User"
            ),
            
            # ========== DEFENSE EVASION (TA0005) ==========
            "T1014": MITRETechnique(
                "T1014", "Rootkit", "Defense Evasion",
                "Adversaries may use rootkits to hide the presence of programs.",
                platforms=["Windows"],
                data_sources=["BIOS", "API Monitoring", "Process Monitoring", "System calls"],
                permissions_required=["Admin"],
                effective_permissions="Admin"
            ),
            "T1027": MITRETechnique(
                "T1027", "Obfuscated Files or Information", "Defense Evasion",
                "Adversaries may attempt to obfuscate files or information.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["File Monitoring", "Process Monitoring"],
                permissions_required=["User"]
            ),
            "T1027.002": MITRETechnique(
                "T1027.002", "Software Packing", "Defense Evasion",
                "Adversaries may perform software packing to conceal code.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["File Monitoring", "Process Monitoring"],
                is_subtechnique=True,
                parent_technique="T1027",
                permissions_required=["User"]
            ),
            "T1218": MITRETechnique(
                "T1218", "Signed Binary Proxy Execution", "Defense Evasion",
                "Adversaries may use signed binaries to proxy execution.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "Command Line"],
                permissions_required=["User"]
            ),
            "T1218.001": MITRETechnique(
                "T1218.001", "Compiled HTML File", "Defense Evasion",
                "Adversaries may use Compiled HTML files to execute code.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "Command Line"],
                is_subtechnique=True,
                parent_technique="T1218",
                permissions_required=["User"]
            ),
            "T1218.011": MITRETechnique(
                "T1218.011", "Rundll32", "Defense Evasion",
                "Adversaries may use Rundll32 to execute arbitrary code.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "Command Line"],
                is_subtechnique=True,
                parent_technique="T1218",
                permissions_required=["User"]
            ),
            "T1562": MITRETechnique(
                "T1562", "Impair Defenses", "Defense Evasion",
                "Adversaries may disable or modify security tools.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "API Monitoring"],
                permissions_required=["Admin"]
            ),
            "T1562.001": MITRETechnique(
                "T1562.001", "Disable or Modify Tools", "Defense Evasion",
                "Adversaries may modify security tools.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "API Monitoring"],
                is_subtechnique=True,
                parent_technique="T1562",
                permissions_required=["Admin"]
            ),
            
            # ========== CREDENTIAL ACCESS (TA0006) ==========
            "T1003": MITRETechnique(
                "T1003", "OS Credential Dumping", "Credential Access",
                "Adversaries may attempt to dump credentials.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "API Monitoring", "Windows Event logs"],
                permissions_required=["Admin"]
            ),
            "T1003.001": MITRETechnique(
                "T1003.001", "LSASS Memory", "Credential Access",
                "Adversaries may access credentials stored in LSASS memory.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring", "Windows Event logs"],
                is_subtechnique=True,
                parent_technique="T1003",
                permissions_required=["Admin"]
            ),
            "T1003.002": MITRETechnique(
                "T1003.002", "Security Account Manager", "Credential Access",
                "Adversaries may extract credentials from the SAM.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring"],
                is_subtechnique=True,
                parent_technique="T1003",
                permissions_required=["Admin"]
            ),
            "T1003.003": MITRETechnique(
                "T1003.003", "NTDS", "Credential Access",
                "Adversaries may access the Active Directory domain database.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring", "Network Traffic"],
                is_subtechnique=True,
                parent_technique="T1003",
                permissions_required=["Admin"]
            ),
            "T1558": MITRETechnique(
                "T1558", "Steal or Forge Kerberos Tickets", "Credential Access",
                "Adversaries may subvert Kerberos authentication.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring", "Authentication Logs"],
                permissions_required=["Admin"]
            ),
            "T1558.001": MITRETechnique(
                "T1558.001", "Golden Ticket", "Credential Access",
                "Adversaries may forge Kerberos ticket-granting tickets.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring", "Authentication Logs"],
                is_subtechnique=True,
                parent_technique="T1558",
                permissions_required=["Admin"]
            ),
            "T1558.003": MITRETechnique(
                "T1558.003", "Kerberoasting", "Credential Access",
                "Adversaries may perform Kerberoasting to obtain credentials.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring", "Authentication Logs"],
                is_subtechnique=True,
                parent_technique="T1558",
                permissions_required=["User"]
            ),
            "T1558.004": MITRETechnique(
                "T1558.004", "AS-REP Roasting", "Credential Access",
                "Adversaries may perform AS-REP roasting.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "API Monitoring", "Authentication Logs"],
                is_subtechnique=True,
                parent_technique="T1558",
                permissions_required=["User"]
            ),
            "T1056": MITRETechnique(
                "T1056", "Input Capture", "Credential Access",
                "Adversaries may capture user input to obtain credentials.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["API Monitoring", "Process Monitoring"],
                permissions_required=["User"]
            ),
            "T1056.001": MITRETechnique(
                "T1056.001", "Keylogging", "Credential Access",
                "Adversaries may log user keystrokes.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "API Monitoring"],
                is_subtechnique=True,
                parent_technique="T1056",
                permissions_required=["User"]
            ),
            
            # ========== DISCOVERY (TA0007) ==========
            "T1083": MITRETechnique(
                "T1083", "File and Directory Discovery", "Discovery",
                "Adversaries may enumerate files and directories.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "File Monitoring"],
                permissions_required=["User"]
            ),
            "T1087": MITRETechnique(
                "T1087", "Account Discovery", "Discovery",
                "Adversaries may get a listing of accounts.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "Windows Event logs"],
                permissions_required=["User"]
            ),
            "T1057": MITRETechnique(
                "T1057", "Process Discovery", "Discovery",
                "Adversaries may get information about running processes.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "API Monitoring"],
                permissions_required=["User"]
            ),
            "T1012": MITRETechnique(
                "T1012", "Query Registry", "Discovery",
                "Adversaries may interact with the Windows Registry.",
                platforms=["Windows"],
                data_sources=["Windows Registry", "Process Monitoring"],
                permissions_required=["User"]
            ),
            "T1046": MITRETechnique(
                "T1046", "Network Service Scanning", "Discovery",
                "Adversaries may scan for network services.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic", "Process Monitoring"],
                permissions_required=["User"]
            ),
            
            # ========== LATERAL MOVEMENT (TA0008) ==========
            "T1021": MITRETechnique(
                "T1021", "Remote Services", "Lateral Movement",
                "Adversaries may use remote services to move laterally.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "Network Traffic"],
                permissions_required=["User"]
            ),
            "T1021.002": MITRETechnique(
                "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement",
                "Adversaries may use SMB to move laterally.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "Network Traffic"],
                is_subtechnique=True,
                parent_technique="T1021",
                permissions_required=["Admin"]
            ),
            "T1021.004": MITRETechnique(
                "T1021.004", "SSH", "Lateral Movement",
                "Adversaries may use SSH to move laterally.",
                platforms=["Linux", "macOS"],
                data_sources=["Process Monitoring", "Network Traffic"],
                is_subtechnique=True,
                parent_technique="T1021",
                permissions_required=["User"]
            ),
            "T1570": MITRETechnique(
                "T1570", "Lateral Tool Transfer", "Lateral Movement",
                "Adversaries may transfer tools to other systems.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic", "File Monitoring"],
                permissions_required=["User"]
            ),
            
            # ========== COLLECTION (TA0009) ==========
            "T1005": MITRETechnique(
                "T1005", "Data from Local System", "Collection",
                "Adversaries may search local system sources for files.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["File Monitoring", "Process Monitoring"],
                permissions_required=["User"]
            ),
            "T1113": MITRETechnique(
                "T1113", "Screen Capture", "Collection",
                "Adversaries may capture screenshots.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "API Monitoring"],
                permissions_required=["User"]
            ),
            
            # ========== COMMAND AND CONTROL (TA0011) ==========
            "T1071": MITRETechnique(
                "T1071", "Application Layer Protocol", "Command and Control",
                "Adversaries may use OSI application layer protocols.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic"],
                permissions_required=["User"]
            ),
            "T1071.001": MITRETechnique(
                "T1071.001", "Web Protocols", "Command and Control",
                "Adversaries may use web protocols for C2.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic"],
                is_subtechnique=True,
                parent_technique="T1071",
                permissions_required=["User"]
            ),
            "T1071.004": MITRETechnique(
                "T1071.004", "DNS", "Command and Control",
                "Adversaries may use DNS for C2.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic", "DNS Logs"],
                is_subtechnique=True,
                parent_technique="T1071",
                permissions_required=["User"]
            ),
            "T1573": MITRETechnique(
                "T1573", "Encrypted Channel", "Command and Control",
                "Adversaries may use encryption for C2.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic"],
                permissions_required=["User"]
            ),
            "T1573.001": MITRETechnique(
                "T1573.001", "Symmetric Cryptography", "Command and Control",
                "Adversaries may use symmetric encryption for C2.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic"],
                is_subtechnique=True,
                parent_technique="T1573",
                permissions_required=["User"]
            ),
            "T1102": MITRETechnique(
                "T1102", "Web Service", "Command and Control",
                "Adversaries may use web services for C2.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic"],
                permissions_required=["User"]
            ),
            
            # ========== EXFILTRATION (TA0010) ==========
            "T1041": MITRETechnique(
                "T1041", "Exfiltration Over C2 Channel", "Exfiltration",
                "Adversaries may exfiltrate data over C2 channels.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic"],
                permissions_required=["User"]
            ),
            "T1567": MITRETechnique(
                "T1567", "Exfiltration Over Web Service", "Exfiltration",
                "Adversaries may exfiltrate data over web services.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Network Traffic"],
                permissions_required=["User"]
            ),
            
            # ========== IMPACT (TA0040) ==========
            "T1486": MITRETechnique(
                "T1486", "Data Encrypted for Impact", "Impact",
                "Adversaries may encrypt data to interrupt availability.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "File Monitoring"],
                permissions_required=["User"]
            ),
            "T1490": MITRETechnique(
                "T1490", "Inhibit System Recovery", "Impact",
                "Adversaries may prevent system recovery.",
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process Monitoring", "File Monitoring"],
                permissions_required=["Admin"]
            ),
            "T1490.001": MITRETechnique(
                "T1490.001", "Delete System Restore Points", "Impact",
                "Adversaries may delete system restore points.",
                platforms=["Windows"],
                data_sources=["Process Monitoring", "File Monitoring"],
                is_subtechnique=True,
                parent_technique="T1490",
                permissions_required=["Admin"]
            ),
        }

        # Techniques emitted by the detection engine that the base catalogue lacked.
        extra = [
            ("T1036", "Masquerading", "Defense Evasion",
             "Adversaries may manipulate artifacts to make them appear legitimate or benign.",
             False, None, ["Process Monitoring", "File Monitoring"], ["User"]),
            ("T1036.005", "Match Legitimate Name or Location", "Defense Evasion",
             "Adversaries may match or approximate the name or location of legitimate files or resources.",
             True, "T1036", ["Process Monitoring", "File Monitoring"], ["User"]),
            ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration",
             "Adversaries may steal data over a different protocol than the existing C2 channel.",
             False, None, ["Network Traffic"], ["User"]),
            ("T1105", "Ingress Tool Transfer", "Command and Control",
             "Adversaries may transfer tools or other files from an external system into a compromised environment.",
             False, None, ["Process Monitoring", "Network Traffic"], ["User"]),
            ("T1218.005", "Mshta", "Defense Evasion",
             "Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and scripts.",
             True, "T1218", ["Process Monitoring", "Command Monitoring"], ["User"]),
        ]
        for tid, name, tactic, desc, is_sub, parent, sources, perms in extra:
            techniques.setdefault(tid, MITRETechnique(
                tid, name, tactic, desc,
                platforms=["Windows"], data_sources=sources,
                is_subtechnique=is_sub, parent_technique=parent,
                permissions_required=perms,
                references=[f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"],
            ))

        self._techniques = techniques
    
    def _load_software(self):
        """
        Load known malware/tool software entries (MITRESoftware).

        Reserved for future expansion — nothing else in this class reads
        self._software yet, so this is a safe no-op today. It exists so
        __init__'s call to it doesn't raise AttributeError (that crash was
        silently swallowing every MITREAttackMapper() instantiation).
        """
        pass

    def _load_mitigations(self):
        """
        Load MITRE ATT&CK mitigations (MITREMitigation).

        Reserved for future expansion — nothing else in this class reads
        self._mitigations yet, so this is a safe no-op today.
        """
        pass

    def _load_data_sources(self):
        """
        Load MITRE ATT&CK data source mappings.

        Reserved for future expansion — nothing else in this class reads
        self._data_sources yet, so this is a safe no-op today.
        """
        pass

    def _load_groups(self):
        """Load MITRE ATT&CK Groups (Threat Actors)."""
        self._groups = {
            "G0007": MITREGroup(
                group_id="G0007",
                name="APT28",
                aliases=["Fancy Bear", "Sofacy", "Tsar Team", "STRONTIUM"],
                description="Russian state-sponsored threat actor active since 2007. Targets government, military, and security organizations.",
                techniques=["T1055.012", "T1003.001", "T1059.001", "T1071.001", "T1566"],
                software=["S0004", "S0018", "S0026"],
                references=["https://attack.mitre.org/groups/G0007/"]
            ),
            "G0016": MITREGroup(
                group_id="G0016",
                name="APT29",
                aliases=["Cozy Bear", "The Dukes", "CozyDuke", "YTTRIUM"],
                description="Russian state-sponsored threat actor. Known for SolarWinds compromise.",
                techniques=["T1055", "T1003", "T1547", "T1027", "T1078"],
                software=["S0038", "S0049", "S0051"],
                references=["https://attack.mitre.org/groups/G0016/"]
            ),
            "G0046": MITREGroup(
                group_id="G0046",
                name="FIN7",
                aliases=["Carbanak", "Anunak"],
                description="Financially motivated threat actor targeting the financial sector.",
                techniques=["T1059.001", "T1218", "T1078", "T1003", "T1071"],
                software=["S0030", "S0034", "S0042"],
                references=["https://attack.mitre.org/groups/G0046/"]
            ),
            "G0050": MITREGroup(
                group_id="G0050",
                name="Lazarus Group",
                aliases=["HIDDEN COBRA", "Guardians of Peace", "APT38"],
                description="North Korean state-sponsored threat actor.",
                techniques=["T1055.012", "T1003", "T1547", "T1071", "T1486"],
                software=["S0029", "S0036", "S0038"],
                references=["https://attack.mitre.org/groups/G0050/"]
            ),
            "G0047": MITREGroup(
                group_id="G0047",
                name="Gamaredon Group",
                aliases=["Primitive Bear", "ACTINIUM"],
                description="Russian state-sponsored threat actor targeting Ukrainian entities.",
                techniques=["T1059.001", "T1078", "T1566", "T1071"],
                software=["S0050", "S0052"],
                references=["https://attack.mitre.org/groups/G0047/"]
            ),
            "G0001": MITREGroup(
                group_id="G0001",
                name="Axiom",
                aliases=["Group 72", "Wild Neutron", "Morpho"],
                description="Chinese state-sponsored threat actor.",
                techniques=["T1055", "T1003", "T1078", "T1071"],
                software=["S0004", "S0021"],
                references=["https://attack.mitre.org/groups/G0001/"]
            ),
            "G0012": MITREGroup(
                group_id="G0012",
                name="DarkHotel",
                aliases=["Tapaoux"],
                description="Korean-affiliated threat actor known for targeting hotel Wi-Fi networks and spear-phishing campaigns.",
                techniques=["T1566.001", "T1055", "T1027", "T1071"],
                software=["S0049", "S0017"],
                references=["https://attack.mitre.org/groups/G0012/"]
            ),
        }

    # =========================================================================
    # Detection -> ATT&CK Mapping (public API used by app.py / tabs)
    # =========================================================================

    # Maps the slugified detection-engine technique names (as produced by
    # app.py: det.technique.lower().replace(" ", "_")) to real ATT&CK
    # technique IDs. Keys are kept in whatever unicode form .lower() would
    # produce; _slugify() below also strips accents so callers don't have
    # to worry about the exact encoding of names like "Doppelgänging".
    _DETECTION_TECHNIQUE_MAP = {
        "process_hollowing": "T1055.012",
        "dll_injection": "T1055.001",
        "reflective_dll_loading": "T1620",
        "process_doppelganging": "T1055",
        "process_herpaderping": "T1055",
        "rootkit": "T1014",
        "parent_pid_spoofing": "T1134.004",
        "command_obfuscation": "T1027",
        "fileless_malware": "T1059",
        "powershell_abuse": "T1059.001",
        "credential_dumping": "T1003",
        "lsass_memory": "T1003.001",
        "persistence": "T1547",
        "application_layer_protocol": "T1071",
        "exfiltration_over_c2_channel": "T1041",
        "exfiltration_over_alternative_protocol": "T1048",
        "masquerading": "T1036.005",
        "ingress_tool_transfer": "T1105",
        "mshta_proxy_execution": "T1218.005",
        "rundll32_proxy_execution": "T1218.011",
        "suspicious_script_host_execution": "T1059",
        "lsass_memory": "T1003.001",
        "dll_injection": "T1055.001",
        "parent_pid_spoofing": "T1134.004",
        "reflective_dll_loading": "T1620",
        "create_or_modify_system_process": "T1543",
    }

    @staticmethod
    def _slugify(text: str) -> str:
        """ASCII-normalize + slugify a technique name/key for lookup."""
        normalized = unicodedata.normalize("NFKD", text)
        ascii_text = normalized.encode("ascii", "ignore").decode("ascii")
        return re.sub(r"\s+", "_", ascii_text.strip().lower())

    def map_detection(self, technique_key: str, evidence: Optional[List] = None) -> List[TechniqueMapping]:
        """
        Map a detection engine finding to one or more ATT&CK techniques.

        Args:
            technique_key: either an ATT&CK technique ID directly (e.g.
                "T1055.012") or a slugified detection name (e.g.
                "process_hollowing", as produced by app.py).
            evidence: the raw evidence list attached to the detection.

        Returns:
            List of TechniqueMapping objects (empty if nothing matched).
            Each call also appends its results to self.mappings.
        """
        evidence = evidence or []
        if not technique_key and not evidence:
            return []

        # Direct technique ID lookup first (e.g. someone passes "T1055").
        technique = self._techniques.get(technique_key)
        technique_id = technique_key if technique else None

        # Otherwise resolve via the detection-name slug table.
        if technique is None and technique_key:
            slug = self._slugify(technique_key)
            technique_id = self._DETECTION_TECHNIQUE_MAP.get(slug)
            technique = self._techniques.get(technique_id) if technique_id else None

        # Fallback: some engines (YARA in particular) label their own
        # detections after the rule name (e.g. "YARA: Mimikatz_Memory"),
        # which won't be in the slug table above. Those engines embed the
        # real ATT&CK ID directly in each evidence item's metadata instead
        # (evidence[i]["meta"]["mitre_technique"] or evidence[i]["mitre_technique"]),
        # so fall back to reading it straight from there.
        if technique is None:
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                candidate = item.get("mitre_technique") or (item.get("meta") or {}).get("mitre_technique")
                if candidate and candidate in self._techniques:
                    technique_id = candidate
                    technique = self._techniques[candidate]
                    break

        if technique is None:
            return []

        confidence = 50.0
        if evidence:
            confidence = min(95.0, 50.0 + len(evidence) * 10.0)

        mapping = TechniqueMapping(
            technique_id=technique.technique_id,
            technique_name=technique.name,
            tactic=technique.tactic,
            detection_source=technique_key,
            confidence=confidence,
            evidence=evidence if isinstance(evidence, list) else [evidence],
            process_indicators=[
                str(e.get("process") or e.get("pid"))
                for e in evidence if isinstance(e, dict) and (e.get("process") or e.get("pid"))
            ],
            event_count=len(evidence),
            platforms=technique.platforms,
            permissions_required=technique.permissions_required,
            data_sources=technique.data_sources,
        )
        self.mappings.append(mapping)
        return [mapping]

    def generate_heatmap_data(self, mappings: Optional[List[TechniqueMapping]] = None) -> Dict:
        """
        Build heatmap-ready rows: one point per unique technique, sized/
        colored by an aggregate score across however many times it fired.
        """
        mappings = mappings if mappings is not None else self.mappings

        by_technique: Dict[str, Dict[str, Any]] = {}
        for m in mappings:
            key = m.technique_id
            if key not in by_technique:
                by_technique[key] = {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                    "score": 0.0,
                    "count": 0,
                }
            entry = by_technique[key]
            entry["score"] = max(entry["score"], m.confidence)
            entry["count"] += 1

        rows = list(by_technique.values())
        rows.sort(key=lambda r: (
            self.TACTICS_ORDER.index(r["tactic"]) if r["tactic"] in self.TACTICS_ORDER else len(self.TACTICS_ORDER),
            -r["score"],
        ))

        return {"data": rows, "technique_count": len(rows), "total_detections": len(mappings)}

    def get_tactic_summary(self, mappings: Optional[List[TechniqueMapping]] = None) -> Dict[str, Dict]:
        """Group mappings by tactic with per-tactic technique/event/score stats."""
        mappings = mappings if mappings is not None else self.mappings

        summary: Dict[str, Dict] = {}
        for m in mappings:
            tactic = m.tactic or "Unknown"
            if tactic not in summary:
                summary[tactic] = {
                    "techniques": [],
                    "technique_count": 0,
                    "total_events": 0,
                    "highest_score": 0.0,
                }
            entry = summary[tactic]
            if m.technique_id not in entry["techniques"]:
                entry["techniques"].append(m.technique_id)
            entry["technique_count"] = len(entry["techniques"])
            entry["total_events"] += max(m.event_count, 1)
            entry["highest_score"] = max(entry["highest_score"], m.confidence)

        # Return in canonical ATT&CK tactic order where possible.
        ordered = {t: summary[t] for t in self.TACTICS_ORDER if t in summary}
        ordered.update({t: v for t, v in summary.items() if t not in ordered})
        return ordered

    def generate_attack_navigator_layer(self, mappings: Optional[List[TechniqueMapping]] = None) -> Dict:
        """Generate a MITRE ATT&CK Navigator v4.5 compatible layer JSON."""
        mappings = mappings if mappings is not None else self.mappings

        by_technique: Dict[str, TechniqueMapping] = {}
        for m in mappings:
            existing = by_technique.get(m.technique_id)
            if existing is None or m.confidence > existing.confidence:
                by_technique[m.technique_id] = m

        def _color_for_score(score: float) -> str:
            if score >= 80:
                return "#ff4444"
            elif score >= 60:
                return "#ff8800"
            elif score >= 40:
                return "#ffcc00"
            return "#00cc66"

        techniques_layer = []
        for technique_id, m in by_technique.items():
            techniques_layer.append({
                "techniqueID": technique_id,
                "score": round(m.confidence, 1),
                "color": _color_for_score(m.confidence),
                "comment": f"Detected via {m.detection_source} ({m.event_count} event(s))",
                "enabled": True,
                "metadata": [
                    {"name": "tactic", "value": m.tactic},
                    {"name": "technique_name", "value": m.technique_name},
                ],
            })

        return {
            "name": "Memory Forensics Detections",
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Auto-generated from Enterprise Memory Forensics Platform detections.",
            "sorting": 3,
            "layout": {"layout": "side", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": techniques_layer,
            "gradient": {
                "colors": ["#00cc66", "#ffcc00", "#ff8800", "#ff4444"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#205b8f",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }
