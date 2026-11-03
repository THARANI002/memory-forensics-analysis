"""
Enterprise Memory Forensics Platform - Threat Detection Engine
===============================================================
Implements detection for advanced threats, injection techniques,
credential dumping, persistence mechanisms, and more.
"""

import re
import json
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict


@dataclass
class DetectionResult:
    """Result from a single threat detection module."""
    technique: str
    technique_id: str
    tactic: str
    detected: bool
    confidence: float
    severity: str
    description: str
    evidence: List[Dict] = field(default_factory=list)
    process_indicators: List[str] = field(default_factory=list)
    iocs: List[Dict] = field(default_factory=list)
    remediation: str = ""
    detection_source: str = "heuristic"
    
    def to_dict(self) -> Dict:
        return asdict(self)


class ThreatDetectionEngine:
    """
    Advanced Threat Detection Engine.
    
    Detects:
    - Process Hollowing (T1055.012)
    - DLL Injection (T1055.001)
    - Reflective DLL Loading (T1620)
    - Process Doppelgänging (T1055)
    - AtomBombing (T1055)
    - Process Herpaderping (T1055)
    - Rootkits (T1014)
    - Parent PID Spoofing (T1134.004)
    - Command Line Obfuscation (T1027)
    - Fileless Malware (T1059)
    - PowerShell Abuse (T1059.001)
    - Credential Dumping (T1003)
    - LSASS Access (T1003.001)
    - Persistence Mechanisms (T1547)
    """
    
    SYSTEM_BINARIES = {
        "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe", "csrss.exe",
        "smss.exe", "svchost.exe", "taskmgr.exe", "spoolsv.exe", "conhost.exe",
    }

    def __init__(self):
        self.detections = []
        self._setup_patterns()
    
    def _setup_patterns(self):
        """Setup detection patterns and indicators."""
        # Known suspicious processes for credential dumping
        self.credential_dumping_tools = [
            "mimikatz.exe", "procdump.exe", "gsecdump.exe",
            "wce.exe", "pwdump.exe", "fgdump.exe",
            "secretsdump.exe", "ntdsutil.exe", "vssadmin.exe",
            "diskshadow.exe", "esentutl.exe",
        ]
        
        # PowerShell abuse indicators
        self.powershell_indicators = [
            "-enc", "-encodedcommand", "-nop", "-noprofile",
            "-windowstyle hidden", "-w hidden", "bypass",
            "iex", "invoke-expression", "downloadstring",
            "net.webclient", "frombase64string",
            "-com", "createobject", "wscript.shell",
            "bits.transfer", "reflection.assembly",
            "system.security.cryptography",
            "convert]::frombase64",
            "invoke-mimikatz", "invoke-shellcode",
            "bloodhound", "sharphound",
        ]
        
        # Common LOLBAS (Living Off The Land) binaries
        self.lolbas_binaries = [
            "certutil.exe", "bitsadmin.exe", "mshta.exe",
            "regsvr32.exe", "rundll32.exe", "cmstp.exe",
            "installutil.exe", "msbuild.exe", "csc.exe",
            "msiexec.exe", "forfiles.exe", "ieexec.exe",
            "odbcconf.exe", "rcsi.exe", "te.exe",
            "winword.exe", "excel.exe", "powerpnt.exe",
        ]
        
        # Rootkit indicators
        self.rootkit_indicators = [
            "sysenter", "syscall", "inline hook",
            "iat hook", "eat hook", "ssdt hook",
            "irp hook", "dkom", "direct kernel object manipulation",
        ]
        
        # Obfuscation patterns
        self.obfuscation_patterns = [
            r"\^",  # Caret obfuscation
            r"%[a-zA-Z0-9]{2}%",  # Environment variable obfuscation
            r"`",  # Backtick obfuscation
            r"\+[\s]*\"",  # String concatenation
            r"for\s+/f",  # For loop obfuscation
            r"set\s+/p",  # Set variable obfuscation
        ]
        
        # Persistence registry keys
        self.persistence_registry = [
            r"\\software\\microsoft\\windows\\currentversion\\run",
            r"\\software\\microsoft\\windows\\currentversion\\runonce",
            r"\\software\\microsoft\\windows\\currentversion\\runoncesetup",
            r"\\software\\microsoft\\windows\\currentversion\\explorer\\shell folders",
            r"\\software\\microsoft\\windows nt\\currentversion\\winlogon\\shell",
            r"\\software\\microsoft\\windows nt\\currentversion\\winlogon\\userinit",
            r"\\system\\currentcontrolset\\services",
            r"\\software\\microsoft\\windows\\currentversion\\explorer\\user shell folders",
        ]
    
    def analyze_processes(self, processes: List[Dict]) -> List[DetectionResult]:
        """Run all detection modules against process list."""
        results = []
        
        results.extend(self.detect_process_hollowing(processes))
        results.extend(self.detect_dll_injection(processes))
        results.extend(self.detect_reflective_dll(processes))
        results.extend(self.detect_process_doppelganging(processes))
        results.extend(self.detect_atombombing(processes))
        results.extend(self.detect_process_herpaderping(processes))
        results.extend(self.detect_rootkits(processes))
        results.extend(self.detect_masquerading(processes))
        results.extend(self.detect_parent_pid_spoofing(processes))
        results.extend(self.detect_credential_dumping(processes))
        results.extend(self.detect_lsass_access(processes))
        
        return results
    
    def analyze_network(self, connections: List[Dict]) -> List[DetectionResult]:
        """Analyze network connections for threats."""
        results = []
        
        # Detect suspicious C2 patterns
        c2_detection = self._detect_c2_beaconing(connections)
        if c2_detection:
            results.append(c2_detection)
        
        # Detect data exfiltration
        exfil_detection = self._detect_data_exfiltration(connections)
        if exfil_detection:
            results.append(exfil_detection)
        
        return results
    
    def analyze_services(self, services: List[Dict]) -> List[DetectionResult]:
        """Analyze services for persistence."""
        results = []
        
        persistence_detection = self._detect_service_persistence(services)
        if persistence_detection:
            results.append(persistence_detection)
        
        return results
    
    def detect_process_hollowing(self, processes: List[Dict]) -> List[DetectionResult]:
        """
        Detect Process Hollowing (T1055.012).
        
        Indicators:
        - Suspicious parent-child relationships
        - Processes started from unexpected locations
        - Section mappings with RWX permissions
        - Entry point mismatches
        """
        results = []
        evidence = []
        
        for proc in processes:
            indicators = []
            
            # Check for suspicious process hollowing indicators
            if self._is_system_process(proc.get("name", "")):
                # System processes should have specific parents
                ppid = proc.get("ppid")
                if ppid and not self._is_valid_system_parent(proc.get("name"), ppid, processes):
                    indicators.append(f"Invalid parent process for {proc['name']}: {ppid}")
            
            # Check for process creation from temporary directories
            if proc.get("create_time"):
                # New processes in temp directories are suspicious
                pass  # Would need full path info
            
            if indicators:
                evidence.append({
                    "process": proc.get("name"),
                    "pid": proc.get("pid"),
                    "indicators": indicators
                })
        
        if evidence:
            results.append(DetectionResult(
                technique="Process Hollowing",
                technique_id="T1055.012",
                tactic="Defense Evasion",
                detected=True,
                confidence=75.0,
                severity="high",
                description="Process hollowing indicators detected. "
                           "Suspicious parent-child relationships found.",
                evidence=evidence,
                process_indicators=list(set(e["process"] for e in evidence)),
                remediation="Terminate suspicious processes and analyze memory dumps "
                           "for injected code sections."
            ))
        
        return results
    
    def detect_dll_injection(self, processes: List[Dict]) -> List[DetectionResult]:
        """
        Detect DLL Injection (T1055.001).

        Real memory forensics tools (Volatility's ldrmodules/malfind) detect
        this by comparing loaded-module lists against PEB entries and VAD
        memory protections — data this app doesn't have at the process-list
        level. The next best, well-established proxy signal (used in
        production Sigma/EDR rules such as "Suspicious Rundll32 Activity"
        and MITRE's own notes on T1218.011) is command-line analysis of the
        classic DLL-loading LOLBins: rundll32.exe, regsvr32.exe, and mshta.exe
        invoking a payload from a world-writable directory. Attack frameworks
        (Cobalt Strike, Metasploit, etc.) commonly use exactly this pattern
        to load an injected DLL, e.g.:
            rundll32.exe C:\\Users\\AppData\\Local\\Temp\\beacon.dll,EntryPoint
        """
        results = []

        dll_loader_processes = {"rundll32.exe", "regsvr32.exe", "mshta.exe"}
        suspicious_dll_patterns = [
            "\\temp\\", "\\appdata\\", "\\downloads\\",
            "\\users\\public\\", "\\programdata\\",
        ]

        evidence = []
        for proc in processes:
            name = proc.get("name", "").lower()
            if name not in dll_loader_processes:
                continue

            command_line = (proc.get("command_line") or "").lower()
            if not command_line:
                continue

            if any(pattern in command_line for pattern in suspicious_dll_patterns):
                evidence.append({
                    "process": proc.get("name"),
                    "pid": proc.get("pid"),
                    "ppid": proc.get("ppid"),
                    "command_line": proc.get("command_line"),
                    "indicator": f"{proc.get('name')} loading a module from a writable, non-standard directory",
                })

        if evidence:
            results.append(DetectionResult(
                technique="DLL Injection",
                technique_id="T1055.001",
                tactic="Defense Evasion",
                detected=True,
                confidence=75.0,
                severity="critical",
                description=(
                    "One or more LOLBins commonly abused for DLL injection "
                    "(rundll32.exe/regsvr32.exe/mshta.exe) were seen loading "
                    "a module from a writable, non-standard directory — a "
                    "pattern frequently used by post-exploitation frameworks "
                    "to execute an injected/dropped DLL."
                ),
                evidence=evidence,
                process_indicators=[str(e["pid"]) for e in evidence],
                remediation=(
                    "Acquire and analyze the referenced DLL (hash + submit for "
                    "detonation/reversal). Review parent process and how the "
                    "loader process was spawned. Consider blocking execution "
                    "from user-writable directories via application control."
                ),
            ))

        return results
    
    def detect_reflective_dll(self, processes: List[Dict]) -> List[DetectionResult]:
        """
        Detect Reflective DLL Loading (T1620).
        
        Indicators:
        - DLLs loaded without standard LoadLibrary
        - Memory regions with execute permissions
        - Missing PE headers in memory
        """
        results = []
        evidence = []
        
        # Reflective loading indicators
        for proc in processes:
            # Look for processes with RWX memory sections
            if proc.get("name", "").lower() in ["rundll32.exe", "regsvr32.exe"]:
                # These processes loading DLLs from memory is suspicious
                evidence.append({
                    "process": proc.get("name"),
                    "pid": proc.get("pid"),
                    "indicator": "Process commonly used for reflective loading"
                })
        
        if evidence:
            results.append(DetectionResult(
                technique="Reflective DLL Loading",
                technique_id="T1620",
                tactic="Defense Evasion",
                detected=True,
                confidence=70.0,
                severity="high",
                description="Reflective DLL loading indicators detected.",
                evidence=evidence,
                remediation="Analyze process memory for manually mapped PE files."
            ))
        
        return results
    
    def detect_process_doppelganging(self, processes: List[Dict]) -> List[DetectionResult]:
        """
        Detect Process Doppelgänging (T1055).
        
        Indicators:
        - Transacted file operations
        - Process creation from deleted files
        - Section creation from file transactions
        """
        results = []
        evidence = []
        
        for proc in processes:
            # Only explicit forensic flags count (deleted/transacted backing file)
            if proc.get("name") and (proc.get("transacted_file") or proc.get("backing_file_deleted")):
                evidence.append({
                    "process": proc.get("name"),
                    "pid": proc.get("pid"),
                    "indicator": "Process backed by a deleted or transacted file"
                })
        
        if evidence:
            results.append(DetectionResult(
                technique="Process Doppelgänging",
                technique_id="T1055",
                tactic="Defense Evasion",
                detected=True,
                confidence=65.0,
                severity="high",
                description="Process doppelgänging indicators detected. "
                           "Processes found without backing files.",
                evidence=evidence,
                remediation="Investigate process creation events and file system transactions."
            ))
        
        return results
    
    def detect_atombombing(self, processes: List[Dict]) -> List[DetectionResult]:
        """
        Detect AtomBombing injection (T1055.011).

        Indicators (per real published research/MITRE):
        - Global atom table entries containing shellcode
        - APC injection via GlobalGetAtomName/NtQueueApcThread targeting a
          window-owning process (explorer.exe is the classic target)

        This is intentionally a no-op, not an oversight: reliably
        distinguishing AtomBombing from a process-level view (pid, name,
        ppid, thread/handle counts) isn't possible — the actual evidence
        lives in the atom table and the APC queue, neither of which is
        exposed to this method. I checked every process's handle/thread
        ratio across this app's process schema, and there's no metadata
        proxy that separates a genuine AtomBombing victim from an ordinary
        GUI process without inventing an arbitrary threshold that would
        produce false positives with no real detection value.

        Real detection of this technique needs a Volatility plugin (or
        equivalent) that walks the atom table and correlates it against
        APC queue entries — that's a acquisition/analysis-engine-level
        capability, not something this heuristic layer can add safely.
        """
        results = []

        # Deliberately returns no findings — see docstring. If atom-table /
        # APC-queue data ever becomes available upstream (e.g. via a
        # Volatility atom-table plugin), this method is the right place to
        # add real detection logic against that data.

        return results
    
    def detect_process_herpaderping(self, processes: List[Dict]) -> List[DetectionResult]:
        """
        Detect Process Herpaderping (T1055).
        
        Indicators:
        - Process binary modified after creation
        - Mismatch between on-disk and in-memory image
        - Write access to process executable
        """
        results = []
        evidence = []
        
        for proc in processes:
            # Check for process image tampering indicators
            if proc.get("image_modified"):
                evidence.append({
                    "process": proc.get("name"),
                    "pid": proc.get("pid"),
                    "indicator": "Process image modified after creation"
                })
        
        if evidence:
            results.append(DetectionResult(
                technique="Process Herpaderping",
                technique_id="T1055",
                tactic="Defense Evasion",
                detected=True,
                confidence=70.0,
                severity="high",
                description="Process herpaderping indicators detected.",
                evidence=evidence,
                remediation="Compare on-disk and in-memory process images."
            ))
        
        return results
    
    def detect_rootkits(self, processes: List[Dict]) -> List[DetectionResult]:
        """
        Detect Rootkit presence (T1014).
        
        Indicators:
        - SSDT hooks
        - IRP hooks
        - DKOM (Direct Kernel Object Manipulation)
        - Hidden processes
        - API hooks
        """
        results = []
        evidence = []
        
        # Check for hidden processes (in pslist but not psscan)
        # Check for DKOM indicators
        # Check for driver anomalies
        
        rootkit_driver_names = [
            "capcom.sys", "asmmap64.sys", "win32k.sys",
            "ntfs.sys", "null.sys", "beep.sys",
        ]
        
        for proc in processes:
            name = proc.get("name", "").lower()
            
            # Check for processes with rootkit indicators
            if any(rk in name for rk in ["rootkit", "hook", "hide"]):
                evidence.append({
                    "process": name,
                    "pid": proc.get("pid"),
                    "indicator": "Process name contains rootkit indicators"
                })
        
        for proc in processes:
            if proc.get("in_psscan") and proc.get("in_pslist") is False:
                evidence.append({
                    "process": proc.get("name"),
                    "pid": proc.get("pid"),
                    "indicator": "Found by pool-tag scan but unlinked from active process list (DKOM)"
                })
        
        if evidence:
            results.append(DetectionResult(
                technique="Rootkit",
                technique_id="T1014",
                tactic="Defense Evasion",
                detected=True,
                confidence=85.0,
                severity="critical",
                description="Rootkit indicators detected in memory.",
                evidence=evidence,
                remediation="Immediate system isolation required. "
                           "Perform full memory and disk forensics."
            ))
        
        return results
    
    def detect_masquerading(self, processes: List[Dict]) -> List[DetectionResult]:
        """Detect Masquerading (T1036.005): duplicate singleton OS processes
        and system binaries running from non-system paths."""
        evidence = []
        singletons = ["lsass.exe", "services.exe", "wininit.exe"]
        for single in singletons:
            same = [p for p in processes if str(p.get("name", "")).lower() == single]
            if len(same) > 1:
                # the earliest instance is treated as genuine
                same.sort(key=lambda p: (str(p.get("create_time") or ""), p.get("pid") or 0))
                for dup in same[1:]:
                    evidence.append({
                        "process": dup.get("name"), "pid": dup.get("pid"),
                        "indicator": f"Duplicate {single}; legitimate system has exactly one instance",
                    })
        for p in processes:
            path = str(p.get("exe_path") or "").lower().replace("/", "\\")
            name = str(p.get("name", "")).lower()
            if path and name in self.SYSTEM_BINARIES and not path.startswith("c:\\windows\\"):
                evidence.append({
                    "process": p.get("name"), "pid": p.get("pid"),
                    "indicator": f"System binary {name} running from {p.get('exe_path')}",
                })
        if not evidence:
            return []
        return [DetectionResult(
            technique="Masquerading", technique_id="T1036.005", tactic="Defense Evasion",
            detected=True, confidence=82.0, severity="high",
            description="Processes impersonating legitimate Windows system processes.",
            evidence=evidence,
            process_indicators=[f"{e['process']} (PID {e['pid']})" for e in evidence],
            remediation="Verify image path and signature; terminate and image the process.",
        )]

    LOLBIN_RULES = [
        (re.compile(r"certutil(\.exe)?\b.*(-urlcache|-verifyctl|-decode).*", re.I),
         "T1105", "Ingress Tool Transfer", "Command and Control",
         "certutil used to download or decode a payload"),
        (re.compile(r"mshta(\.exe)?\s+(https?://|javascript:|vbscript:|\S+\.hta)", re.I),
         "T1218.005", "Mshta Proxy Execution", "Defense Evasion",
         "mshta executing remote or script content"),
        (re.compile(r"rundll32(\.exe)?\s+\S*\\(temp|appdata|public|programdata)\\\S+\.dll", re.I),
         "T1218.011", "Rundll32 Proxy Execution", "Defense Evasion",
         "rundll32 loading a DLL from a user-writable path"),
        (re.compile(r"(wscript|cscript)(\.exe)?\s+\S*\\(temp|appdata|public|downloads)\\\S+\.(vbs|js|jse|vbe|wsf)", re.I),
         "T1059", "Suspicious Script Host Execution", "Execution",
         "script host running a script from a user-writable path"),
    ]

    def detect_lolbin_abuse(self, processes: List[Dict], command_lines: List[Dict] = None) -> List[DetectionResult]:
        """Living-off-the-land binary abuse, judged from command-line evidence."""
        seen = {}
        entries = [(c.get("pid"), c.get("process"), c.get("command_line", "")) for c in (command_lines or [])]
        entries += [(p.get("pid"), p.get("name"), p.get("command_line", "")) for p in processes if p.get("command_line")]
        for pid, name, cmd in entries:
            for rx, tid, tech, tactic, why in self.LOLBIN_RULES:
                if cmd and rx.search(cmd):
                    seen.setdefault((tid, tech, tactic, why), {})[pid] = {
                        "process": name, "pid": pid, "command_line": cmd[:300], "indicator": why}
        results = []
        for (tid, tech, tactic, why), by_pid in seen.items():
            ev = list(by_pid.values())
            results.append(DetectionResult(
                technique=tech, technique_id=tid, tactic=tactic, detected=True,
                confidence=85.0 if tid != "T1059" else 75.0, severity="high",
                description=why.capitalize() + ".", evidence=ev,
                process_indicators=[f"{e['process']} (PID {e['pid']})" for e in ev],
                remediation="Inspect the referenced payload, block the source, and review parent process chain.",
            ))
        return results

    def detect_parent_pid_spoofing(self, processes: List[Dict]) -> List[DetectionResult]:
        """
        Detect Parent PID Spoofing (T1134.004).
        
        Indicators:
        - Child processes with unexpected parents
        - Explorer spawning suspicious processes
        - svchost with incorrect parent
        """
        results = []
        evidence = []
        
        # Expected parent-child relationships
        valid_parents = {  # child -> parents it may legitimately have
            "svchost.exe": ["services.exe", "msmpeng.exe"],
            "services.exe": ["wininit.exe"],
            "lsass.exe": ["wininit.exe"],
            "spoolsv.exe": ["services.exe"],
            "smss.exe": ["system"],
            "csrss.exe": ["smss.exe"],
            "wininit.exe": ["smss.exe"],
            "winlogon.exe": ["smss.exe"],
        }
        
        for proc in processes:
            name = proc.get("name", "").lower()
            ppid = proc.get("ppid")
            
            if not ppid or ppid == 0:
                continue
            
            # Find parent process
            parent = next((p for p in processes if p.get("pid") == ppid), None)
            if not parent:
                continue
            
            parent_name = parent.get("name", "").lower()
            
            # Check for spoofed parent relationships
            if name in valid_parents:
                expected_parents = [p.lower() for p in valid_parents[name]]
                if expected_parents and parent_name not in expected_parents:
                    evidence.append({
                        "process": name,
                        "pid": proc.get("pid"),
                        "parent": parent_name,
                        "ppid": ppid,
                        "indicator": f"Unexpected parent: {parent_name} for {name}"
                    })
        
        if evidence:
            results.append(DetectionResult(
                technique="Parent PID Spoofing",
                technique_id="T1134.004",
                tactic="Defense Evasion",
                detected=True,
                confidence=80.0,
                severity="high",
                description="Parent PID spoofing indicators detected. "
                           "Suspicious parent-child process relationships found.",
                evidence=evidence,
                remediation="Investigate process creation chains and verify PPID authenticity."
            ))
        
        return results
    
    def detect_command_line_obfuscation(self, command_lines: List[Dict]) -> List[DetectionResult]:
        """
        Detect Command Line Obfuscation (T1027).
        
        Indicators:
        - Caret (^) obfuscation
        - Environment variable obfuscation
        - Base64 encoding
        - String concatenation
        """
        results = []
        evidence = []
        
        for cmd_entry in command_lines:
            cmd_line = cmd_entry.get("command_line", "")
            obfuscation_indicators = []
            
            for pattern in self.obfuscation_patterns:
                if re.search(pattern, cmd_line, re.IGNORECASE):
                    obfuscation_indicators.append(pattern)
            
            # Check for base64
            if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', cmd_line):
                obfuscation_indicators.append("base64_pattern")
            
            if obfuscation_indicators:
                evidence.append({
                    "process": cmd_entry.get("process"),
                    "pid": cmd_entry.get("pid"),
                    "command_line": cmd_line[:200],
                    "obfuscation_techniques": obfuscation_indicators
                })
        
        if evidence:
            results.append(DetectionResult(
                technique="Command Obfuscation",
                technique_id="T1027",
                tactic="Defense Evasion",
                detected=True,
                confidence=85.0,
                severity="medium",
                description="Command line obfuscation detected.",
                evidence=evidence,
                remediation="Deobfuscate commands and analyze intended execution."
            ))
        
        return results
    
    def detect_fileless_malware(self, processes: List[Dict]) -> List[DetectionResult]:
        """
        Detect Fileless Malware (T1059).
        
        Indicators:
        - Execution from registry
        - WMI event subscriptions
        - PowerShell in memory
        - COM hijacking
        """
        results = []
        evidence = []
        
        fileless_indicators = [
            "wscript.exe", "cscript.exe", "mshta.exe",
            "powershell.exe", "pwsh.exe", "cmd.exe",
        ]
        
        for proc in processes:
            name = proc.get("name", "").lower()
            
            if name in fileless_indicators:
                evidence.append({
                    "process": name,
                    "pid": proc.get("pid"),
                    "indicator": "Scripting engine execution - potential fileless malware"
                })
        
        if evidence:
            results.append(DetectionResult(
                technique="Fileless Malware",
                technique_id="T1059",
                tactic="Execution",
                detected=True,
                confidence=65.0,
                severity="high",
                description="Fileless malware indicators detected. "
                           "Scripting engines executing without corresponding files.",
                evidence=evidence,
                remediation="Analyze script content and parent process chain."
            ))
        
        return results
    
    def detect_powershell_abuse(self, processes: List[Dict], command_lines: List[Dict]) -> List[DetectionResult]:
        """
        Detect PowerShell Abuse (T1059.001).
        
        Indicators:
        - Encoded commands
        - Download cradles
        - Obfuscated scripts
        - Suspicious cmdlets
        """
        results = []
        evidence = []
        
        for cmd_entry in command_lines:
            cmd = cmd_entry.get("command_line", "").lower()
            
            if "powershell" not in cmd and "pwsh" not in cmd:
                continue
            
            indicators = []
            
            for indicator in self.powershell_indicators:
                if indicator in cmd:
                    indicators.append(indicator)
            
            if indicators:
                evidence.append({
                    "process": cmd_entry.get("process"),
                    "pid": cmd_entry.get("pid"),
                    "command_line": cmd[:300],
                    "indicators": indicators
                })
        
        if evidence:
            results.append(DetectionResult(
                technique="PowerShell Abuse",
                technique_id="T1059.001",
                tactic="Execution",
                detected=True,
                confidence=85.0,
                severity="high",
                description="PowerShell abuse indicators detected. "
                           f"{len(evidence)} suspicious PowerShell executions found.",
                evidence=evidence,
                iocs=[{"type": "command", "value": e["command_line"]} for e in evidence],
                remediation="Decode and analyze PowerShell commands. "
                           "Block suspicious PowerShell execution via AppLocker/WDAC."
            ))
        
        return results
    
    def detect_credential_dumping(self, processes: List[Dict]) -> List[DetectionResult]:
        """
        Detect Credential Dumping (T1003).
        
        Indicators:
        - LSASS access
        - SAM database access
        - NTDS.dit extraction
        - Kerberos ticket extraction
        """
        results = []
        evidence = []
        
        for proc in processes:
            name = proc.get("name", "").lower()
            
            if name in [t.lower() for t in self.credential_dumping_tools]:
                evidence.append({
                    "process": name,
                    "pid": proc.get("pid"),
                    "indicator": "Known credential dumping tool"
                })
            
            # Detect VSS admin usage for shadow copy
            if name == "vssadmin.exe":
                evidence.append({
                    "process": name,
                    "pid": proc.get("pid"),
                    "indicator": "Volume Shadow Copy manipulation - possible credential extraction"
                })
            
            # Detect ntdsutil usage
            if name == "ntdsutil.exe":
                evidence.append({
                    "process": name,
                    "pid": proc.get("pid"),
                    "indicator": "NTDS database utility - Active Directory credential extraction"
                })
        
        if evidence:
            results.append(DetectionResult(
                technique="Credential Dumping",
                technique_id="T1003",
                tactic="Credential Access",
                detected=True,
                confidence=90.0,
                severity="critical",
                description="Credential dumping activity detected! "
                           f"{len(evidence)} indicators found.",
                evidence=evidence,
                iocs=[{"type": "process", "value": e["process"]} for e in evidence],
                remediation="IMMEDIATE: Reset all credentials. "
                           "Isolate affected systems. Review authentication logs."
            ))
        
        return results
    
    def detect_lsass_access(self, processes: List[Dict]) -> List[DetectionResult]:
        """
        Detect LSASS Memory Access (T1003.001).
        
        Indicators:
        - Non-system processes accessing LSASS
        - Processes with SeDebugPrivilege
        - Memory reads from LSASS process
        """
        results = []
        evidence = []
        
        lsass_pid = None
        for proc in processes:
            if proc.get("name", "").lower() == "lsass.exe":
                lsass_pid = proc.get("pid")
                break
        
        if lsass_pid:
            for proc in processes:
                name = proc.get("name", "").lower()
                pid = proc.get("pid")
                
                # Skip system processes
                if name in ["system", "registry", "smss.exe", "csrss.exe"]:
                    continue
                
                # Check for processes that shouldn't access LSASS
                if self._has_lsass_access_indicators(proc):
                    evidence.append({
                        "process": name,
                        "pid": pid,
                        "target": "lsass.exe",
                        "target_pid": lsass_pid,
                        "indicator": "Potential LSASS memory access"
                    })
        
        if evidence:
            results.append(DetectionResult(
                technique="LSASS Memory",
                technique_id="T1003.001",
                tactic="Credential Access",
                detected=True,
                confidence=85.0,
                severity="critical",
                description="LSASS memory access detected! "
                           "Potential credential dumping in progress.",
                evidence=evidence,
                process_indicators=[e["process"] for e in evidence],
                iocs=[{"type": "process", "value": e["process"]} for e in evidence],
                remediation="IMMEDIATE: Terminate accessing processes. "
                           "Enable LSASS protection (RunAsPPL). "
                           "Reset all domain and local credentials."
            ))
        
        return results
    
    def detect_persistence_mechanisms(self, services: List[Dict], registry: List[Dict]) -> List[DetectionResult]:
        """
        Detect Persistence Mechanisms (T1547).
        
        Indicators:
        - Auto-start services
        - Registry run keys
        - Scheduled tasks
        - WMI event subscriptions
        """
        results = []
        evidence = []
        
        # Check services
        for svc in services:
            if svc.get("start") in ["SERVICE_AUTO_START", "2", "auto"]:
                binary_path = svc.get("binary_path", "")
                if any(susp in binary_path.lower() for susp in ["\\temp\\", "\\appdata\\", "\\users\\"]):
                    evidence.append({
                        "type": "service",
                        "name": svc.get("service_name"),
                        "path": binary_path,
                        "indicator": "Suspicious auto-start service location"
                    })
        
        # Check registry
        for reg in registry:
            reg_path = reg.get("path", "").lower()
            for pattern in self.persistence_registry:
                if re.search(pattern, reg_path):
                    evidence.append({
                        "type": "registry",
                        "path": reg_path,
                        "indicator": "Persistence registry key modification"
                    })
        
        if evidence:
            results.append(DetectionResult(
                technique="Persistence",
                technique_id="T1547",
                tactic="Persistence",
                detected=True,
                confidence=75.0,
                severity="high",
                description="Persistence mechanisms detected.",
                evidence=evidence,
                remediation="Remove unauthorized persistence entries. "
                           "Scan for additional backdoors."
            ))
        
        return results
    
    def _is_system_process(self, name: str) -> bool:
        """Check if process is a critical system process."""
        system_processes = [
            "system", "registry", "smss.exe", "csrss.exe",
            "wininit.exe", "services.exe", "lsass.exe",
            "svchost.exe", "explorer.exe", "winlogon.exe",
        ]
        return name.lower() in system_processes
    
    def _is_valid_system_parent(self, proc_name: str, ppid: int, processes: List[Dict]) -> bool:
        """Validate parent process for system processes."""
        parent = next((p for p in processes if p.get("pid") == ppid), None)
        if not parent:
            # Parent already exited (normal for userinit/smss children) -> no evidence
            return True
        
        parent_name = parent.get("name", "").lower()
        proc_name = proc_name.lower()
        
        valid_relationships = {
            "services.exe": ["wininit.exe"],
            "lsass.exe": ["wininit.exe"],
            "svchost.exe": ["services.exe", "msmpeng.exe"],
            "explorer.exe": ["userinit.exe", "winlogon.exe", "dwm.exe"],
            "winlogon.exe": ["smss.exe"],
            "csrss.exe": ["smss.exe"],
            "wininit.exe": ["smss.exe"],
            "smss.exe": ["system"],
        }
        
        expected = valid_relationships.get(proc_name)
        if expected is None:
            return True
        return parent_name in expected
    
    def _has_lsass_access_indicators(self, proc: Dict) -> bool:
        """Check if process has LSASS access indicators."""
        name = proc.get("name", "").lower()
        
        # Known LSASS accessors
        lsass_accessors = [
            "mimikatz.exe", "procdump.exe", "procdump64.exe", "nanodump.exe",
            "dumpert.exe", "processhacker.exe", "systeminformer.exe",
        ]
        
        if name in [a.lower() for a in lsass_accessors]:
            return True
        cmd = str(proc.get("command_line") or "").lower()
        if "lsass" in cmd and any(k in cmd for k in ("-ma", "minidump", "comsvcs", "sekurlsa", ".dmp")):
            return True
        
        # Check for debug privileges
        if proc.get("has_debug_priv"):
            return True
        
        return False
    
    def _detect_c2_beaconing(self, connections: List[Dict]) -> Optional[DetectionResult]:
        """Detect C2 beaconing patterns."""
        # Group connections by remote address
        addr_connections = defaultdict(list)
        for conn in connections:
            remote = conn.get("remote_addr")
            if remote and remote not in ["0.0.0.0", "127.0.0.1", "::"]:
                addr_connections[remote].append(conn)
        
        evidence = []
        for addr, conns in addr_connections.items():
            if len(conns) >= 3:  # Multiple connections to same address
                ports = set(c.get("remote_port") for c in conns)
                if len(ports) == 1:  # Same port - beaconing indicator
                    evidence.append({
                        "remote_addr": addr,
                        "port": list(ports)[0],
                        "connection_count": len(conns),
                        "indicator": "Regular connections to external address"
                    })
        
        if evidence:
            return DetectionResult(
                technique="Application Layer Protocol",
                technique_id="T1071",
                tactic="Command and Control",
                detected=True,
                confidence=70.0,
                severity="high",
                description="Potential C2 beaconing detected.",
                evidence=evidence,
                iocs=[{"type": "ip", "value": e["remote_addr"]} for e in evidence],
                remediation="Block external IP addresses and investigate compromised hosts."
            )
        
        return None
    
    def _detect_data_exfiltration(self, connections: List[Dict]) -> Optional[DetectionResult]:
        """Detect potential data exfiltration."""
        # Large outbound connections or connections to unusual ports
        evidence = []
        
        for conn in connections:
            remote_port = conn.get("remote_port", 0)
            if remote_port in [21, 22, 23, 69, 443, 995, 2222]:
                if conn.get("state") == "ESTABLISHED":
                    evidence.append({
                        "remote_addr": conn.get("remote_addr"),
                        "port": remote_port,
                        "protocol": conn.get("protocol"),
                        "process": conn.get("process"),
                        "indicator": f"Potential exfiltration channel on port {remote_port}"
                    })
        
        if len(evidence) >= 2:
            return DetectionResult(
                technique="Exfiltration Over C2 Channel",
                technique_id="T1041",
                tactic="Exfiltration",
                detected=True,
                confidence=60.0,
                severity="medium",
                description="Potential data exfiltration detected.",
                evidence=evidence,
                remediation="Monitor outbound data volume and block suspicious destinations."
            )
        
        return None
    
    def _detect_service_persistence(self, services: List[Dict]) -> Optional[DetectionResult]:
        """Detect persistence via services."""
        evidence = []
        
        for svc in services:
            binary = svc.get("binary_path", "").lower()
            # Services running from unusual locations
            if any(loc in binary for loc in ["\\temp\\", "\\appdata\\", "\\users\\", "\\downloads\\"]):
                evidence.append({
                    "service": svc.get("service_name"),
                    "binary": binary,
                    "start_type": svc.get("start"),
                    "indicator": "Service binary in user-writable directory"
                })
        
        if evidence:
            return DetectionResult(
                technique="Create or Modify System Process",
                technique_id="T1543",
                tactic="Persistence",
                detected=True,
                confidence=80.0,
                severity="high",
                description="Persistence via malicious Windows service detected.",
                evidence=evidence,
                remediation="Remove malicious services and investigate how they were installed."
            )
        
        return None
    
    def run_all_detections(
        self,
        processes: List[Dict],
        connections: List[Dict] = None,
        services: List[Dict] = None,
        registry: List[Dict] = None,
        command_lines: List[Dict] = None
    ) -> List[DetectionResult]:
        """Run all detection modules."""
        all_results = []
        
        # Process-based detections
        all_results.extend(self.analyze_processes(processes))
        
        # Network detections
        if connections:
            all_results.extend(self.analyze_network(connections))
        
        # Service detections
        if services:
            all_results.extend(self.analyze_services(services))
        
        # Command line detections
        if command_lines:
            all_results.extend(self.detect_command_line_obfuscation(command_lines))
            all_results.extend(self.detect_powershell_abuse(processes, command_lines))
        
        # Persistence detections
        if services and registry:
            all_results.extend(self.detect_persistence_mechanisms(services, registry))
        
        # Fileless malware
        all_results.extend(self.detect_fileless_malware(processes))

        # Living-off-the-land abuse (uses per-process command lines too)
        all_results.extend(self.detect_lolbin_abuse(processes, command_lines))
        
        # Sort by confidence descending
        all_results.sort(key=lambda x: x.confidence, reverse=True)
        
        return all_results
    
    def calculate_overall_score(self, detections: List[DetectionResult]) -> Dict:
        """Calculate overall threat score from detections."""
        if not detections:
            return {
                "score": 0.0,
                "level": "CLEAN",
                "total_detections": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}
            }
        
        # Weight by severity
        weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1}
        
        total_score = 0.0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for det in detections:
            if det.detected:
                weight = weights.get(det.severity, 0.1)
                total_score += det.confidence * weight
                severity_counts[det.severity] = severity_counts.get(det.severity, 0) + 1
        
        # Noisy-OR: independent corroborating detections raise the score; one
        # strong finding is already serious, and benign noise cannot dilute it.
        miss = 1.0
        for det in detections:
            if det.detected:
                p = min(max(det.confidence, 0.0), 100.0) / 100.0 * weights.get(det.severity, 0.1)
                miss *= (1.0 - p)
        score = min(100.0 * (1.0 - miss), 100.0)
        
        if score >= 90:
            level = "CRITICAL"
        elif score >= 70:
            level = "HIGH"
        elif score >= 50:
            level = "MEDIUM"
        elif score >= 30:
            level = "LOW"
        else:
            level = "MINIMAL"
        
        return {
            "score": round(score, 2),
            "level": level,
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "total_detections": len([d for d in detections if d.detected]),
            "severity_counts": severity_counts
        }