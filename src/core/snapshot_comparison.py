"""
Enterprise Memory Forensics Platform - Snapshot Comparison Engine
==================================================================
Compares baseline vs suspicious memory snapshots to detect changes.
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict


@dataclass
class DifferenceFinding:
    """A single difference finding between snapshots."""
    change_type: str  # new, removed, modified, hidden
    category: str     # process, dll, service, driver, network, registry, injection, persistence
    item_name: str
    baseline_value: Optional[Dict] = None
    snapshot_value: Optional[Dict] = None
    details: Dict = field(default_factory=dict)
    severity: str = "medium"
    confidence: float = 0.0
    description: str = ""


@dataclass
class ComparisonResult:
    """Complete snapshot comparison result."""
    baseline_id: str
    snapshot_id: str
    comparison_time: str
    threat_delta_score: float = 0.0
    changes_detected: int = 0
    new_processes: List[DifferenceFinding] = field(default_factory=list)
    missing_processes: List[DifferenceFinding] = field(default_factory=list)
    hidden_processes: List[DifferenceFinding] = field(default_factory=list)
    dll_changes: List[DifferenceFinding] = field(default_factory=list)
    new_services: List[DifferenceFinding] = field(default_factory=list)
    new_drivers: List[DifferenceFinding] = field(default_factory=list)
    network_changes: List[DifferenceFinding] = field(default_factory=list)
    registry_changes: List[DifferenceFinding] = field(default_factory=list)
    persistence_changes: List[DifferenceFinding] = field(default_factory=list)
    injection_changes: List[DifferenceFinding] = field(default_factory=list)
    timeline_of_changes: List[Dict] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "baseline_id": self.baseline_id,
            "snapshot_id": self.snapshot_id,
            "comparison_time": self.comparison_time,
            "threat_delta_score": self.threat_delta_score,
            "changes_detected": self.changes_detected,
            "new_processes": [asdict(f) for f in self.new_processes],
            "missing_processes": [asdict(f) for f in self.missing_processes],
            "hidden_processes": [asdict(f) for f in self.hidden_processes],
            "dll_changes": [asdict(f) for f in self.dll_changes],
            "new_services": [asdict(f) for f in self.new_services],
            "new_drivers": [asdict(f) for f in self.new_drivers],
            "network_changes": [asdict(f) for f in self.network_changes],
            "registry_changes": [asdict(f) for f in self.registry_changes],
            "persistence_changes": [asdict(f) for f in self.persistence_changes],
            "injection_changes": [asdict(f) for f in self.injection_changes],
            "timeline_of_changes": self.timeline_of_changes,
            "summary": self.summary
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class SnapshotComparisonEngine:
    """Engine for comparing memory snapshots."""
    
    # Severity weights for scoring
    SEVERITY_WEIGHTS = {
        "critical": 10.0,
        "high": 7.0,
        "medium": 4.0,
        "low": 1.0,
    }
    
    # Change type multipliers
    CHANGE_MULTIPLIERS = {
        "new": 1.2,
        "removed": 1.0,
        "modified": 1.5,
        "hidden": 2.0,  # Hidden processes are highly suspicious
    }
    
    def __init__(self):
        self.baseline_data = None
        self.snapshot_data = None
    
    def load_snapshot_data(self, analysis_results: List[Dict]) -> Dict:
        """Convert analysis results to comparable snapshot data."""
        snapshot_data = {
            "processes": {},
            "dlls": defaultdict(list),
            "services": {},
            "drivers": {},
            "network_connections": [],
            "registry": {},
            "modules": {},
            "callbacks": [],
            "injections": [],
            "yara_matches": [],
            "metadata": {}
        }
        
        for result in analysis_results:
            finding_type = result.get("type", "").lower()
            
            if finding_type == "process":
                pid = result.get("process_id")
                if pid is not None:
                    snapshot_data["processes"][str(pid)] = {
                        "pid": pid,
                        "name": result.get("process_name", "Unknown"),
                        "ppid": result.get("parent_pid"),
                        "threads": result.get("threads"),
                        "handles": result.get("handles"),
                        "create_time": result.get("create_time"),
                        "wow64": result.get("wow64"),
                        "session": result.get("session_id"),
                    }
            
            elif finding_type == "dll":
                pid = result.get("process_id")
                dll_name = result.get("dll_name")
                if pid is not None and dll_name:
                    snapshot_data["dlls"][str(pid)].append({
                        "name": dll_name,
                        "path": result.get("dll_path"),
                        "load_time": result.get("load_time"),
                        "size": result.get("size"),
                    })
            
            elif finding_type == "service":
                svc_name = result.get("service_name")
                if svc_name:
                    snapshot_data["services"][svc_name] = {
                        "name": svc_name,
                        "display_name": result.get("display_name"),
                        "type": result.get("service_type"),
                        "state": result.get("state"),
                        "binary_path": result.get("binary_path"),
                        "start": result.get("start"),
                    }
            
            elif finding_type == "driver":
                driver_name = result.get("driver_name")
                if driver_name:
                    snapshot_data["drivers"][driver_name] = {
                        "name": driver_name,
                        "address": result.get("driver_address"),
                        "irp": result.get("irp_function"),
                        "module": result.get("module"),
                    }
            
            elif finding_type == "network":
                snapshot_data["network_connections"].append({
                    "protocol": result.get("protocol"),
                    "local_addr": result.get("local_address"),
                    "local_port": result.get("local_port"),
                    "remote_addr": result.get("remote_address"),
                    "remote_port": result.get("remote_port"),
                    "state": result.get("state"),
                    "pid": result.get("process_id"),
                    "process": result.get("process_name"),
                })
            
            elif finding_type == "registry":
                hive_name = result.get("hive_name")
                if hive_name:
                    snapshot_data["registry"][hive_name] = {
                        "name": hive_name,
                        "offset": result.get("hive_offset"),
                        "path": result.get("file_path"),
                    }
            
            elif finding_type == "injection" or result.get("is_injected"):
                snapshot_data["injections"].append({
                    "pid": result.get("process_id"),
                    "process": result.get("process_name"),
                    "address": result.get("memory_address"),
                    "protection": result.get("protection"),
                    "vad_tag": result.get("vad_tag"),
                })
            
            elif finding_type == "callback":
                snapshot_data["callbacks"].append({
                    "type": result.get("callback_type"),
                    "callback": result.get("callback_function"),
                    "module": result.get("module"),
                    "details": result.get("details"),
                })
            
            elif finding_type == "module":
                mod_name = result.get("module_name")
                if mod_name:
                    snapshot_data["modules"][mod_name] = {
                        "name": mod_name,
                        "base": result.get("base_address"),
                        "size": result.get("size"),
                        "file": result.get("file"),
                    }
            
            elif finding_type == "yara_match":
                snapshot_data["yara_matches"].append({
                    "rule": result.get("rule_name"),
                    "tags": result.get("tags", []),
                    "meta": result.get("meta", {}),
                    "severity": result.get("severity", "medium"),
                })
        
        return snapshot_data
    
    def compare_snapshots(
        self,
        baseline_results: List[Dict],
        snapshot_results: List[Dict],
        baseline_id: str,
        snapshot_id: str
    ) -> ComparisonResult:
        """
        Compare baseline snapshot against suspicious snapshot.
        
        Returns:
            ComparisonResult with all differences detected
        """
        self.baseline_data = self.load_snapshot_data(baseline_results)
        self.snapshot_data = self.load_snapshot_data(snapshot_results)
        
        result = ComparisonResult(
            baseline_id=baseline_id,
            snapshot_id=snapshot_id,
            comparison_time=datetime.now(timezone.utc).isoformat()
        )
        
        # Detect all types of changes
        self._detect_new_processes(result)
        self._detect_missing_processes(result)
        self._detect_hidden_processes(result)
        self._detect_dll_changes(result)
        self._detect_new_services(result)
        self._detect_new_drivers(result)
        self._detect_network_changes(result)
        self._detect_registry_changes(result)
        self._detect_persistence_changes(result)
        self._detect_injection_changes(result)
        
        # Calculate threat delta score
        result.threat_delta_score = self._calculate_threat_delta(result)
        result.changes_detected = (
            len(result.new_processes) +
            len(result.missing_processes) +
            len(result.hidden_processes) +
            len(result.dll_changes) +
            len(result.new_services) +
            len(result.new_drivers) +
            len(result.network_changes) +
            len(result.registry_changes) +
            len(result.persistence_changes) +
            len(result.injection_changes)
        )
        
        # Build timeline
        result.timeline_of_changes = self._build_timeline(result)
        
        # Generate summary
        result.summary = self._generate_summary(result)
        
        return result
    
    def _detect_new_processes(self, result: ComparisonResult) -> None:
        """Detect processes present in snapshot but not in baseline."""
        baseline_pids = set(self.baseline_data["processes"].keys())
        snapshot_pids = set(self.snapshot_data["processes"].keys())
        
        new_pids = snapshot_pids - baseline_pids
        
        for pid in new_pids:
            proc = self.snapshot_data["processes"][pid]
            
            # Check if it's a suspicious process
            severity = self._classify_process_risk(proc)
            
            finding = DifferenceFinding(
                change_type="new",
                category="process",
                item_name=f"{proc['name']} (PID: {pid})",
                snapshot_value=proc,
                severity=severity,
                confidence=80.0 if severity in ["critical", "high"] else 60.0,
                description=f"New process detected: {proc['name']} (PID: {pid}) "
                           f"not present in baseline. "
                           f"Parent: {proc.get('ppid', 'Unknown')}"
            )
            result.new_processes.append(finding)
    
    def _detect_missing_processes(self, result: ComparisonResult) -> None:
        """Detect processes present in baseline but missing in snapshot."""
        baseline_pids = set(self.baseline_data["processes"].keys())
        snapshot_pids = set(self.snapshot_data["processes"].keys())
        
        missing_pids = baseline_pids - snapshot_pids
        
        for pid in missing_pids:
            proc = self.baseline_data["processes"][pid]
            
            finding = DifferenceFinding(
                change_type="removed",
                category="process",
                item_name=f"{proc['name']} (PID: {pid})",
                baseline_value=proc,
                severity="medium",
                confidence=50.0,
                description=f"Process missing from snapshot: {proc['name']} (PID: {pid}) "
                           f"was present in baseline but not in current snapshot"
            )
            result.missing_processes.append(finding)
    
    def _detect_hidden_processes(self, result: ComparisonResult) -> None:
        """Detect hidden processes using cross-view analysis."""
        # Hidden processes are detected by comparing different sources:
        # - PsList (active processes)
        # - PsScan (memory scan)
        # - CSRSS list
        # - PSScan may find processes not in PsList
        
        # For comparison, if a process exists in snapshot's psscan but not in pslist
        # it's potentially hidden
        
        # In the context of snapshot comparison, we look for processes
        # that have characteristics of being hidden
        for pid, proc in self.snapshot_data["processes"].items():
            risk_score = 0
            indicators = []
            
            # Check for common hidden process indicators
            if proc.get("name") in ["svchost.exe", "csrss.exe", "lsass.exe"]:
                if not proc.get("parent_pid") or proc.get("parent_pid") == 0:
                    risk_score += 30
                    indicators.append("System process with no parent")
            
            if proc.get("threads") == 0 and proc.get("name") not in ["System", "Registry"]:
                risk_score += 40
                indicators.append("Process with zero threads")
            
            # Check if process name matches known malicious patterns
            suspicious_names = ["svch0st", "csrsss", "1sass", "crss"]
            if any(s in proc.get("name", "").lower() for s in suspicious_names):
                risk_score += 50
                indicators.append("Suspicious process name typo-squatting")
            
            if risk_score >= 40:
                finding = DifferenceFinding(
                    change_type="hidden",
                    category="process",
                    item_name=f"{proc['name']} (PID: {pid})",
                    snapshot_value=proc,
                    details={"risk_score": risk_score, "indicators": indicators},
                    severity="high" if risk_score >= 50 else "medium",
                    confidence=min(risk_score, 95.0),
                    description=f"Potentially hidden process: {proc['name']} (PID: {pid}). "
                               f"Indicators: {', '.join(indicators)}"
                )
                result.hidden_processes.append(finding)
    
    def _detect_dll_changes(self, result: ComparisonResult) -> None:
        """Detect DLL changes between snapshots."""
        baseline_dlls = self.baseline_data["dlls"]
        snapshot_dlls = self.snapshot_data["dlls"]
        
        all_pids = set(baseline_dlls.keys()) | set(snapshot_dlls.keys())
        
        for pid in all_pids:
            baseline_list = {d["name"]: d for d in baseline_dlls.get(pid, [])}
            snapshot_list = {d["name"]: d for d in snapshot_dlls.get(pid, [])}
            
            # New DLLs
            new_dlls = set(snapshot_list.keys()) - set(baseline_list.keys())
            for dll_name in new_dlls:
                dll_info = snapshot_list[dll_name]
                proc_name = self.snapshot_data["processes"].get(pid, {}).get("name", f"PID:{pid}")
                
                # Check for suspicious DLL characteristics
                severity = self._classify_dll_risk(dll_name, dll_info)
                
                finding = DifferenceFinding(
                    change_type="new",
                    category="dll",
                    item_name=f"{dll_name} in {proc_name}",
                    snapshot_value=dll_info,
                    severity=severity,
                    confidence=70.0 if severity in ["high", "critical"] else 50.0,
                    description=f"New DLL loaded: {dll_name} in process {proc_name} (PID: {pid})"
                )
                result.dll_changes.append(finding)
            
            # Modified DLLs
            common_dlls = set(baseline_list.keys()) & set(snapshot_list.keys())
            for dll_name in common_dlls:
                base_dll = baseline_list[dll_name]
                snap_dll = snapshot_list[dll_name]
                
                if base_dll.get("path") != snap_dll.get("path"):
                    proc_name = self.snapshot_data["processes"].get(pid, {}).get("name", f"PID:{pid}")
                    
                    finding = DifferenceFinding(
                        change_type="modified",
                        category="dll",
                        item_name=f"{dll_name} in {proc_name}",
                        baseline_value=base_dll,
                        snapshot_value=snap_dll,
                        severity="high",
                        confidence=75.0,
                        description=f"DLL path changed: {dll_name} in {proc_name}. "
                                   f"Baseline: {base_dll.get('path')} -> "
                                   f"Snapshot: {snap_dll.get('path')}"
                    )
                    result.dll_changes.append(finding)
    
    def _detect_new_services(self, result: ComparisonResult) -> None:
        """Detect new services in snapshot."""
        baseline_svcs = set(self.baseline_data["services"].keys())
        snapshot_svcs = set(self.snapshot_data["services"].keys())
        
        new_svcs = snapshot_svcs - baseline_svcs
        
        for svc_name in new_svcs:
            svc = self.snapshot_data["services"][svc_name]
            
            # Check for suspicious service characteristics
            severity = self._classify_service_risk(svc)
            
            finding = DifferenceFinding(
                change_type="new",
                category="service",
                item_name=svc_name,
                snapshot_value=svc,
                severity=severity,
                confidence=75.0 if severity == "high" else 55.0,
                description=f"New service detected: {svc_name} - {svc.get('display_name', '')}. "
                           f"Binary: {svc.get('binary_path', 'Unknown')}"
            )
            result.new_services.append(finding)
    
    def _detect_new_drivers(self, result: ComparisonResult) -> None:
        """Detect new kernel drivers in snapshot."""
        baseline_drivers = set(self.baseline_data["drivers"].keys())
        snapshot_drivers = set(self.snapshot_data["drivers"].keys())
        
        new_drivers = snapshot_drivers - baseline_drivers
        
        for driver_name in new_drivers:
            driver = self.snapshot_data["drivers"][driver_name]
            
            finding = DifferenceFinding(
                change_type="new",
                category="driver",
                item_name=driver_name,
                snapshot_value=driver,
                severity="high",  # New drivers are always suspicious
                confidence=80.0,
                description=f"New kernel driver detected: {driver_name}. "
                           f"Address: {driver.get('address', 'Unknown')}"
            )
            result.new_drivers.append(finding)
    
    def _detect_network_changes(self, result: ComparisonResult) -> None:
        """Detect network connection changes."""
        baseline_conns = self.baseline_data["network_connections"]
        snapshot_conns = self.snapshot_data["network_connections"]
        
        # Create connection signatures
        def conn_sig(conn):
            return f"{conn.get('local_addr')}:{conn.get('local_port')}->" \
                   f"{conn.get('remote_addr')}:{conn.get('remote_port')}"
        
        baseline_sigs = {conn_sig(c): c for c in baseline_conns}
        snapshot_sigs = {conn_sig(c): c for c in snapshot_conns}
        
        # New connections
        new_sigs = set(snapshot_sigs.keys()) - set(baseline_sigs.keys())
        for sig in new_sigs:
            conn = snapshot_sigs[sig]
            
            # Check for suspicious connections
            severity = self._classify_network_risk(conn)
            
            finding = DifferenceFinding(
                change_type="new",
                category="network",
                item_name=sig,
                snapshot_value=conn,
                severity=severity,
                confidence=70.0 if severity in ["high", "critical"] else 50.0,
                description=f"New network connection: {conn.get('protocol', 'TCP')} "
                           f"{conn.get('local_addr')}:{conn.get('local_port')} -> "
                           f"{conn.get('remote_addr')}:{conn.get('remote_port')} "
                           f"(PID: {conn.get('pid', 'Unknown')})"
            )
            result.network_changes.append(finding)
    
    def _detect_registry_changes(self, result: ComparisonResult) -> None:
        """Detect registry hive changes."""
        baseline_reg = set(self.baseline_data["registry"].keys())
        snapshot_reg = set(self.snapshot_data["registry"].keys())
        
        new_reg = snapshot_reg - baseline_reg
        missing_reg = baseline_reg - snapshot_reg
        
        for reg_name in new_reg:
            reg = self.snapshot_data["registry"][reg_name]
            finding = DifferenceFinding(
                change_type="new",
                category="registry",
                item_name=reg_name,
                snapshot_value=reg,
                severity="medium",
                confidence=55.0,
                description=f"New registry hive: {reg_name} at {reg.get('path', 'Unknown')}"
            )
            result.registry_changes.append(finding)
        
        for reg_name in missing_reg:
            reg = self.baseline_data["registry"][reg_name]
            finding = DifferenceFinding(
                change_type="removed",
                category="registry",
                item_name=reg_name,
                baseline_value=reg,
                severity="low",
                confidence=40.0,
                description=f"Registry hive missing: {reg_name}"
            )
            result.registry_changes.append(finding)
    
    def _detect_persistence_changes(self, result: ComparisonResult) -> None:
        """Detect new persistence mechanisms."""
        # Persistence can be indicated by:
        # - New services set to auto-start
        # - New registry run keys
        # - New scheduled tasks
        # - New Winlogon entries
        
        for svc_name, svc in self.snapshot_data["services"].items():
            if svc.get("start") in ["SERVICE_AUTO_START", "2", "auto"]:
                if svc_name not in self.baseline_data["services"]:
                    finding = DifferenceFinding(
                        change_type="new",
                        category="persistence",
                        item_name=svc_name,
                        snapshot_value=svc,
                        severity="high",
                        confidence=80.0,
                        description=f"New auto-start service (persistence): {svc_name}. "
                                   f"Binary: {svc.get('binary_path', 'Unknown')}"
                    )
                    result.persistence_changes.append(finding)
    
    def _detect_injection_changes(self, result: ComparisonResult) -> None:
        """Detect new memory injections."""
        baseline_injections = {
            f"{i['pid']}:{i['address']}": i 
            for i in self.baseline_data["injections"]
        }
        snapshot_injections = {
            f"{i['pid']}:{i['address']}": i 
            for i in self.snapshot_data["injections"]
        }
        
        new_injections = set(snapshot_injections.keys()) - set(baseline_injections.keys())
        
        for inj_key in new_injections:
            inj = snapshot_injections[inj_key]
            finding = DifferenceFinding(
                change_type="new",
                category="injection",
                item_name=f"{inj['process']}:{inj['address']}",
                snapshot_value=inj,
                severity="critical",
                confidence=90.0,
                description=f"New memory injection detected in {inj['process']} (PID: {inj['pid']}) "
                           f"at address {inj['address']} with protection {inj.get('protection', 'Unknown')}"
            )
            result.injection_changes.append(finding)
    
    def _calculate_threat_delta(self, result: ComparisonResult) -> float:
        """Calculate overall threat delta score."""
        score = 0.0
        
        all_changes = (
            result.new_processes +
            result.missing_processes +
            result.hidden_processes +
            result.dll_changes +
            result.new_services +
            result.new_drivers +
            result.network_changes +
            result.registry_changes +
            result.persistence_changes +
            result.injection_changes
        )
        
        for finding in all_changes:
            weight = self.SEVERITY_WEIGHTS.get(finding.severity, 4.0)
            multiplier = self.CHANGE_MULTIPLIERS.get(finding.change_type, 1.0)
            score += weight * multiplier
        
        # Cap at 100
        return min(score, 100.0)
    
    def _build_timeline(self, result: ComparisonResult) -> List[Dict]:
        """Build timeline of changes."""
        timeline = []
        
        all_changes = (
            result.new_processes +
            result.missing_processes +
            result.hidden_processes +
            result.dll_changes +
            result.new_services +
            result.new_drivers +
            result.network_changes +
            result.registry_changes +
            result.persistence_changes +
            result.injection_changes
        )
        
        for finding in all_changes:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "change_type": finding.change_type,
                "category": finding.category,
                "item": finding.item_name,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "description": finding.description
            }
            timeline.append(entry)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        timeline.sort(key=lambda x: severity_order.get(x["severity"], 2))
        
        return timeline
    
    def _generate_summary(self, result: ComparisonResult) -> Dict:
        """Generate comparison summary."""
        return {
            "baseline_id": result.baseline_id,
            "snapshot_id": result.snapshot_id,
            "total_changes": result.changes_detected,
            "threat_delta_score": round(result.threat_delta_score, 2),
            "risk_level": self._score_to_risk_level(result.threat_delta_score),
            "breakdown": {
                "new_processes": len(result.new_processes),
                "missing_processes": len(result.missing_processes),
                "hidden_processes": len(result.hidden_processes),
                "dll_changes": len(result.dll_changes),
                "new_services": len(result.new_services),
                "new_drivers": len(result.new_drivers),
                "network_changes": len(result.network_changes),
                "registry_changes": len(result.registry_changes),
                "persistence_changes": len(result.persistence_changes),
                "injection_changes": len(result.injection_changes),
            },
            "severity_counts": {
                "critical": sum(1 for f in self._all_findings(result) if f.severity == "critical"),
                "high": sum(1 for f in self._all_findings(result) if f.severity == "high"),
                "medium": sum(1 for f in self._all_findings(result) if f.severity == "medium"),
                "low": sum(1 for f in self._all_findings(result) if f.severity == "low"),
            },
            "recommendation": self._generate_recommendation(result)
        }
    
    def _all_findings(self, result: ComparisonResult) -> List[DifferenceFinding]:
        """Get all findings from result."""
        return (
            result.new_processes +
            result.missing_processes +
            result.hidden_processes +
            result.dll_changes +
            result.new_services +
            result.new_drivers +
            result.network_changes +
            result.registry_changes +
            result.persistence_changes +
            result.injection_changes
        )
    
    def _score_to_risk_level(self, score: float) -> str:
        """Convert score to risk level."""
        if score >= 90: return "CRITICAL"
        if score >= 70: return "HIGH"
        if score >= 50: return "MEDIUM"
        if score >= 30: return "LOW"
        return "MINIMAL"
    
    def _classify_process_risk(self, proc: Dict) -> str:
        """Classify process risk level."""
        name = proc.get("name", "").lower()
        
        suspicious = [
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
            "vssadmin.exe", "wbadmin.exe", "wevtutil.exe",
        ]
        
        if any(s in name for s in suspicious):
            return "high"
        
        if proc.get("parent_pid") == 0 and name not in ["system", "registry", "smss.exe"]:
            return "medium"
        
        return "low"
    
    def _classify_dll_risk(self, dll_name: str, dll_info: Dict) -> str:
        """Classify DLL risk level."""
        name = dll_name.lower()
        path = (dll_info.get("path") or "").lower()
        
        # Unsigned DLLs in system directories
        if "\\windows\\system32" in path or "\\windows\\syswow64" in path:
            if not name.endswith(".dll"):
                return "high"
        
        # DLLs loaded from temp directories
        if "\\temp\\" in path or "\\tmp\\" in path:
            return "high"
        
        # Known suspicious DLL patterns
        suspicious_patterns = ["api", "hook", "inject", "patch", "reflect"]
        if any(p in name for p in suspicious_patterns):
            return "medium"
        
        return "low"
    
    def _classify_service_risk(self, svc: Dict) -> str:
        """Classify service risk level."""
        binary_path = (svc.get("binary_path") or "").lower()
        
        if "\\temp\\" in binary_path or "\\tmp\\" in binary_path:
            return "critical"
        
        if "\\users\\" in binary_path and "\\appdata\\" in binary_path:
            return "high"
        
        if not binary_path.endswith(".exe") and binary_path:
            return "medium"
        
        return "low"
    
    def _classify_network_risk(self, conn: Dict) -> str:
        """Classify network connection risk."""
        remote_addr = conn.get("remote_addr", "")
        remote_port = conn.get("remote_port", 0)
        
        # Common C2 ports
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 443, 80]
        
        if remote_port in suspicious_ports:
            return "medium"
        
        # External connections
        if remote_addr and not remote_addr.startswith(("10.", "192.168.", "172.")):
            if remote_addr not in ["0.0.0.0", "127.0.0.1", "::"]:
                return "medium"
        
        return "low"
    
    def _generate_recommendation(self, result: ComparisonResult) -> str:
        """Generate actionable recommendation based on findings."""
        if result.threat_delta_score >= 90:
            return (
                "CRITICAL: Immediate incident response required. "
                "Multiple severe anomalies detected including potential memory injections, "
                "hidden processes, and persistence mechanisms. Isolate the system immediately "
                "and begin full forensic investigation."
            )
        elif result.threat_delta_score >= 70:
            return (
                "HIGH: Significant suspicious activity detected. "
                "Review all high-severity findings immediately. "
                "Consider isolating the system and conducting deeper analysis. "
                "Focus on memory injections, unauthorized services, and suspicious network connections."
            )
        elif result.threat_delta_score >= 50:
            return (
                "MEDIUM: Moderate changes detected from baseline. "
                "Review new processes, services, and DLL changes. "
                "Some changes may be legitimate system updates. "
                "Validate each finding against expected change management."
            )
        elif result.threat_delta_score >= 30:
            return (
                "LOW: Minor changes detected. "
                "Most changes are likely benign but should be reviewed for completeness. "
                "Verify new processes and network connections."
            )
        else:
            return (
                "MINIMAL: Few or no significant changes from baseline. "
                "System appears consistent with baseline configuration. "
                "Continue routine monitoring."
            )