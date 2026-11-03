"""
Enterprise Memory Forensics Platform - Timeline Reconstruction
===============================================================
Builds forensic timelines from multiple memory analysis sources.
"""

import json
import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from collections import defaultdict


@dataclass
class TimelineEntry:
    """Single entry in the forensic timeline."""
    timestamp: str
    event_type: str  # process_created, dll_loaded, network_connection, registry_modified, service_started, driver_loaded, injection_detected
    category: str    # process, dll, network, registry, service, driver, injection
    description: str
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    parent_pid: Optional[int] = None
    details: Dict = field(default_factory=dict)
    significance: str = "medium"  # critical, high, medium, low
    source: str = "memory_analysis"
    related_events: List[str] = field(default_factory=list)
    iocs: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)


class TimelineReconstructor:
    """
    Timeline reconstruction engine.
    
    Builds comprehensive timelines from:
    - Process creation events
    - DLL loading events
    - Network activity
    - Registry events
    - Service creation
    - Driver loading
    - Memory injection events
    """
    
    EVENT_TYPE_ORDER = [
        "driver_loaded",
        "service_started",
        "process_created",
        "dll_loaded",
        "registry_modified",
        "network_connection",
        "injection_detected",
    ]
    
    SIGNIFICANCE_WEIGHTS = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }
    
    def __init__(self):
        self.entries: List[TimelineEntry] = []
    
    def build_timeline(
        self,
        processes: List[Dict] = None,
        dlls: List[Dict] = None,
        network: List[Dict] = None,
        registry: List[Dict] = None,
        services: List[Dict] = None,
        drivers: List[Dict] = None,
        injections: List[Dict] = None,
        callbacks: List[Dict] = None
    ) -> List[TimelineEntry]:
        """
        Build comprehensive timeline from all memory analysis results.
        
        Args:
            processes: Process list findings
            dlls: DLL list findings
            network: Network connection findings
            registry: Registry findings
            services: Service findings
            drivers: Driver findings
            injections: Memory injection findings
            callbacks: Callback findings
        
        Returns:
            List of TimelineEntry sorted chronologically
        """
        self.entries = []
        
        if processes:
            self._add_process_events(processes)
        
        if dlls:
            self._add_dll_events(dlls)
        
        if network:
            self._add_network_events(network)
        
        if registry:
            self._add_registry_events(registry)
        
        if services:
            self._add_service_events(services)
        
        if drivers:
            self._add_driver_events(drivers)
        
        if injections:
            self._add_injection_events(injections)
        
        if callbacks:
            self._add_callback_events(callbacks)
        
        # Sort by timestamp
        self.entries.sort(key=lambda e: (e.timestamp or "", self.EVENT_TYPE_ORDER.index(e.event_type) if e.event_type in self.EVENT_TYPE_ORDER else 99))
        
        # Link related events
        self._link_related_events()
        
        return self.entries
    
    def _add_process_events(self, processes: List[Dict]) -> None:
        """Add process creation events to timeline."""
        for proc in processes:
            entry = TimelineEntry(
                timestamp=proc.get("create_time") or datetime.now(timezone.utc).isoformat(),
                event_type="process_created",
                category="process",
                description=f"Process created: {proc.get('name', 'Unknown')} (PID: {proc.get('pid', '?')})",
                process_name=proc.get("name"),
                process_id=proc.get("pid"),
                parent_process=proc.get("parent_name"),
                parent_pid=proc.get("ppid"),
                details={
                    "threads": proc.get("threads"),
                    "handles": proc.get("handles"),
                    "wow64": proc.get("wow64"),
                    "session": proc.get("session_id"),
                    "path": proc.get("exe_path") or proc.get("path"),
                },
                significance=self._classify_process_significance(proc)
            )
            self.entries.append(entry)
    
    def _add_dll_events(self, dlls: List[Dict]) -> None:
        """Add DLL loading events to timeline."""
        for dll in dlls:
            entry = TimelineEntry(
                timestamp=dll.get("load_time") or datetime.now(timezone.utc).isoformat(),
                event_type="dll_loaded",
                category="dll",
                description=f"DLL loaded: {dll.get('dll_name', 'Unknown')} into {dll.get('process_name', '?')} (PID: {dll.get('pid', '?')})",
                process_name=dll.get("process_name"),
                process_id=dll.get("pid"),
                details={
                    "dll_name": dll.get("dll_name"),
                    "dll_path": dll.get("dll_path"),
                    "size": dll.get("size"),
                },
                significance=self._classify_dll_significance(dll)
            )
            self.entries.append(entry)
    
    def _add_network_events(self, network: List[Dict]) -> None:
        """Add network connection events to timeline."""
        for conn in network:
            entry = TimelineEntry(
                timestamp=conn.get("create_time") or datetime.now(timezone.utc).isoformat(),
                event_type="network_connection",
                category="network",
                description=(
                    f"Network {conn.get('protocol', 'TCP')} connection: "
                    f"{conn.get('local_address', '?')}:{conn.get('local_port', '?')} -> "
                    f"{conn.get('remote_address', '?')}:{conn.get('remote_port', '?')} "
                    f"({conn.get('state', 'Unknown')})"
                ),
                process_name=conn.get("process"),
                process_id=conn.get("pid"),
                details={
                    "protocol": conn.get("protocol"),
                    "local_addr": conn.get("local_address"),
                    "local_port": conn.get("local_port"),
                    "remote_addr": conn.get("remote_address"),
                    "remote_port": conn.get("remote_port"),
                    "state": conn.get("state"),
                },
                significance=self._classify_network_significance(conn),
                iocs=[{"type": "ip", "value": conn.get("remote_address")}] if conn.get("remote_address") else []
            )
            self.entries.append(entry)
    
    def _add_registry_events(self, registry: List[Dict]) -> None:
        """Add registry events to timeline."""
        for reg in registry:
            entry = TimelineEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="registry_modified",
                category="registry",
                description=f"Registry hive: {reg.get('hive_name', 'Unknown')}",
                details={
                    "hive_name": reg.get("hive_name"),
                    "hive_offset": reg.get("hive_offset"),
                    "file_path": reg.get("file_path"),
                },
                significance="medium"
            )
            self.entries.append(entry)
    
    def _add_service_events(self, services: List[Dict]) -> None:
        """Add service events to timeline."""
        for svc in services:
            # Determine if auto-start (persistence indicator)
            is_auto = svc.get("start") in ["SERVICE_AUTO_START", "2", "auto"]
            
            entry = TimelineEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="service_started",
                category="service",
                description=f"Service: {svc.get('service_name', 'Unknown')} - {svc.get('display_name', '')}",
                details={
                    "service_name": svc.get("service_name"),
                    "display_name": svc.get("display_name"),
                    "service_type": svc.get("type"),
                    "state": svc.get("state"),
                    "binary_path": svc.get("binary_path"),
                    "start_type": svc.get("start"),
                    "is_auto_start": is_auto,
                },
                significance="high" if is_auto else "medium"
            )
            self.entries.append(entry)
    
    def _add_driver_events(self, drivers: List[Dict]) -> None:
        """Add driver loading events to timeline."""
        for driver in drivers:
            entry = TimelineEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="driver_loaded",
                category="driver",
                description=f"Driver loaded: {driver.get('driver_name', 'Unknown')}",
                details={
                    "driver_name": driver.get("driver_name"),
                    "driver_address": driver.get("driver_address"),
                    "irp_function": driver.get("irp_function"),
                    "module": driver.get("module"),
                },
                significance="high"  # Driver loads are always significant
            )
            self.entries.append(entry)
    
    def _add_injection_events(self, injections: List[Dict]) -> None:
        """Add memory injection events to timeline."""
        for inj in injections:
            entry = TimelineEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="injection_detected",
                category="injection",
                description=(
                    f"Memory injection detected in {inj.get('process', 'Unknown')} "
                    f"(PID: {inj.get('pid', '?')}) at {inj.get('address', 'Unknown')}"
                ),
                process_name=inj.get("process"),
                process_id=inj.get("pid"),
                details={
                    "memory_address": inj.get("address"),
                    "protection": inj.get("protection"),
                    "vad_tag": inj.get("vad_tag"),
                    "size": inj.get("size"),
                },
                significance="critical"
            )
            self.entries.append(entry)
    
    def _add_callback_events(self, callbacks: List[Dict]) -> None:
        """Add callback events to timeline."""
        for cb in callbacks:
            entry = TimelineEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="callback_registered",
                category="callback",
                description=f"Callback registered: {cb.get('callback_type', 'Unknown')}",
                details={
                    "callback_type": cb.get("callback_type"),
                    "callback_function": cb.get("callback"),
                    "module": cb.get("module"),
                    "details": cb.get("details"),
                },
                significance="high"
            )
            self.entries.append(entry)
    
    def _link_related_events(self) -> None:
        """Link related timeline events together."""
        # Group by process
        process_events = defaultdict(list)
        for i, entry in enumerate(self.entries):
            if entry.process_id is not None:
                process_events[entry.process_id].append(i)
        
        # Link events for the same process
        for pid, indices in process_events.items():
            if len(indices) > 1:
                event_ids = [f"EVT_{idx}" for idx in indices]
                for idx in indices:
                    self.entries[idx].related_events = [eid for eid in event_ids if eid != f"EVT_{idx}"]
    
    _SUSPICIOUS_CMD = re.compile(
        r"(-enc\b|-encodedcommand|-nop\b|-w\s+hidden|-urlcache|https?://|\\temp\\|\\public\\|\\appdata\\|"
        r"sekurlsa|privilege::|comsvcs|minidump|\.hta\b|\.vbs\b|\bfrombase64string\b)", re.I)
    _LOLBINS = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "regsvr32.exe", "rundll32.exe", "certutil.exe"}

    def _classify_process_significance(self, proc: Dict) -> str:
        """Judge significance from evidence, not from process names alone.

        Core OS processes are routine (low). Script hosts / LOLBins are only notable
        (medium) until their command line looks malicious (high). Detection results
        can raise any entry further via escalate_from_detections().
        """
        name = (proc.get("name") or "").lower()
        cmd = str(proc.get("command_line") or proc.get("cmdline") or "")
        if cmd and self._SUSPICIOUS_CMD.search(cmd):
            return "high"
        if name in self._LOLBINS:
            return "medium"
        return "low"

    def escalate_from_detections(self, detections) -> None:
        """Raise the significance of events whose process was implicated by a detection."""
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        by_rank = {v: k for k, v in rank.items()}
        worst: Dict[int, int] = {}
        for d in detections or []:
            if not getattr(d, "detected", False):
                continue
            pids = set()
            for ind in getattr(d, "process_indicators", []) or []:
                pids.update(int(x) for x in re.findall(r"PID\s+(\d+)", str(ind)))
            for ev in getattr(d, "evidence", []) or []:
                if isinstance(ev, dict) and isinstance(ev.get("pid"), int):
                    pids.add(ev["pid"])
            for pid in pids:
                worst[pid] = max(worst.get(pid, 0), rank.get(str(d.severity).lower(), 2))
        for entry in self.entries:
            target = worst.get(entry.process_id)
            if target and rank.get(entry.significance, 0) < target:
                entry.significance = by_rank[target]

    def _classify_dll_significance(self, dll: Dict) -> str:
        """Classify DLL event significance."""
        path = (dll.get("dll_path") or "").lower()
        
        if "\\temp\\" in path or "\\appdata\\" in path:
            return "high"
        
        if "\\windows\\system32" in path or "\\windows\\syswow64" in path:
            return "low"
        
        return "medium"
    
    def _classify_network_significance(self, conn: Dict) -> str:
        """Classify network event significance."""
        remote_addr = conn.get("remote_address", "")
        remote_port = conn.get("remote_port", 0)
        
        # External connections
        if remote_addr and not remote_addr.startswith(("10.", "192.168.", "172.")):
            if remote_addr not in ["0.0.0.0", "127.0.0.1", "::"]:
                return "medium"
        
        # Common C2 ports
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999]
        if remote_port in suspicious_ports:
            return "high"
        
        return "low"
    
    def get_timeline_summary(self) -> Dict:
        """Get summary statistics for the timeline."""
        if not self.entries:
            return {"total_events": 0}
        
        # Count by category
        category_counts = defaultdict(int)
        significance_counts = defaultdict(int)
        
        for entry in self.entries:
            category_counts[entry.category] += 1
            significance_counts[entry.significance] += 1
        
        # Get time range
        timestamps = [e.timestamp for e in self.entries if e.timestamp]
        
        return {
            "total_events": len(self.entries),
            "time_range": {
                "start": min(timestamps) if timestamps else None,
                "end": max(timestamps) if timestamps else None,
            },
            "by_category": dict(category_counts),
            "by_significance": dict(significance_counts),
            "critical_events": [
                e.to_dict() for e in self.entries 
                if e.significance == "critical"
            ],
        }
    
    def export_timeline(self, output_path: str, format: str = "json") -> str:
        """Export timeline to file."""
        data = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_events": len(self.entries),
            },
            "timeline": [e.to_dict() for e in self.entries]
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        return output_path