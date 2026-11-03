"""
Enterprise Memory Forensics Platform - Multi-Engine Analysis
=============================================================
Orchestrates Volatility 3, YARA, and other analysis engines.
"""

import os
import json
import subprocess
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from config.settings import VOLATILITY_CONFIG, YARA_CONFIG


logger = logging.getLogger(__name__)


@dataclass
class EngineResult:
    """Result from a single analysis engine."""
    engine_name: str
    plugin_name: str
    status: str  # success, error, timeout
    findings: List[Dict]
    execution_time: float
    raw_output: Optional[str] = None
    error_message: Optional[str] = None
    parsed_data: Optional[Dict] = None


@dataclass
class AnalysisSession:
    """Complete analysis session results."""
    session_id: str
    snapshot_id: str
    memory_path: str
    start_time: str
    end_time: Optional[str] = None
    engine_results: List[EngineResult] = None
    aggregated_findings: List[Dict] = None
    status: str = "running"  # running, completed, failed
    
    def __post_init__(self):
        if self.engine_results is None:
            self.engine_results = []
        if self.aggregated_findings is None:
            self.aggregated_findings = []


class VolatilityEngine:
    """Volatility 3 memory analysis engine."""
    
    REQUIRED_PLUGINS = [
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
    ]
    
    def __init__(self, timeout: int = 3600):
        self.timeout = timeout
        self.config = VOLATILITY_CONFIG
        logger.info("Volatility 3 Engine initialized")
    
    def _run_volatility(self, memory_path: str, plugin: str) -> Dict:
        """Execute a Volatility 3 plugin."""
        cmd = [
            "python", "-m", "volatility3",
            "-f", memory_path,
            "-r", "json",
            plugin
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    return {"status": "success", "data": data}
                except json.JSONDecodeError:
                    return {
                        "status": "success",
                        "data": result.stdout,
                        "format": "raw"
                    }
            else:
                return {
                    "status": "error",
                    "error": result.stderr,
                    "returncode": result.returncode
                }
        
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": f"Plugin {plugin} timed out"}
        except FileNotFoundError:
            return {
                "status": "error",
                "error": "Volatility 3 not found. Install with: pip install volatility3"
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def run_plugin(self, memory_path: str, plugin: str) -> EngineResult:
        """Run a single Volatility plugin."""
        start_time = time.time()
        
        result = self._run_volatility(memory_path, plugin)
        execution_time = time.time() - start_time
        
        findings = []
        if result["status"] == "success":
            data = result.get("data", [])
            if isinstance(data, list):
                for item in data:
                    finding = self._parse_finding(plugin, item)
                    if finding:
                        findings.append(finding)
        
        return EngineResult(
            engine_name="volatility3",
            plugin_name=plugin,
            status=result["status"],
            findings=findings,
            execution_time=execution_time,
            raw_output=json.dumps(result) if isinstance(result.get("data"), (dict, list)) else str(result.get("data", "")),
            error_message=result.get("error")
        )
    
    def _parse_finding(self, plugin: str, data: Dict) -> Optional[Dict]:
        """Parse a single finding from plugin output."""
        finding = {
            "engine": "volatility3",
            "plugin": plugin,
            "type": self._get_plugin_type(plugin),
            "raw": data
        }
        
        # Plugin-specific parsing
        if "pslist" in plugin or "psscan" in plugin or "pstree" in plugin:
            finding.update({
                "process_id": data.get("PID") or data.get("pid"),
                "process_name": data.get("ImageFileName") or data.get("name"),
                "parent_pid": data.get("PPID") or data.get("ppid"),
                "threads": data.get("Threads") or data.get("threads"),
                "handles": data.get("Handles") or data.get("handles"),
                "create_time": data.get("CreateTime") or data.get("created"),
                "exit_time": data.get("ExitTime") or data.get("exited"),
                "wow64": data.get("Wow64") or data.get("wow64"),
                "session_id": data.get("SessionId") or data.get("session"),
            })
        
        elif "dlllist" in plugin:
            finding.update({
                "process_id": data.get("PID") or data.get("pid"),
                "process_name": data.get("BaseDllName") or data.get("Process"),
                "dll_name": data.get("Name") or data.get("dll"),
                "dll_path": data.get("Path") or data.get("path"),
                "load_time": data.get("LoadTime") or data.get("loaded"),
                "size": data.get("Size") or data.get("size"),
            })
        
        elif "malfind" in plugin:
            finding.update({
                "process_id": data.get("PID") or data.get("pid"),
                "process_name": data.get("Process") or data.get("process"),
                "memory_address": data.get("Address") or data.get("address"),
                "vad_tag": data.get("VadTag") or data.get("tag"),
                "protection": data.get("Protection") or data.get("protection"),
                "commit_charge": data.get("CommitCharge") or data.get("commit"),
                "private_memory": data.get("PrivateMemory") or data.get("private"),
                "is_injected": True,
                "suspicious": True,
            })
        
        elif "netscan" in plugin:
            finding.update({
                "protocol": data.get("Protocol") or data.get("protocol"),
                "local_address": data.get("LocalAddr") or data.get("local"),
                "local_port": data.get("LocalPort") or data.get("local_port"),
                "remote_address": data.get("ForeignAddr") or data.get("remote"),
                "remote_port": data.get("ForeignPort") or data.get("remote_port"),
                "state": data.get("State") or data.get("state"),
                "process_id": data.get("PID") or data.get("pid"),
                "process_name": data.get("Owner") or data.get("process"),
                "create_time": data.get("CreateTime") or data.get("created"),
            })
        
        elif "svcscan" in plugin:
            finding.update({
                "service_name": data.get("ServiceName") or data.get("name"),
                "display_name": data.get("DisplayName") or data.get("display"),
                "service_type": data.get("Type") or data.get("type"),
                "state": data.get("State") or data.get("state"),
                "binary_path": data.get("Binary") or data.get("path"),
                "order": data.get("Order") or data.get("order"),
                "pid": data.get("PID") or data.get("pid"),
                "start": data.get("Start") or data.get("start"),
            })
        
        elif "callbacks" in plugin:
            finding.update({
                "callback_type": data.get("Type") or data.get("type"),
                "callback_function": data.get("Callback") or data.get("callback"),
                "module": data.get("Module") or data.get("module"),
                "details": data.get("Details") or data.get("details"),
            })
        
        elif "driverirp" in plugin:
            finding.update({
                "driver_name": data.get("DriverName") or data.get("driver"),
                "driver_address": data.get("DriverAddress") or data.get("address"),
                "irp_function": data.get("IRP") or data.get("irp"),
                "module": data.get("Module") or data.get("module"),
            })
        
        elif "modscan" in plugin:
            finding.update({
                "module_name": data.get("Name") or data.get("name"),
                "base_address": data.get("Base") or data.get("base"),
                "size": data.get("Size") or data.get("size"),
                "file": data.get("File") or data.get("file"),
            })
        
        elif "registry" in plugin:
            finding.update({
                "hive_name": data.get("Name") or data.get("name"),
                "hive_offset": data.get("Offset") or data.get("offset"),
                "file_path": data.get("FileFullPath") or data.get("path"),
            })
        
        return {k: v for k, v in finding.items() if v is not None}
    
    def _get_plugin_type(self, plugin: str) -> str:
        """Map plugin to finding type."""
        type_map = {
            "pslist": "process",
            "psscan": "process",
            "pstree": "process",
            "dlllist": "dll",
            "malfind": "injection",
            "netscan": "network",
            "svcscan": "service",
            "callbacks": "callback",
            "driverirp": "driver",
            "modscan": "module",
            "registry": "registry",
        }
        for key, val in type_map.items():
            if key in plugin.lower():
                return val
        return "unknown"
    
    def analyze(self, memory_path: str, plugins: Optional[List[str]] = None) -> List[EngineResult]:
        """Run all Volatility 3 plugins."""
        plugins = plugins or self.REQUIRED_PLUGINS
        results = []
        
        logger.info(f"Starting Volatility 3 analysis on {memory_path}")
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {
                executor.submit(self.run_plugin, memory_path, plugin): plugin 
                for plugin in plugins
            }
            
            for future in as_completed(futures):
                plugin = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"Plugin {plugin}: {result.status} - {len(result.findings)} findings")
                except Exception as e:
                    logger.error(f"Plugin {plugin} failed: {e}")
                    results.append(EngineResult(
                        engine_name="volatility3",
                        plugin_name=plugin,
                        status="error",
                        findings=[],
                        execution_time=0.0,
                        error_message=str(e)
                    ))
        
        logger.info(f"Volatility 3 analysis complete. {len(results)} plugins executed.")
        return results


class YARAAnalyzer:
    """YARA rule-based memory scanner."""
    
    def __init__(self):
        self.config = YARA_CONFIG
        self.rules = []
        self.compiled_rules = None
        logger.info("YARA Engine initialized")
    
    def load_rules(self, rule_paths: Optional[List[str]] = None) -> bool:
        """Load and compile YARA rules."""
        try:
            import yara
            
            rule_paths = rule_paths or self.config.rule_directories
            rule_dict = {}
            
            for path in rule_paths:
                rule_dir = Path(path)
                if rule_dir.exists():
                    for rule_file in rule_dir.rglob("*.yar"):
                        try:
                            namespace = str(rule_file.relative_to(rule_dir)).replace("/", "_")
                            rule_dict[namespace] = str(rule_file)
                        except Exception as e:
                            logger.warning(f"Failed to load rule {rule_file}: {e}")
            
            if rule_dict:
                self.compiled_rules = yara.compile(filepaths=rule_dict)
                logger.info(f"Compiled {len(rule_dict)} YARA rules")
                return True
            else:
                logger.warning("No YARA rules found")
                return False
                
        except ImportError:
            logger.error("yara-python not installed")
            return False
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            return False
    
    
    def scan_directory_or_file(self, target_path: str) -> EngineResult:
        """Scan a file or directory with YARA rules."""
        start_time = time.time()
        
        if self.compiled_rules is None:
            if not self.load_rules():
                return EngineResult(
                    engine_name="yara",
                    plugin_name="static_scan",
                    status="error",
                    findings=[],
                    execution_time=0.0,
                    error_message="YARA rules not loaded"
                )
        
        findings = []
        target = Path(target_path)
        
        try:
            if target.is_file():
                files_to_scan = [target]
            elif target.is_dir():
                files_to_scan = [f for f in target.rglob("*") if f.is_file() and f.suffix not in ['.pyc', '.git']]
            else:
                raise FileNotFoundError(f"Target not found: {target_path}")

            for file_path in files_to_scan:
                try:
                    matches = self.compiled_rules.match(filepath=str(file_path))
                    for match in matches:
                        finding = {
                            "engine": "yara",
                            "plugin": "static_scan",
                            "type": "yara_match",
                            "rule_name": match.rule,
                            "namespace": match.namespace,
                            "file_matched": str(file_path.name),
                            "tags": list(match.tags),
                            "meta": dict(match.meta),
                            "strings": [
                                {
                                    "identifier": s.identifier,
                                    "instances": [
                                        {
                                            "offset": i.offset,
                                            "matched_data": i.matched_data.decode('utf-8', errors='ignore') if i.matched_data else None
                                        }
                                        for i in s.instances[:3] # Limit to 3 instances to avoid huge payloads
                                    ]
                                }
                                for s in match.strings
                            ],
                            "severity": self._classify_yara_match(match),
                        }
                        findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to scan {file_path}: {e}")
            
            execution_time = time.time() - start_time
            
            return EngineResult(
                engine_name="yara",
                plugin_name="static_scan",
                status="success",
                findings=findings,
                execution_time=execution_time
            )
            
        except Exception as e:
            logger.error(f"YARA scan failed: {e}")
            return EngineResult(
                engine_name="yara",
                plugin_name="static_scan",
                status="error",
                findings=[],
                execution_time=time.time() - start_time,
                error_message=str(e)
            )

    def scan_memory(self, memory_path: str) -> EngineResult:
        """Scan memory dump with YARA rules."""
        start_time = time.time()
        
        if self.compiled_rules is None:
            if not self.load_rules():
                return EngineResult(
                    engine_name="yara",
                    plugin_name="memory_scan",
                    status="error",
                    findings=[],
                    execution_time=0.0,
                    error_message="YARA rules not loaded"
                )
        
        findings = []
        
        try:
            # Scan in chunks for large files
            chunk_size = 1024 * 1024 * 100  # 100MB chunks
            file_size = Path(memory_path).stat().st_size
            
            if file_size > chunk_size:
                # For large files, scan in chunks
                with open(memory_path, 'rb') as f:
                    offset = 0
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        
                        matches = self.compiled_rules.match(data=chunk)
                        for match in matches:
                            finding = {
                                "engine": "yara",
                                "plugin": "memory_scan",
                                "type": "yara_match",
                                "rule_name": match.rule,
                                "namespace": match.namespace,
                                "tags": list(match.tags),
                                "meta": dict(match.meta),
                                "strings": [
                                    {
                                        "identifier": s.identifier,
                                        "instances": [
                                            {
                                                "offset": i.offset + offset,
                                                "matched_data": i.matched_data.hex()[:100] if i.matched_data else None
                                            }
                                            for i in s.instances
                                        ]
                                    }
                                    for s in match.strings
                                ],
                                "memory_offset": offset,
                                "severity": self._classify_yara_match(match),
                            }
                            findings.append(finding)
                        
                        offset += len(chunk)
            else:
                matches = self.compiled_rules.match(filepath=memory_path)
                for match in matches:
                    finding = {
                        "engine": "yara",
                        "plugin": "memory_scan",
                        "type": "yara_match",
                        "rule_name": match.rule,
                        "namespace": match.namespace,
                        "tags": list(match.tags),
                        "meta": dict(match.meta),
                        "strings": [
                            {
                                "identifier": s.identifier,
                                "instances": [
                                    {
                                        "offset": i.offset,
                                        "matched_data": i.matched_data.hex()[:100] if i.matched_data else None
                                    }
                                    for i in s.instances
                                ]
                            }
                            for s in match.strings
                        ],
                        "severity": self._classify_yara_match(match),
                    }
                    findings.append(finding)
            
            execution_time = time.time() - start_time
            
            return EngineResult(
                engine_name="yara",
                plugin_name="memory_scan",
                status="success",
                findings=findings,
                execution_time=execution_time
            )
            
        except Exception as e:
            logger.error(f"YARA scan failed: {e}")
            return EngineResult(
                engine_name="yara",
                plugin_name="memory_scan",
                status="error",
                findings=findings,
                execution_time=time.time() - start_time,
                error_message=str(e)
            )
    
    def _classify_yara_match(self, match) -> str:
        """Classify YARA match severity."""
        severity = "medium"
        
        # Check tags for severity indicators
        tags_lower = [t.lower() for t in match.tags]
        if any(t in tags_lower for t in ["malware", "trojan", "ransomware", "apt"]):
            severity = "critical"
        elif any(t in tags_lower for t in ["suspicious", "hacktool", "exploit"]):
            severity = "high"
        elif any(t in tags_lower for t in ["info", "benign"]):
            severity = "low"
        
        # Check metadata
        meta = {k.lower(): v for k, v in match.meta.items()}
        if "severity" in meta:
            severity = meta["severity"]
        elif "score" in meta:
            score = meta["score"]
            if isinstance(score, int):
                if score >= 75:
                    severity = "critical"
                elif score >= 50:
                    severity = "high"
                elif score >= 25:
                    severity = "medium"
                else:
                    severity = "low"
        
        return severity


class MemProcFSEngine:
    """MemProcFS integration engine."""
    
    def analyze(self, memory_path: str) -> EngineResult:
        """Analyze memory with MemProcFS."""
        start_time = time.time()
        
        # MemProcFS is typically used via its Python API or as a FUSE mount
        # This is a placeholder for the integration
        
        findings = []
        
        try:
            # Try to use memprocfs Python bindings if available
            import memprocfs
            
            vmm = memprocfs.Vmm(["-device", memory_path])
            
            # List processes
            for process in vmm.process_list():
                proc_info = vmm.process_info(process)
                finding = {
                    "engine": "memprocfs",
                    "plugin": "process_list",
                    "type": "process",
                    "process_id": process,
                    "process_name": proc_info.get("name"),
                    "parent_pid": proc_info.get("ppid"),
                    "dtb": proc_info.get("dtb"),
                    "state": proc_info.get("state"),
                }
                findings.append(finding)
            
            vmm.close()
            
        except ImportError:
            logger.warning("MemProcFS Python bindings not available")
        except Exception as e:
            logger.error(f"MemProcFS analysis failed: {e}")
        
        return EngineResult(
            engine_name="memprocfs",
            plugin_name="memory_analysis",
            status="success" if findings else "error",
            findings=findings,
            execution_time=time.time() - start_time,
            error_message=None if findings else "MemProcFS not available"
        )


class AnalysisOrchestrator:
    """Orchestrates all analysis engines."""
    
    def __init__(self):
        self.volatility = VolatilityEngine()
        self.yara = YARAAnalyzer()
        self.memprocfs = MemProcFSEngine()
        logger.info("Analysis Orchestrator initialized")
    
    def run_full_analysis(
        self,
        memory_path: str,
        snapshot_id: str,
        run_volatility: bool = True,
        run_yara: bool = True,
        run_memprocfs: bool = False
    ) -> AnalysisSession:
        """Run all enabled analysis engines."""
        from datetime import datetime, timezone
        
        session = AnalysisSession(
            session_id=f"SESSION_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            snapshot_id=snapshot_id,
            memory_path=memory_path,
            start_time=datetime.now(timezone.utc).isoformat()
        )
        
        logger.info(f"Starting full analysis session {session.session_id}")
        
        # Run Volatility 3
        if run_volatility:
            logger.info("Running Volatility 3 analysis...")
            vol_results = self.volatility.analyze(memory_path)
            session.engine_results.extend(vol_results)
        
        # Run YARA
        if run_yara:
            logger.info("Running YARA analysis...")
            yara_result = self.yara.scan_memory(memory_path)
            session.engine_results.append(yara_result)
        
        # Run MemProcFS
        if run_memprocfs:
            logger.info("Running MemProcFS analysis...")
            mpf_result = self.memprocfs.analyze(memory_path)
            session.engine_results.append(mpf_result)
        
        # Aggregate findings
        session.aggregated_findings = self._aggregate_findings(session.engine_results)
        session.end_time = datetime.now(timezone.utc).isoformat()
        session.status = "completed"
        
        logger.info(
            f"Analysis complete. "
            f"Engines: {len(session.engine_results)}, "
            f"Total findings: {len(session.aggregated_findings)}"
        )
        
        return session
    
    def _aggregate_findings(self, engine_results: List[EngineResult]) -> List[Dict]:
        """Aggregate and deduplicate findings from all engines."""
        all_findings = []
        
        for result in engine_results:
            for finding in result.findings:
                finding["source_engine"] = result.engine_name
                finding["source_plugin"] = result.plugin_name
                all_findings.append(finding)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "medium"), 2))
        
        return all_findings
    
    def get_process_list(self, session: AnalysisSession) -> List[Dict]:
        """Extract process list from analysis results."""
        processes = []
        
        for finding in session.aggregated_findings:
            if finding.get("type") == "process" and finding.get("process_id"):
                proc = {
                    "pid": finding.get("process_id"),
                    "name": finding.get("process_name", "Unknown"),
                    "ppid": finding.get("parent_pid"),
                    "threads": finding.get("threads"),
                    "create_time": finding.get("create_time"),
                    "engine": finding.get("source_engine"),
                }
                # Avoid duplicates
                if not any(p["pid"] == proc["pid"] and p["name"] == proc["name"] for p in processes):
                    processes.append(proc)
        
        return sorted(processes, key=lambda x: x["pid"] or 0)
    
    def get_network_connections(self, session: AnalysisSession) -> List[Dict]:
        """Extract network connections from analysis results."""
        connections = []
        
        for finding in session.aggregated_findings:
            if finding.get("type") == "network":
                conn = {
                    "protocol": finding.get("protocol"),
                    "local_addr": finding.get("local_address"),
                    "local_port": finding.get("local_port"),
                    "remote_addr": finding.get("remote_address"),
                    "remote_port": finding.get("remote_port"),
                    "state": finding.get("state"),
                    "pid": finding.get("process_id"),
                    "process": finding.get("process_name"),
                }
                connections.append(conn)
        
        return connections
    
    def get_malfind_injections(self, session: AnalysisSession) -> List[Dict]:
        """Extract memory injection findings."""
        injections = []
        
        for finding in session.aggregated_findings:
            if finding.get("type") == "injection" or finding.get("is_injected"):
                injections.append({
                    "pid": finding.get("process_id"),
                    "process": finding.get("process_name"),
                    "address": finding.get("memory_address"),
                    "protection": finding.get("protection"),
                    "vad_tag": finding.get("vad_tag"),
                    "suspicious": finding.get("suspicious", True),
                })
        
        return injections