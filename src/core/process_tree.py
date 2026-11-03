"""
Enterprise Memory Forensics Platform - Process Tree Explorer
=============================================================
Builds interactive process trees with threat highlighting.
"""

import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict


@dataclass
class ProcessNode:
    """Node in the process tree."""
    pid: int
    name: str
    ppid: int
    parent_name: str = ""
    create_time: str = ""
    exit_time: str = ""
    threads: int = 0
    handles: int = 0
    session: int = 0
    wow64: bool = False
    cmdline: str = ""
    exe_path: str = ""
    is_suspicious: bool = False
    is_hidden: bool = False
    is_injected: bool = False
    threat_score: float = 0.0
    detection_reasons: List[str] = field(default_factory=list)
    children: List['ProcessNode'] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        result["children"] = [c.to_dict() for c in self.children]
        return result


class ProcessTreeBuilder:
    """
    Process Tree Explorer.
    
    Builds dynamic process trees from memory analysis with:
    - Suspicious parent chain highlighting
    - Injection target identification
    - Hidden process detection
    """
    
    # System processes that should have specific parents
    SYSTEM_PROCESSES = {
        "System": {"ppid": 0, "valid_parents": [0]},
        "Registry": {"ppid": 0, "valid_parents": [0]},
        "smss.exe": {"ppid": 0, "valid_parents": [0, 4]},
        "csrss.exe": {"ppid": 0, "valid_parents": [0]},
        "wininit.exe": {"ppid": 0, "valid_parents": [0]},
        "services.exe": {"ppid": 0, "valid_parents": [0]},
        "lsass.exe": {"ppid": 0, "valid_parents": [0]},
        "svchost.exe": {"ppid": 0, "valid_parents": [0]},
        "winlogon.exe": {"ppid": 0, "valid_parents": [0]},
        "explorer.exe": {"ppid": 0, "valid_parents": [0]},
    }
    
    # Known suspicious process relationships
    SUSPICIOUS_PARENTS = {
        "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
        "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
        "outlook.exe": ["cmd.exe", "powershell.exe"],
        "iexplore.exe": ["cmd.exe", "powershell.exe"],
        "chrome.exe": ["cmd.exe", "powershell.exe"],
        "firefox.exe": ["cmd.exe", "powershell.exe"],
    }
    
    # High-value injection targets
    INJECTION_TARGETS = [
        "lsass.exe", "svchost.exe", "explorer.exe", "services.exe",
        "winlogon.exe", "csrss.exe", "smss.exe", "csrss.exe",
    ]
    
    def __init__(self):
        self.processes: Dict[int, ProcessNode] = {}
        self.root_nodes: List[ProcessNode] = []
    
    def build_tree(self, process_list: List[Dict]) -> List[ProcessNode]:
        """
        Build process tree from flat process list.
        
        Args:
            process_list: List of process dicts with pid, ppid, name, etc.
        
        Returns:
            List of root ProcessNode objects
        """
        self.processes = {}
        self.root_nodes = []
        
        # First pass: create all nodes
        for proc in process_list:
            pid = proc.get("pid")
            if pid is None:
                continue
            
            node = ProcessNode(
                pid=pid,
                name=proc.get("name", "Unknown"),
                ppid=proc.get("ppid", 0),
                parent_name=proc.get("parent_name", ""),
                create_time=proc.get("create_time", ""),
                exit_time=proc.get("exit_time", ""),
                threads=proc.get("threads", 0),
                handles=proc.get("handles", 0),
                session=proc.get("session_id", 0),
                wow64=proc.get("wow64", False),
                cmdline=proc.get("command_line", ""),
                exe_path=proc.get("exe_path") or proc.get("path", ""),
            )
            self.processes[pid] = node
        
        # Second pass: build tree relationships
        for node in self.processes.values():
            if node.ppid in self.processes:
                parent = self.processes[node.ppid]
                parent.children.append(node)
                node.parent_name = parent.name
            else:
                # Root-level process
                self.root_nodes.append(node)
        
        # Third pass: analyze threats
        self._analyze_suspicious_parents()
        self._analyze_injection_targets()
        self._analyze_hidden_processes()
        self._calculate_threat_scores()
        
        return self.root_nodes
    
    def _analyze_suspicious_parents(self) -> None:
        """Identify suspicious parent-child relationships."""
        for node in self.processes.values():
            name_lower = node.name.lower()
            parent = self.processes.get(node.ppid)
            
            if not parent:
                continue
            
            parent_name_lower = parent.name.lower()
            
            # Check known suspicious relationships
            for app, suspicious_children in self.SUSPICIOUS_PARENTS.items():
                if parent_name_lower == app and name_lower in [s.lower() for s in suspicious_children]:
                    node.is_suspicious = True
                    node.detection_reasons.append(
                        f"Suspicious: {parent.name} spawned {node.name}"
                    )
                    parent.is_suspicious = True
                    parent.detection_reasons.append(
                        f"Launched suspicious child: {node.name}"
                    )
            
            # Check system process parent validation
            if name_lower in self.SYSTEM_PROCESSES:
                valid_ppids = self.SYSTEM_PROCESSES[name_lower].get("valid_parents", [])
                if node.ppid not in valid_ppids and node.ppid != 0:
                    node.is_suspicious = True
                    node.detection_reasons.append(
                        f"Invalid parent for {node.name}: {parent.name} (PID: {node.ppid})"
                    )
    
    def _analyze_injection_targets(self) -> None:
        """Identify processes that are injection targets."""
        for node in self.processes.values():
            if node.name.lower() in [t.lower() for t in self.INJECTION_TARGETS]:
                # These processes being modified is suspicious
                if node.children:
                    for child in node.children:
                        if child.name.lower() not in [t.lower() for t in self.INJECTION_TARGETS]:
                            child.is_suspicious = True
                            child.detection_reasons.append(
                                f"Child of high-value target: {node.name}"
                            )
    
    def _analyze_hidden_processes(self) -> None:
        """Identify potentially hidden processes."""
        for node in self.processes.values():
            indicators = []
            
            # Zero threads (except system processes)
            if node.threads == 0 and node.name.lower() not in ["system", "registry"]:
                indicators.append("Zero threads")
            
            # Name typo-squatting
            common_names = ["svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "smss.exe", "wininit.exe"]
            for common in common_names:
                if self._levenshtein_distance(node.name.lower(), common) == 1:
                    indicators.append(f"Name similar to {common}")
            
            # No children for processes that normally have children
            if node.name.lower() in ["services.exe", "wininit.exe"] and not node.children:
                indicators.append("Missing expected child processes")
            
            if indicators:
                node.is_hidden = True
                node.is_suspicious = True
                node.detection_reasons.extend(indicators)
    
    def _calculate_threat_scores(self) -> None:
        """Calculate threat score for each process."""
        for node in self.processes.values():
            score = 0.0
            
            if node.is_suspicious:
                score += 30.0
            
            if node.is_hidden:
                score += 25.0
            
            if node.is_injected:
                score += 35.0
            
            # Boost score for each detection reason
            score += len(node.detection_reasons) * 5.0
            
            # Cap at 100
            node.threat_score = min(score, 100.0)
            
            # Propagate suspicion to children
            if node.is_suspicious and node.children:
                for child in node.children:
                    if not child.is_suspicious:
                        child.threat_score = max(child.threat_score, 15.0)
    
    def get_suspicious_chains(self) -> List[List[ProcessNode]]:
        """Get suspicious parent-child chains."""
        chains = []
        
        for node in self.processes.values():
            if node.is_suspicious:
                # Build chain from this node to root
                chain = []
                current = node
                visited = set()
                
                while current and current.pid not in visited:
                    chain.append(current)
                    visited.add(current.pid)
                    current = self.processes.get(current.ppid)
                
                if len(chain) > 1:
                    chains.append(list(reversed(chain)))
        
        return chains
    
    def get_injection_targets(self) -> List[ProcessNode]:
        """Get identified injection targets."""
        return [
            node for node in self.processes.values()
            if node.name.lower() in [t.lower() for t in self.INJECTION_TARGETS]
            and node.is_suspicious
        ]
    
    def get_hidden_processes(self) -> List[ProcessNode]:
        """Get identified hidden processes."""
        return [node for node in self.processes.values() if node.is_hidden]
    
    def get_high_risk_processes(self, threshold: float = 50.0) -> List[ProcessNode]:
        """Get processes with threat score above threshold."""
        return [
            node for node in self.processes.values()
            if node.threat_score >= threshold
        ]
    
    def generate_plotly_data(self) -> List[Dict]:
        """Generate Plotly figure data for process tree visualization."""
        nodes = []
        edges = []
        
        def traverse(node: ProcessNode, parent_id: str = None, depth: int = 0):
            node_id = f"{node.pid}_{node.name}"
            
            # Color based on threat
            if node.threat_score >= 70:
                color = "#FF0000"
                border = "#8B0000"
            elif node.threat_score >= 40:
                color = "#FF8800"
                border = "#CC6600"
            elif node.is_suspicious:
                color = "#FFCC00"
                border = "#CC9900"
            else:
                color = "#00CC66"
                border = "#009944"
            
            nodes.append({
                "id": node_id,
                "label": f"{node.name}\nPID: {node.pid}",
                "pid": node.pid,
                "name": node.name,
                "ppid": node.ppid,
                "color": color,
                "border": border,
                "threat_score": node.threat_score,
                "is_suspicious": node.is_suspicious,
                "is_hidden": node.is_hidden,
                "depth": depth,
                "size": 20 + min(node.threat_score / 2, 30),
                "title": f"PID: {node.pid}\nName: {node.name}\n" +
                        f"PPID: {node.ppid}\nParent: {node.parent_name}\n" +
                        f"Threat Score: {node.threat_score:.1f}\n" +
                        f"Threads: {node.threads}\n" +
                        f"Suspicious: {node.is_suspicious}\n" +
                        f"Hidden: {node.is_hidden}\n" +
                        (f"Reasons: {', '.join(node.detection_reasons)}" 
                         if node.detection_reasons else "")
            })
            
            if parent_id:
                edges.append({
                    "source": parent_id,
                    "target": node_id,
                    "is_suspicious": node.is_suspicious
                })
            
            for child in node.children:
                traverse(child, node_id, depth + 1)
        
        for root in self.root_nodes:
            traverse(root)
        
        return {"nodes": nodes, "edges": edges}
    
    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return ProcessTreeBuilder._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]