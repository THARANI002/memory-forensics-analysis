"""
Enterprise Memory Forensics Platform - VirusTotal-Style Aggregation Engine
==========================================================================
Multi-engine correlation with weighted scoring for threat confidence.
"""

import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict


@dataclass
class EngineVote:
    """A single engine's vote on a finding."""
    engine_name: str
    detection_type: str  # signature, heuristic, anomaly
    detected: bool
    confidence: float
    details: Dict = field(default_factory=dict)


@dataclass
class AggregatedFinding:
    """A finding aggregated across multiple engines."""
    finding_id: str
    finding_type: str
    target: str
    description: str
    engine_votes: List[EngineVote] = field(default_factory=list)
    weighted_score: float = 0.0
    confidence_score: float = 0.0
    final_verdict: str = "unknown"
    severity: str = "medium"
    iocs: List[Dict] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    @property
    def engine_confirmations(self) -> int:
        """Count engines that detected this."""
        return sum(1 for v in self.engine_votes if v.detected)
    
    @property
    def total_engines(self) -> int:
        """Total number of engines that analyzed."""
        return len(self.engine_votes)
    
    @property
    def confirmation_ratio(self) -> float:
        """Ratio of confirming engines."""
        if self.total_engines == 0:
            return 0.0
        return self.engine_confirmations / self.total_engines


class VirusTotalStyleAggregator:
    """
    VirusTotal-style multi-engine aggregation engine.
    
    Rules:
    - Minimum 2 engine confirmations for positive detection
    - Signature Weight = 1.0
    - Heuristic Weight = 0.7
    - Anomaly Weight = 0.5
    
    Confidence Levels:
    - Confirmed Malicious >= 90
    - Highly Suspicious >= 70
    - Suspicious >= 50
    - Possibly Suspicious >= 30
    - Likely Benign < 30
    """
    
    # Detection type weights
    DETECTION_WEIGHTS = {
        "signature": 1.0,
        "heuristic": 0.7,
        "anomaly": 0.5,
        "behavioral": 0.6,
        "reputation": 0.8,
    }
    
    # Confidence level thresholds
    CONFIDENCE_LEVELS = {
        "confirmed_malicious": 90.0,
        "highly_suspicious": 70.0,
        "suspicious": 50.0,
        "possibly_suspicious": 30.0,
        "likely_benign": 0.0,
    }
    
    # Minimum engine confirmations required
    MIN_CONFIRMATIONS = 2
    
    def __init__(self):
        self.findings: Dict[str, AggregatedFinding] = {}
        self.engine_results: Dict[str, List[Dict]] = {}
    
    def add_engine_result(self, engine_name: str, results: List[Dict]) -> None:
        """Add results from an analysis engine."""
        self.engine_results[engine_name] = results
    
    def correlate_findings(self) -> List[AggregatedFinding]:
        """
        Correlate findings across all engines.
        
        Groups findings by target (PID, IP, hash, etc.) and
        calculates weighted confidence scores.
        """
        # Group raw findings by target
        findings_by_target: Dict[str, List[Tuple[str, Dict]]] = defaultdict(list)
        
        for engine_name, results in self.engine_results.items():
            for finding in results:
                target = self._extract_target(finding)
                findings_by_target[target].append((engine_name, finding))
        
        # Aggregate findings
        aggregated = []
        for finding_id, (target, engine_findings) in enumerate(findings_by_target.items()):
            agg = self._aggregate_single_finding(finding_id, target, engine_findings)
            if agg:
                aggregated.append(agg)
        
        # Sort by confidence score descending
        aggregated.sort(key=lambda x: x.confidence_score, reverse=True)
        
        self.findings = {a.finding_id: a for a in aggregated}
        return aggregated
    
    def _extract_target(self, finding: Dict) -> str:
        """Extract the target identifier from a finding."""
        # Try various identifiers
        if "pid" in finding and "process_name" in finding:
            return f"proc:{finding['pid']}:{finding.get('process_name', 'unknown')}"
        elif "remote_addr" in finding:
            return f"net:{finding['remote_addr']}:{finding.get('remote_port', 0)}"
        elif "dll_name" in finding:
            return f"dll:{finding.get('pid', 0)}:{finding['dll_name']}"
        elif "service_name" in finding:
            return f"svc:{finding['service_name']}"
        elif "driver_name" in finding:
            return f"drv:{finding['driver_name']}"
        elif "memory_address" in finding:
            return f"mem:{finding.get('pid', 0)}:{finding['memory_address']}"
        elif "rule_name" in finding:
            return f"yara:{finding['rule_name']}"
        else:
            # Generic hash-based target
            return f"other:{hash(str(finding))}"
    
    def _aggregate_single_finding(
        self,
        finding_id: int,
        target: str,
        engine_findings: List[Tuple[str, Dict]]
    ) -> Optional[AggregatedFinding]:
        """Aggregate findings for a single target."""
        # Determine finding type and description
        finding_types = [f[1].get("type", "unknown") for f in engine_findings]
        finding_type = max(set(finding_types), key=finding_types.count)
        
        # Collect engine votes
        engine_votes = []
        for engine_name, finding in engine_findings:
            det_type = self._classify_detection_type(finding)
            vote = EngineVote(
                engine_name=engine_name,
                detection_type=det_type,
                detected=True,
                confidence=finding.get("confidence", 50.0),
                details=finding
            )
            engine_votes.append(vote)
        
        # Calculate weighted score
        weighted_score = self._calculate_weighted_score(engine_votes)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(engine_votes, weighted_score)
        
        # Determine final verdict
        final_verdict = self._determine_verdict(confidence_score, len(engine_votes))
        
        # Determine severity
        severity = self._calculate_severity(confidence_score, finding)
        
        # Extract IOCs
        iocs = self._extract_iocs(engine_findings)
        
        # Extract MITRE techniques
        mitre_techniques = self._extract_mitre_techniques(engine_findings)
        
        return AggregatedFinding(
            finding_id=f"F{finding_id:05d}",
            finding_type=finding_type,
            target=target,
            description=self._generate_description(target, engine_findings),
            engine_votes=engine_votes,
            weighted_score=weighted_score,
            confidence_score=confidence_score,
            final_verdict=final_verdict,
            severity=severity,
            iocs=iocs,
            mitre_techniques=mitre_techniques
        )
    
    def _classify_detection_type(self, finding: Dict) -> str:
        """Classify the detection type of a finding."""
        engine = finding.get("engine", "").lower()
        
        if engine == "yara":
            return "signature"
        elif engine == "volatility3":
            # Volatility plugins can be signature or heuristic
            plugin = finding.get("plugin", "")
            if "malfind" in plugin or "pslist" in plugin:
                return "heuristic"
            return "signature"
        elif engine == "heuristic":
            return "heuristic"
        elif engine == "anomaly":
            return "anomaly"
        elif engine == "behavioral":
            return "behavioral"
        else:
            return "heuristic"
    
    def _calculate_weighted_score(self, votes: List[EngineVote]) -> float:
        """Calculate weighted score from engine votes."""
        total_weight = 0.0
        weighted_sum = 0.0
        
        for vote in votes:
            if vote.detected:
                weight = self.DETECTION_WEIGHTS.get(vote.detection_type, 0.5)
                weighted_sum += vote.confidence * weight
                total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        return weighted_sum / total_weight
    
    def _calculate_confidence_score(self, votes: List[EngineVote], weighted_score: float) -> float:
        """
        Calculate final confidence score.
        
        Factors:
        - Weighted score from detection types
        - Number of confirming engines
        - Engine diversity bonus
        """
        confirming = sum(1 for v in votes if v.detected)
        total = len(votes)
        
        if total == 0:
            return 0.0
        
        # Base score from weighted detections
        base_score = weighted_score
        
        # Engine confirmation bonus
        confirmation_ratio = confirming / total
        confirmation_bonus = confirmation_ratio * 20  # Up to 20 points
        
        # Engine diversity bonus
        unique_engines = len(set(v.engine_name for v in votes if v.detected))
        diversity_bonus = min(unique_engines * 5, 15)  # Up to 15 points
        
        # Detection type diversity bonus
        det_types = set(v.detection_type for v in votes if v.detected)
        type_bonus = len(det_types) * 5  # Up to 20 points for 4 types
        
        final_score = base_score + confirmation_bonus + diversity_bonus + type_bonus
        
        # Cap at 100
        return min(final_score, 100.0)
    
    def _determine_verdict(self, confidence_score: float, total_engines: int) -> str:
        """Determine final verdict based on confidence score."""
        if total_engines < self.MIN_CONFIRMATIONS:
            if confidence_score >= 70:
                return "suspicious_unconfirmed"
            return "likely_benign"
        
        if confidence_score >= self.CONFIDENCE_LEVELS["confirmed_malicious"]:
            return "confirmed_malicious"
        elif confidence_score >= self.CONFIDENCE_LEVELS["highly_suspicious"]:
            return "highly_suspicious"
        elif confidence_score >= self.CONFIDENCE_LEVELS["suspicious"]:
            return "suspicious"
        elif confidence_score >= self.CONFIDENCE_LEVELS["possibly_suspicious"]:
            return "possibly_suspicious"
        else:
            return "likely_benign"
    
    def _calculate_severity(self, confidence_score: float, finding: Dict) -> str:
        """Calculate severity based on confidence and finding type."""
        base_severity = finding.get("severity", "medium")
        
        if confidence_score >= 90:
            return "critical"
        elif confidence_score >= 70:
            return "high"
        elif confidence_score >= 50:
            return "medium"
        else:
            return "low"
    
    def _extract_iocs(self, engine_findings: List[Tuple[str, Dict]]) -> List[Dict]:
        """Extract IOCs from engine findings."""
        iocs = []
        seen = set()
        
        for engine_name, finding in engine_findings:
            # Extract various IOC types
            if "remote_addr" in finding:
                val = finding["remote_addr"]
                if val not in seen:
                    iocs.append({"type": "ip", "value": val})
                    seen.add(val)
            
            if "dll_name" in finding:
                val = finding["dll_name"]
                if val not in seen:
                    iocs.append({"type": "dll", "value": val})
                    seen.add(val)
            
            if "process_name" in finding:
                val = finding["process_name"]
                if val not in seen:
                    iocs.append({"type": "process", "value": val})
                    seen.add(val)
            
            if "service_name" in finding:
                val = finding["service_name"]
                if val not in seen:
                    iocs.append({"type": "service", "value": val})
                    seen.add(val)
        
        return iocs
    
    def _extract_mitre_techniques(self, engine_findings: List[Tuple[str, Dict]]) -> List[str]:
        """Extract MITRE technique references."""
        techniques = set()
        
        for engine_name, finding in engine_findings:
            tech = finding.get("mitre_technique")
            if tech:
                techniques.add(tech)
        
        return list(techniques)
    
    def _generate_description(self, target: str, engine_findings: List[Tuple[str, Dict]]) -> str:
        """Generate human-readable description."""
        engines = [e[0] for e in engine_findings]
        types = [e[1].get("type", "unknown") for e in engine_findings]
        
        return f"{target}: Detected by {', '.join(set(engines))} as {', '.join(set(types))}"
    
    def get_confidence_distribution(self) -> Dict[str, int]:
        """Get distribution of confidence levels."""
        distribution = {
            "confirmed_malicious": 0,
            "highly_suspicious": 0,
            "suspicious": 0,
            "possibly_suspicious": 0,
            "likely_benign": 0,
        }
        
        for finding in self.findings.values():
            verdict = finding.final_verdict
            if verdict in distribution:
                distribution[verdict] += 1
        
        return distribution
    
    def get_engine_agreement_stats(self) -> Dict:
        """Get statistics on engine agreement rates."""
        total_findings = len(self.findings)
        if total_findings == 0:
            return {}
        
        agreement_stats = {
            "total_findings": total_findings,
            "full_agreement": 0,  # All engines agree
            "majority_agreement": 0,  # >50% agree
            "split": 0,  # No majority
            "unconfirmed": 0,  # Single engine detection
        }
        
        for finding in self.findings.values():
            ratio = finding.confirmation_ratio
            if ratio == 1.0:
                agreement_stats["full_agreement"] += 1
            elif ratio > 0.5:
                agreement_stats["majority_agreement"] += 1
            elif ratio == 0:
                agreement_stats["unconfirmed"] += 1
            else:
                agreement_stats["split"] += 1
        
        return agreement_stats
    
    def generate_aggregation_report(self) -> Dict:
        """Generate comprehensive aggregation report."""
        if not self.findings:
            return {"status": "no_findings", "message": "No findings to aggregate"}
        
        findings_list = list(self.findings.values())
        
        return {
            "status": "success",
            "total_findings": len(findings_list),
            "confidence_distribution": self.get_confidence_distribution(),
            "engine_agreement": self.get_engine_agreement_stats(),
            "top_findings": [
                {
                    "id": f.finding_id,
                    "type": f.finding_type,
                    "target": f.target,
                    "confidence": f.confidence_score,
                    "verdict": f.final_verdict,
                    "severity": f.severity,
                    "engines": f.engine_confirmations,
                    "description": f.description,
                }
                for f in findings_list[:10]
            ],
            "severity_summary": {
                "critical": sum(1 for f in findings_list if f.severity == "critical"),
                "high": sum(1 for f in findings_list if f.severity == "high"),
                "medium": sum(1 for f in findings_list if f.severity == "medium"),
                "low": sum(1 for f in findings_list if f.severity == "low"),
            },
            "all_iocs": self._get_all_iocs(),
        }
    
    def _get_all_iocs(self) -> List[Dict]:
        """Get all unique IOCs from aggregated findings."""
        all_iocs = []
        seen = set()
        
        for finding in self.findings.values():
            for ioc in finding.iocs:
                key = f"{ioc['type']}:{ioc['value']}"
                if key not in seen:
                    all_iocs.append(ioc)
                    seen.add(key)
        
        return all_iocs