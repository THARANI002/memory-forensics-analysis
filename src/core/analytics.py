"""
Enterprise Memory Forensics Platform - Historical Analytics
============================================================
Trends, statistics, and historical analysis of investigations.
"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter


@dataclass
class TrendPoint:
    """Single point in a trend line."""
    timestamp: str
    value: float
    category: str
    metadata: Dict = field(default_factory=dict)


@dataclass
class InvestigationStats:
    """Statistics for an investigation."""
    investigation_id: str
    case_number: str
    date: str
    threat_score: float
    confidence_score: float
    total_threats: int
    critical_count: int
    high_count: int
    ioc_count: int
    techniques_detected: int
    duration_minutes: float
    status: str


class HistoricalAnalytics:
    """
    Historical Analytics Engine.
    
    Tracks and analyzes:
    - Threat trends over time
    - IOC trends
    - Detection trends by technique
    - Engine agreement rates
    - Investigation statistics
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        if storage_dir is None:
            from config.settings import ANALYTICS_DIR
            storage_dir = str(ANALYTICS_DIR)
        self.storage_dir = storage_dir
        self.investigations: List[InvestigationStats] = []
        self.trends: Dict[str, List[TrendPoint]] = defaultdict(list)
    
    def record_investigation(self, stats: InvestigationStats) -> None:
        """Record a completed investigation for historical analysis."""
        self.investigations.append(stats)
        
        # Add to trends
        self.trends["threat_score"].append(TrendPoint(
            timestamp=stats.date,
            value=stats.threat_score,
            category="threat"
        ))
        
        self.trends["threat_count"].append(TrendPoint(
            timestamp=stats.date,
            value=stats.total_threats,
            category="threat_count"
        ))
        
        self.trends["ioc_count"].append(TrendPoint(
            timestamp=stats.date,
            value=stats.ioc_count,
            category="iocs"
        ))
    
    def get_threat_trends(self, days: int = 30) -> Dict:
        """
        Get threat score trends over time.
        
        Args:
            days: Number of days to look back
        
        Returns:
            Dict with trend data for plotting
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        points = [
            {"timestamp": p.timestamp, "value": p.value}
            for p in self.trends["threat_score"]
            if p.timestamp >= cutoff
        ]
        
        if not points:
            return {"trend": "insufficient_data", "points": [], "average": 0}
        
        values = [p["value"] for p in points]
        avg = sum(values) / len(values)
        
        # Determine trend direction
        if len(points) >= 2:
            first_half = values[:len(values)//2]
            second_half = values[len(values)//2:]
            first_avg = sum(first_half) / len(first_half) if first_half else 0
            second_avg = sum(second_half) / len(second_half) if second_half else 0
            
            if second_avg > first_avg * 1.2:
                trend = "increasing"
            elif second_avg < first_avg * 0.8:
                trend = "decreasing"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"
        
        return {
            "trend": trend,
            "points": points,
            "average": round(avg, 2),
            "min": min(values),
            "max": max(values),
            "current": values[-1] if values else 0,
        }
    
    def get_ioc_trends(self, days: int = 30) -> Dict:
        """Get IOC discovery trends."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        points = [
            {"timestamp": p.timestamp, "count": p.value}
            for p in self.trends["ioc_count"]
            if p.timestamp >= cutoff
        ]
        
        if not points:
            return {"trend": "insufficient_data", "points": []}
        
        counts = [p["count"] for p in points]
        
        return {
            "trend": "stable",
            "points": points,
            "total_iocs": sum(counts),
            "average_per_investigation": round(sum(counts) / len(counts), 1),
            "max_single": max(counts),
        }
    
    def get_detection_trends(self, days: int = 30) -> Dict:
        """
        Get detection trends by technique category.
        
        Returns counts of detections by category over time.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        recent = [i for i in self.investigations if i.date >= cutoff]
        
        if not recent:
            return {"trend": "insufficient_data", "by_severity": {}}
        
        # Count by severity
        severity_counts = Counter()
        for inv in recent:
            severity_counts["critical"] += inv.critical_count
            severity_counts["high"] += inv.high_count
        
        return {
            "total_investigations": len(recent),
            "by_severity": dict(severity_counts),
            "average_threats_per_inv": round(
                sum(i.total_threats for i in recent) / len(recent), 1
            ),
            "average_duration_minutes": round(
                sum(i.duration_minutes for i in recent) / len(recent), 1
            ),
        }
    
    def get_engine_agreement_rate(self) -> Dict:
        """
        Calculate engine agreement statistics.
        
        Shows how often different detection engines agree on findings.
        """
        # This would be populated from actual engine correlation data
        # Placeholder for the structure
        
        return {
            "overall_agreement_rate": 0.0,
            "engine_pairs": {},
            "most_reliable_engine": "volatility3",
            "least_reliable_engine": "memprocfs",
            "notes": "Engine agreement tracking requires completed investigations with multi-engine analysis"
        }
    
    def get_summary_statistics(self) -> Dict:
        """Get overall summary statistics."""
        if not self.investigations:
            return {
                "total_investigations": 0,
                "message": "No investigations recorded yet"
            }
        
        total = len(self.investigations)
        
        return {
            "total_investigations": total,
            "status_breakdown": dict(Counter(i.status for i in self.investigations)),
            "average_threat_score": round(
                sum(i.threat_score for i in self.investigations) / total, 2
            ),
            "average_confidence": round(
                sum(i.confidence_score for i in self.investigations) / total, 2
            ),
            "total_threats_detected": sum(i.total_threats for i in self.investigations),
            "total_iocs_extracted": sum(i.ioc_count for i in self.investigations),
            "critical_findings": sum(i.critical_count for i in self.investigations),
            "high_findings": sum(i.high_count for i in self.investigations),
            "date_range": {
                "first": min(i.date for i in self.investigations),
                "last": max(i.date for i in self.investigations),
            },
        }
    
    def generate_dashboard_data(self) -> Dict:
        """Generate data for the analytics dashboard."""
        return {
            "summary": self.get_summary_statistics(),
            "threat_trends": self.get_threat_trends(),
            "ioc_trends": self.get_ioc_trends(),
            "detection_trends": self.get_detection_trends(),
            "engine_agreement": self.get_engine_agreement_rate(),
        }
    
    def save_state(self, filepath: str) -> None:
        """Save analytics state to file."""
        data = {
            "investigations": [asdict(i) for i in self.investigations],
            "trends": {
                category: [asdict(p) for p in points]
                for category, points in self.trends.items()
            },
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_state(self, filepath: str) -> None:
        """Load analytics state from file."""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.investigations = [
                InvestigationStats(**i) for i in data.get("investigations", [])
            ]
            
            for category, points in data.get("trends", {}).items():
                self.trends[category] = [
                    TrendPoint(**p) for p in points
                ]
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Error loading analytics state: {e}")