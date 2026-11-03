"""
Enterprise Memory Forensics Platform - Threat Intelligence
===========================================================
Integrates VirusTotal, MISP, and AlienVault OTX for IOC enrichment.
"""

import json
import time
import hashlib
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass
class EnrichmentResult:
    """Result of enriching a single IOC."""
    ioc_value: str
    ioc_type: str
    source: str  # virustotal, misp, otx
    enriched: bool
    detection_ratio: Optional[str] = None
    community_score: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    malware_families: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    raw_data: Dict = field(default_factory=dict)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


class ThreatIntelligenceEngine:
    """
    Threat Intelligence enrichment engine.
    
    Integrates:
    - VirusTotal API v3
    - MISP (Malware Information Sharing Platform)
    - AlienVault OTX (Open Threat Exchange)
    """
    
    def __init__(
        self,
        vt_api_key: Optional[str] = None,
        misp_url: Optional[str] = None,
        misp_api_key: Optional[str] = None,
        otx_api_key: Optional[str] = None,
        cache_dir: Optional[str] = None
    ):
        self.vt_api_key = vt_api_key
        self.misp_url = misp_url
        self.misp_api_key = misp_api_key
        self.otx_api_key = otx_api_key
        
        # Rate limiting
        self.vt_last_request = 0
        self.vt_rate_limit = 4  # requests per minute for free tier
        
        # Cache
        from config.settings import CACHE_DIR
        self.cache_dir = Path(cache_dir) if cache_dir else CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = 3600  # 1 hour
    
    def _cache_key(self, ioc_value: str, source: str) -> str:
        """Generate cache key for an IOC."""
        return hashlib.sha256(f"{source}:{ioc_value}".encode()).hexdigest()[:16]
    
    def _get_cache(self, ioc_value: str, source: str) -> Optional[Dict]:
        """Get cached enrichment result."""
        cache_file = self.cache_dir / f"{self._cache_key(ioc_value, source)}.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                # Check TTL
                cached_time = datetime.fromisoformat(data.get("cached_at", "2000-01-01"))
                if datetime.now(timezone.utc) - cached_time < timedelta(seconds=self.cache_ttl):
                    return data.get("result")
            except Exception:
                pass
        
        return None
    
    def _set_cache(self, ioc_value: str, source: str, result: Dict) -> None:
        """Cache enrichment result."""
        cache_file = self.cache_dir / f"{self._cache_key(ioc_value, source)}.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    "cached_at": datetime.now(timezone.utc).isoformat(),
                    "ioc": ioc_value,
                    "source": source,
                    "result": result
                }, f)
        except Exception as e:
            print(f"Cache write error: {e}")
    
    def _rate_limit_wait(self, source: str):
        """Wait for rate limit if needed."""
        if source == "virustotal":
            elapsed = time.time() - self.vt_last_request
            min_interval = 60.0 / self.vt_rate_limit
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self.vt_last_request = time.time()
    
    def enrich_ip_virustotal(self, ip: str) -> EnrichmentResult:
        """Enrich an IP address using VirusTotal."""
        if not self.vt_api_key:
            return EnrichmentResult(
                ioc_value=ip,
                ioc_type="ip",
                source="virustotal",
                enriched=False,
                error="No VirusTotal API key configured"
            )
        
        # Check cache
        cached = self._get_cache(ip, "virustotal")
        if cached:
            return EnrichmentResult(**cached)
        
        self._rate_limit_wait("virustotal")
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": self.vt_api_key}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                last_analysis = attributes.get("last_analysis_stats", {})
                malicious = last_analysis.get("malicious", 0)
                suspicious = last_analysis.get("suspicious", 0)
                harmless = last_analysis.get("harmless", 0)
                undetected = last_analysis.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected
                
                detection_ratio = f"{malicious}/{total}" if total > 0 else "0/0"
                
                # Calculate community score (0-100)
                if total > 0:
                    community_score = ((malicious + suspicious * 0.5) / total) * 100
                else:
                    community_score = 0.0
                
                result = EnrichmentResult(
                    ioc_value=ip,
                    ioc_type="ip",
                    source="virustotal",
                    enriched=True,
                    detection_ratio=detection_ratio,
                    community_score=round(community_score, 2),
                    tags=attributes.get("tags", []),
                    first_seen=attributes.get("first_seen_date", ""),
                    last_seen=attributes.get("last_modification_date", ""),
                    raw_data=data
                )
                
                self._set_cache(ip, "virustotal", result.to_dict())
                return result
            
            elif response.status_code == 404:
                return EnrichmentResult(
                    ioc_value=ip,
                    ioc_type="ip",
                    source="virustotal",
                    enriched=True,
                    detection_ratio="0/0",
                    community_score=0.0,
                    error="IP not found in VirusTotal"
                )
            else:
                return EnrichmentResult(
                    ioc_value=ip,
                    ioc_type="ip",
                    source="virustotal",
                    enriched=False,
                    error=f"HTTP {response.status_code}: {response.text[:200]}"
                )
        
        except requests.RequestException as e:
            return EnrichmentResult(
                ioc_value=ip,
                ioc_type="ip",
                source="virustotal",
                enriched=False,
                error=f"Request failed: {str(e)}"
            )
    
    def enrich_hash_virustotal(self, file_hash: str) -> EnrichmentResult:
        """Enrich a file hash using VirusTotal."""
        if not self.vt_api_key:
            return EnrichmentResult(
                ioc_value=file_hash,
                ioc_type="hash",
                source="virustotal",
                enriched=False,
                error="No VirusTotal API key configured"
            )
        
        cached = self._get_cache(file_hash, "virustotal")
        if cached:
            return EnrichmentResult(**cached)
        
        self._rate_limit_wait("virustotal")
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.vt_api_key}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                last_analysis = attributes.get("last_analysis_stats", {})
                malicious = last_analysis.get("malicious", 0)
                suspicious = last_analysis.get("suspicious", 0)
                harmless = last_analysis.get("harmless", 0)
                undetected = last_analysis.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected
                
                detection_ratio = f"{malicious}/{total}" if total > 0 else "0/0"
                
                if total > 0:
                    community_score = ((malicious + suspicious * 0.5) / total) * 100
                else:
                    community_score = 0.0
                
                # Extract malware family names
                malware_families = []
                sandbox_results = attributes.get("sandbox_verdicts", {})
                for engine, verdict in sandbox_results.items():
                    family = verdict.get("malware_family", "")
                    if family and family not in malware_families:
                        malware_families.append(family)
                
                result = EnrichmentResult(
                    ioc_value=file_hash,
                    ioc_type="hash",
                    source="virustotal",
                    enriched=True,
                    detection_ratio=detection_ratio,
                    community_score=round(community_score, 2),
                    tags=attributes.get("tags", []),
                    first_seen=attributes.get("first_submission_date", ""),
                    last_seen=attributes.get("last_modification_date", ""),
                    malware_families=malware_families,
                    raw_data=data
                )
                
                self._set_cache(file_hash, "virustotal", result.to_dict())
                return result
            
            else:
                return EnrichmentResult(
                    ioc_value=file_hash,
                    ioc_type="hash",
                    source="virustotal",
                    enriched=False,
                    error=f"HTTP {response.status_code}"
                )
        
        except requests.RequestException as e:
            return EnrichmentResult(
                ioc_value=file_hash,
                ioc_type="hash",
                source="virustotal",
                enriched=False,
                error=f"Request failed: {str(e)}"
            )
    
    def enrich_domain_virustotal(self, domain: str) -> EnrichmentResult:
        """Enrich a domain using VirusTotal."""
        if not self.vt_api_key:
            return EnrichmentResult(
                ioc_value=domain,
                ioc_type="domain",
                source="virustotal",
                enriched=False,
                error="No VirusTotal API key configured"
            )
        
        cached = self._get_cache(domain, "virustotal")
        if cached:
            return EnrichmentResult(**cached)
        
        self._rate_limit_wait("virustotal")
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": self.vt_api_key}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                last_analysis = attributes.get("last_analysis_stats", {})
                malicious = last_analysis.get("malicious", 0)
                suspicious = last_analysis.get("suspicious", 0)
                harmless = last_analysis.get("harmless", 0)
                undetected = last_analysis.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected
                
                detection_ratio = f"{malicious}/{total}" if total > 0 else "0/0"
                
                if total > 0:
                    community_score = ((malicious + suspicious * 0.5) / total) * 100
                else:
                    community_score = 0.0
                
                result = EnrichmentResult(
                    ioc_value=domain,
                    ioc_type="domain",
                    source="virustotal",
                    enriched=True,
                    detection_ratio=detection_ratio,
                    community_score=round(community_score, 2),
                    tags=attributes.get("tags", []),
                    first_seen=attributes.get("creation_date", ""),
                    last_seen=attributes.get("last_update_date", ""),
                    raw_data=data
                )
                
                self._set_cache(domain, "virustotal", result.to_dict())
                return result
            else:
                return EnrichmentResult(
                    ioc_value=domain,
                    ioc_type="domain",
                    source="virustotal",
                    enriched=False,
                    error=f"HTTP {response.status_code}"
                )
        
        except requests.RequestException as e:
            return EnrichmentResult(
                ioc_value=domain,
                ioc_type="domain",
                source="virustotal",
                enriched=False,
                error=f"Request failed: {str(e)}"
            )
    
    def enrich_ioc_misp(self, ioc_value: str, ioc_type: str) -> EnrichmentResult:
        """Enrich an IOC using MISP."""
        if not self.misp_url or not self.misp_api_key:
            return EnrichmentResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source="misp",
                enriched=False,
                error="MISP not configured"
            )
        
        try:
            url = f"{self.misp_url}/attributes/restSearch/json"
            headers = {
                "Authorization": self.misp_api_key,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            
            misp_type_map = {
                "ip": "ip-dst",
                "domain": "domain",
                "hash": "md5" if len(ioc_value) == 32 else "sha256",
                "url": "url",
            }
            
            body = {
                "returnFormat": "json",
                "type": misp_type_map.get(ioc_type, ioc_type),
                "value": ioc_value,
                "includeEventTags": True,
                "includeProposals": False
            }
            
            response = requests.post(url, headers=headers, json=body, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("response", {}).get("Attribute", [])
                
                if attributes:
                    attr = attributes[0]
                    tags = [t["name"] for t in attr.get("Tag", [])]
                    
                    # Get related events for context
                    events = data.get("response", {}).get("Event", [])
                    threat_levels = [e.get("threat_level_id", "3") for e in events]
                    
                    return EnrichmentResult(
                        ioc_value=ioc_value,
                        ioc_type=ioc_type,
                        source="misp",
                        enriched=True,
                        community_score=float(attr.get("comment", 0)) if attr.get("comment") else 50.0,
                        tags=tags,
                        first_seen=attr.get("first_seen", ""),
                        last_seen=attr.get("last_seen", ""),
                        raw_data=data
                    )
                else:
                    return EnrichmentResult(
                        ioc_value=ioc_value,
                        ioc_type=ioc_type,
                        source="misp",
                        enriched=True,
                        community_score=0.0,
                        error="IOC not found in MISP"
                    )
            else:
                return EnrichmentResult(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    source="misp",
                    enriched=False,
                    error=f"HTTP {response.status_code}"
                )
        
        except requests.RequestException as e:
            return EnrichmentResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source="misp",
                enriched=False,
                error=f"Request failed: {str(e)}"
            )
    
    def enrich_ioc_otx(self, ioc_value: str, ioc_type: str) -> EnrichmentResult:
        """Enrich an IOC using AlienVault OTX."""
        if not self.otx_api_key:
            return EnrichmentResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source="otx",
                enriched=False,
                error="OTX API key not configured"
            )
        
        try:
            otx_type_map = {
                "ip": "IPv4",
                "domain": "domain",
                "hash": "file",
                "url": "URL",
            }
            
            indicator_type = otx_type_map.get(ioc_type, ioc_type)
            url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{ioc_value}/general"
            
            headers = {"X-OTX-API-KEY": self.otx_api_key}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                pulse_info = data.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                
                tags = []
                malware_families = []
                threat_actors = []
                
                for pulse in pulses:
                    tags.extend(pulse.get("tags", []))
                    malware_families.extend(pulse.get("malware_families", []))
                
                # Calculate score based on pulse count
                pulse_count = pulse_info.get("count", 0)
                community_score = min(pulse_count * 10, 100)  # 10 points per pulse, max 100
                
                return EnrichmentResult(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    source="otx",
                    enriched=True,
                    community_score=community_score,
                    tags=list(set(tags)),
                    first_seen=data.get("first_seen", ""),
                    last_seen=data.get("last_seen", ""),
                    malware_families=list(set(malware_families)),
                    threat_actors=list(set(threat_actors)),
                    raw_data=data
                )
            else:
                return EnrichmentResult(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    source="otx",
                    enriched=False,
                    error=f"HTTP {response.status_code}"
                )
        
        except requests.RequestException as e:
            return EnrichmentResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source="otx",
                enriched=False,
                error=f"Request failed: {str(e)}"
            )
    
    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict[str, EnrichmentResult]:
        """Enrich a single IOC using all available sources."""
        results = {}
        
        # VirusTotal
        if ioc_type == "ip":
            results["virustotal"] = self.enrich_ip_virustotal(ioc_value)
        elif ioc_type == "hash":
            results["virustotal"] = self.enrich_hash_virustotal(ioc_value)
        elif ioc_type == "domain":
            results["virustotal"] = self.enrich_domain_virustotal(ioc_value)
        else:
            results["virustotal"] = EnrichmentResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source="virustotal",
                enriched=False,
                error=f"Unsupported IOC type for VT: {ioc_type}"
            )
        
        # MISP
        results["misp"] = self.enrich_ioc_misp(ioc_value, ioc_type)
        
        # OTX
        results["otx"] = self.enrich_ioc_otx(ioc_value, ioc_type)
        
        return results
    
    def enrich_iocs_batch(
        self,
        iocs: List[Dict],
        progress_callback=None
    ) -> Dict[str, Dict[str, EnrichmentResult]]:
        """
        Enrich multiple IOCs.
        
        Args:
            iocs: List of dicts with 'value' and 'type' keys
            progress_callback: Optional callback for progress updates
        
        Returns:
            Dict mapping IOC values to enrichment results by source
        """
        results = {}
        total = len(iocs)
        
        for i, ioc in enumerate(iocs):
            value = ioc.get("value", "")
            ioc_type = ioc.get("type", "")
            
            if not value or not ioc_type:
                continue
            
            results[value] = self.enrich_ioc(value, ioc_type)
            
            if progress_callback:
                progress_callback(i + 1, total)
            
            # Rate limiting between IOCs
            time.sleep(1)
        
        return results
    
    def get_ioc_reputation(self, enrichment_results: Dict[str, EnrichmentResult]) -> Dict:
        """
        Calculate overall reputation from multiple enrichment sources.
        
        Returns:
            Dict with overall score and assessment
        """
        scores = []
        tags = []
        sources_used = []
        
        for source, result in enrichment_results.items():
            if result.enriched and result.community_score is not None:
                scores.append(result.community_score)
                tags.extend(result.tags)
                sources_used.append(source)
        
        if not scores:
            return {
                "score": None,
                "level": "unknown",
                "sources": [],
                "tags": [],
                "assessment": "No enrichment data available"
            }
        
        avg_score = sum(scores) / len(scores)
        
        if avg_score >= 70:
            level = "malicious"
        elif avg_score >= 40:
            level = "suspicious"
        elif avg_score >= 10:
            level = "possibly_suspicious"
        else:
            level = "clean"
        
        return {
            "score": round(avg_score, 2),
            "level": level,
            "sources": sources_used,
            "tags": list(set(tags)),
            "assessment": f"{level.upper()} - Score: {avg_score:.1f}/100"
        }