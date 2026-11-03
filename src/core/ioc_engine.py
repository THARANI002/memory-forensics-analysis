"""
Enterprise Memory Forensics Platform - IOC Engine
=================================================
Extracts, manages, and exports Indicators of Compromise.
"""

import re
import json
import csv
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from io import StringIO

try:
    from stix2 import Indicator, Malware, Relationship, Bundle
    from stix2 import IPv4Address, IPv6Address, DomainName, URL, File
    STIX_AVAILABLE = True
except ImportError:
    STIX_AVAILABLE = False


@dataclass
class IOC:
    """Single Indicator of Compromise."""
    ioc_type: str  # ip, domain, url, hash, mutex, registry, dll, process, service, filepath
    value: str
    description: str = ""
    source: str = "memory_forensics"
    context: str = ""
    confidence: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    times_seen: int = 1
    tags: List[str] = field(default_factory=list)
    related_iocs: List[str] = field(default_factory=list)
    enrichment: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @property
    def stix_pattern(self) -> str:
        """Generate STIX pattern for this IOC.
        
        STIX 2.1 string literals require backslashes escaped as \\\\ and
        single quotes escaped as \\' so that the pattern validator can parse them.
        """
        escaped = self.value.replace("\\", "\\\\").replace("'", "\\'")
        if self.ioc_type == "ip":
            return f"[ipv4-addr:value = '{escaped}']"
        elif self.ioc_type == "domain":
            return f"[domain-name:value = '{escaped}']"
        elif self.ioc_type == "url":
            return f"[url:value = '{escaped}']"
        elif self.ioc_type == "hash":
            hash_type = self._detect_hash_type()
            return f"[file:hashes.{hash_type} = '{escaped}']"
        elif self.ioc_type == "process":
            return f"[process:name = '{escaped}']"
        elif self.ioc_type == "filepath":
            return f"[file:path = '{escaped}']"
        elif self.ioc_type == "registry":
            return f"[windows-registry-key:key = '{escaped}']"
        else:
            return f"[{self.ioc_type}:value = '{escaped}']"
    
    def _detect_hash_type(self) -> str:
        """Detect hash algorithm from length."""
        length = len(self.value)
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA-1"
        elif length == 64:
            return "SHA-256"
        return "UNKNOWN"


class IOCEngine:
    """Engine for IOC extraction and management."""
    
    # Regex patterns for IOC extraction
    PATTERNS = {
        "ip": re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        "domain": re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        ),
        "url": re.compile(
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
        ),
        "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
        "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
        "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
        "mutex": re.compile(
            r'Global\\[A-Za-z0-9_-]+|Local\\[A-Za-z0-9_-]+'
        ),
        "registry": re.compile(
            r'HKEY_[A-Z_]+(?:\\[A-Za-z0-9\s._-]+)+'
        ),
        "email": re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ),
    }
    
    # Common domains to exclude (false positives)
    DOMAIN_EXCLUDES = {
        "microsoft.com", "windows.com", "google.com", "github.com",
        "office.net", "live.com", "outlook.com", "bing.com",
        "mozilla.org", "apple.com", "amazon.com", "facebook.com",
    }
    
    def __init__(self):
        self.iocs: Dict[str, IOC] = {}
    
    def extract_from_string(self, text: str, source: str = "analysis") -> List[IOC]:
        """Extract IOCs from a text string."""
        iocs = []
        
        # Extract IPs
        for match in self.PATTERNS["ip"].finditer(text):
            ip = match.group()
            # Filter out private IPs unless specifically needed
            if not self._is_private_ip(ip):
                ioc = IOC(
                    ioc_type="ip",
                    value=ip,
                    source=source,
                    context=text[max(0, match.start()-50):match.end()+50],
                    confidence=70.0 if source != "command_line" else 80.0,
                )
                iocs.append(ioc)
        
        # Extract domains
        for match in self.PATTERNS["domain"].finditer(text):
            domain = match.group().lower()
            if domain not in self.DOMAIN_EXCLUDES and not domain.endswith(
                tuple(self.DOMAIN_EXCLUDES)
            ):
                ioc = IOC(
                    ioc_type="domain",
                    value=domain,
                    source=source,
                    context=text[max(0, match.start()-50):match.end()+50],
                    confidence=75.0,
                )
                iocs.append(ioc)
        
        # Extract URLs
        for match in self.PATTERNS["url"].finditer(text):
            ioc = IOC(
                ioc_type="url",
                value=match.group(),
                source=source,
                context=text[max(0, match.start()-50):match.end()+50],
                confidence=80.0,
            )
            iocs.append(ioc)
        
        # Extract hashes
        for match in self.PATTERNS["sha256"].finditer(text):
            iocs.append(IOC(
                ioc_type="hash",
                value=match.group(),
                description="SHA-256 hash",
                source=source,
                confidence=90.0,
            ))
        
        for match in self.PATTERNS["md5"].finditer(text):
            iocs.append(IOC(
                ioc_type="hash",
                value=match.group(),
                description="MD5 hash",
                source=source,
                confidence=85.0,
            ))
        
        # Extract mutexes
        for match in self.PATTERNS["mutex"].finditer(text):
            iocs.append(IOC(
                ioc_type="mutex",
                value=match.group(),
                source=source,
                confidence=60.0,
            ))
        
        # Extract registry keys
        for match in self.PATTERNS["registry"].finditer(text):
            iocs.append(IOC(
                ioc_type="registry",
                value=match.group(),
                source=source,
                confidence=70.0,
            ))
        
        return iocs
    
    def extract_from_processes(self, processes: List[Dict]) -> List[IOC]:
        """Extract IOCs from process list."""
        iocs = []
        
        for proc in processes:
            # Extract from process names and paths
            name = proc.get("name", "")
            path = proc.get("exe_path") or proc.get("path", "")
            
            if name:
                iocs.append(IOC(
                    ioc_type="process",
                    value=name,
                    description=f"Process: {name} (PID: {proc.get('pid', '?')})",
                    context=f"Parent: {proc.get('parent_name', 'Unknown')}",
                    confidence=55.0,
                ))
            
            if path:
                iocs.append(IOC(
                    ioc_type="filepath",
                    value=path,
                    source="process",
                    confidence=45.0,
                ))
            
            # Extract from command line
            cmdline = proc.get("command_line", "")
            if cmdline:
                iocs.extend(self.extract_from_string(cmdline, "command_line"))
        
        return iocs
    
    def extract_from_network(self, connections: List[Dict]) -> List[IOC]:
        """Extract IOCs from network connections."""
        iocs = []

        for conn in connections:
            # Support both key naming conventions
            local_ip = conn.get("local_address") or conn.get("local_addr")
            remote_ip = conn.get("remote_address") or conn.get("remote_addr")
            remote_port = conn.get("remote_port")
            local_port = conn.get("local_port")
            process = conn.get("process") or conn.get("process_name", "Unknown")
            protocol = conn.get("protocol", "TCP")
            state = conn.get("state", "")

            # Extract suspicious remote IPs (non-private, non-wildcard)
            if remote_ip and remote_ip not in ("*", "0.0.0.0", "") and not self._is_private_ip(remote_ip):
                confidence = 85.0 if remote_port in [4444, 1337, 8080, 9999, 31337] else 70.0
                iocs.append(IOC(
                    ioc_type="ip",
                    value=remote_ip,
                    description=f"Remote C2 candidate {remote_ip}:{remote_port} via {process}",
                    context=f"Process: {process} | Port: {remote_port} | State: {state}",
                    source="network_connection",
                    confidence=confidence,
                    tags=["network", protocol.lower(), state.lower()]
                ))

            # Extract suspicious local listeners
            if local_ip and local_port and state == "LISTENING":
                if local_port not in [80, 443, 8080, 135, 139, 445, 3389]:
                    iocs.append(IOC(
                        ioc_type="ip",
                        value=f"{local_ip}:{local_port}",
                        description=f"Suspicious listener on port {local_port} by {process}",
                        source="network_listener",
                        confidence=60.0,
                        tags=["network", "listener"]
                    ))

        return iocs
    
    def extract_from_services(self, services: List[Dict]) -> List[IOC]:
        """Extract IOCs from services."""
        iocs = []
        
        for svc in services:
            svc_name = svc.get("service_name")
            binary_path = svc.get("binary_path")
            
            if svc_name:
                iocs.append(IOC(
                    ioc_type="service",
                    value=svc_name,
                    description=f"Service: {svc.get('display_name', svc_name)}",
                    context=f"Binary: {binary_path}",
                    confidence=65.0,
                ))
            
            if binary_path:
                iocs.append(IOC(
                    ioc_type="filepath",
                    value=binary_path,
                    source="service",
                    confidence=60.0,
                ))
        
        return iocs
    
    def extract_all_iocs(
        self,
        processes: List[Dict] = None,
        connections: List[Dict] = None,
        services: List[Dict] = None,
        registry: List[Dict] = None,
        memory_regions: List[Dict] = None,
        strings: List[str] = None
    ) -> List[IOC]:
        """Extract all IOCs from analysis results."""
        all_iocs = []
        
        if processes:
            all_iocs.extend(self.extract_from_processes(processes))
        
        if connections:
            all_iocs.extend(self.extract_from_network(connections))
        
        if services:
            all_iocs.extend(self.extract_from_services(services))
        
        if strings:
            for s in strings:
                all_iocs.extend(self.extract_from_string(s, "memory_strings"))
        
        # Deduplicate
        seen = set()
        unique_iocs = []
        for ioc in all_iocs:
            key = f"{ioc.ioc_type}:{ioc.value}"
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        
        self.iocs = {f"{ioc.ioc_type}:{ioc.value}": ioc for ioc in unique_iocs}
        
        return unique_iocs
    
    def export_to_json(self, output_path: str, iocs: List[IOC] = None) -> str:
        """Export IOCs to JSON format."""
        iocs = iocs or list(self.iocs.values())
        
        data = {
            "export_metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_iocs": len(iocs),
                "format": "json",
                "version": "1.0"
            },
            "iocs": [ioc.to_dict() for ioc in iocs]
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        return output_path
    
    def export_to_csv(self, output_path: str, iocs: List[IOC] = None) -> str:
        """Export IOCs to CSV format."""
        iocs = iocs or list(self.iocs.values())
        
        fieldnames = [
            "ioc_type", "value", "description", "source",
            "confidence", "first_seen", "tags"
        ]
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for ioc in iocs:
                writer.writerow({
                    "ioc_type": ioc.ioc_type,
                    "value": ioc.value,
                    "description": ioc.description,
                    "source": ioc.source,
                    "confidence": ioc.confidence,
                    "first_seen": ioc.first_seen,
                    "tags": ",".join(ioc.tags)
                })
        
        return output_path
    
    def export_to_stix(self, output_path: str, iocs: List[IOC] = None) -> str:
        """Export IOCs to STIX 2.1 format."""
        if not STIX_AVAILABLE:
            raise ImportError("stix2 library not installed. Install with: pip install stix2")
        
        iocs = iocs or list(self.iocs.values())
        
        stix_objects = []
        
        for ioc in iocs:
            indicator = Indicator(
                pattern=ioc.stix_pattern,
                pattern_type="stix",
                name=f"{ioc.ioc_type}: {ioc.value[:50]}",
                description=ioc.description or f"IOC extracted from memory forensics",
                labels=[ioc.source] + ioc.tags,
                confidence=int(ioc.confidence),
                custom_properties={
                    "x_first_seen": ioc.first_seen,
                    "x_times_seen": ioc.times_seen,
                    "x_source": ioc.source,
                }
            )
            stix_objects.append(indicator)
        
        bundle = Bundle(objects=stix_objects, allow_custom=True)
        
        with open(output_path, 'w') as f:
            f.write(bundle.serialize(pretty=True))
        
        return output_path
    
    def export_to_openioc(self, output_path: str, iocs: List[IOC] = None) -> str:
        """Export IOCs to OpenIOC format."""
        iocs = iocs or list(self.iocs.values())
        
        # Generate OpenIOC XML
        xml_content = self._generate_openioc_xml(iocs)
        
        with open(output_path, 'w') as f:
            f.write(xml_content)
        
        return output_path
    
    def _generate_openioc_xml(self, iocs: List[IOC]) -> str:
        """Generate OpenIOC 1.1 XML content."""
        ioc_id = f"memory-forensics-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<OpenIOC xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xmlns:xsd="http://www.w3.org/2001/XMLSchema"
         xmlns="http://openioc.org/schemas/OpenIOC_1.1"
         id="{ioc_id}"
         last-modified="{datetime.now(timezone.utc).isoformat()}"
         published-date="{datetime.now(timezone.utc).isoformat()}"
         revision="1">
    <description>Memory Forensics IOC Export</description>
    <authored_by>Enterprise Memory Forensics Platform</authored_by>
    <authored_date>{datetime.now(timezone.utc).isoformat()}</authored_date>
    <links />
    <definition>
        <Indicator operator="OR" id="{ioc_id}-root">
'''
        
        for i, ioc in enumerate(iocs):
            item_id = f"{ioc_id}-{i:04d}"
            xml += self._generate_openioc_item(ioc, item_id)
        
        xml += '''        </Indicator>
    </definition>
</OpenIOC>'''
        
        return xml
    
    def _generate_openioc_item(self, ioc: IOC, item_id: str) -> str:
        """Generate a single OpenIOC indicator item."""
        type_map = {
            "ip": ("Network", "IPV4AddressItem/IPv4Address"),
            "domain": ("Network", "DnsEntryItem/Host"),
            "url": ("Network", "UrlHistoryItem/URL"),
            "hash": ("FileItem", "FileItem/Md5sum" if len(ioc.value) == 32 else "FileItem/Sha256sum"),
            "process": ("ProcessItem", "ProcessItem/name"),
            "filepath": ("FileItem", "FileItem/FilePath"),
            "registry": ("RegistryItem", "RegistryItem/Path"),
            "mutex": ("HandleItem", "HandleItem/name"),
            "service": ("ServiceItem", "ServiceItem/name"),
        }
        
        context, content = type_map.get(ioc.ioc_type, ("Item", "Item/value"))
        
        return f'''
            <IndicatorItem id="{item_id}" condition="is" preserve-case="true">
                <Context document="{context}" search="{content}" type="mir" />
                <Content type="string">{self._escape_xml(ioc.value)}</Content>
                <Comment>{self._escape_xml(ioc.description)}</Comment>
            </IndicatorItem>
'''
    
    def _escape_xml(self, text: str) -> str:
        """Escape XML special characters."""
        if not text:
            return ""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&apos;"))
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first = int(parts[0])
            second = int(parts[1])
            
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            if first == 169 and second == 254:
                return True
            
            return False
        except ValueError:
            return False
    
    def get_ioc_summary(self) -> Dict:
        """Get summary of extracted IOCs."""
        iocs = list(self.iocs.values())
        
        type_counts = {}
        for ioc in iocs:
            type_counts[ioc.ioc_type] = type_counts.get(ioc.ioc_type, 0) + 1
        
        return {
            "total_iocs": len(iocs),
            "by_type": type_counts,
            "high_confidence": len([i for i in iocs if i.confidence >= 70]),
            "medium_confidence": len([i for i in iocs if 30 <= i.confidence < 70]),
            "low_confidence": len([i for i in iocs if i.confidence < 30]),
        }