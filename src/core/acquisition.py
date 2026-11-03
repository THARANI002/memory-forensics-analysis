"""
Enterprise Memory Forensics Platform - Memory Acquisition Module
================================================================
Handles memory dump acquisition, validation, hashing, and chain of custody.
"""

import os
import hashlib
import json
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, asdict

from config.settings import (
    MEMORY_DUMPS_DIR, ACQUISITION_CONFIG
)


@dataclass
class AcquisitionMetadata:
    """Metadata for a memory acquisition."""
    file_path: str
    snapshot_id: Optional[str] = None
    name: Optional[str] = None
    file_size: int = 0
    sha256_hash: str = ""
    md5_hash: str = ""
    acquisition_tool: str = ""
    acquisition_format: str = ""
    acquisition_time: str = ""
    system_info: Dict = None
    operating_system: Optional[str] = None
    architecture: Optional[str] = None
    profile: Optional[str] = None
    hostname: Optional[str] = None
    analyst: Optional[str] = None
    case_number: Optional[str] = None
    notes: Optional[str] = None
    tags: List[str] = None
    is_baseline: bool = False
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


@dataclass
class ChainOfCustodyEntry:
    """Single entry in the chain of custody log."""
    action: str
    performed_by: str
    performed_at: str
    description: str
    hash_before: Optional[str] = None
    hash_after: Optional[str] = None
    location: Optional[str] = None
    witnesses: Optional[List[str]] = None
    digital_signature: Optional[str] = None
    verification_status: str = "verified"
    
    def to_dict(self) -> Dict:
        return asdict(self)


class ChainOfCustodyLog:
    """Manages chain of custody for memory evidence."""
    
    def __init__(self, snapshot_id: str):
        self.snapshot_id = snapshot_id
        self.entries: List[ChainOfCustodyEntry] = []
        self.log_file = MEMORY_DUMPS_DIR / f"{snapshot_id}_custody.log"
    
    def add_entry(self, entry: ChainOfCustodyEntry) -> None:
        """Add a new chain of custody entry."""
        self.entries.append(entry)
        self._save_log()
    
    def create_entry(
        self,
        action: str,
        performed_by: str,
        description: str,
        hash_before: Optional[str] = None,
        hash_after: Optional[str] = None,
        location: Optional[str] = None,
        witnesses: Optional[List[str]] = None
    ) -> ChainOfCustodyEntry:
        """Create and add a new custody entry."""
        entry = ChainOfCustodyEntry(
            action=action,
            performed_by=performed_by,
            performed_at=datetime.now(timezone.utc).isoformat(),
            description=description,
            hash_before=hash_before,
            hash_after=hash_after,
            location=location,
            witnesses=witnesses or [],
            verification_status="verified"
        )
        self.add_entry(entry)
        return entry
    
    def _save_log(self) -> None:
        """Save custody log to file."""
        log_data = {
            "snapshot_id": self.snapshot_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "entries": [e.to_dict() for e in self.entries]
        }
        with open(self.log_file, 'w') as f:
            json.dump(log_data, f, indent=2)
    
    def load_log(self) -> Dict:
        """Load custody log from file."""
        if self.log_file.exists():
            with open(self.log_file, 'r') as f:
                return json.load(f)
        return {"snapshot_id": self.snapshot_id, "entries": []}
    
    def verify_integrity(self) -> bool:
        """Verify chain of custody integrity."""
        for i, entry in enumerate(self.entries):
            if i > 0 and entry.hash_before != self.entries[i-1].hash_after:
                entry.verification_status = "compromised"
                return False
        return True


class MemoryAcquisition:
    """Core memory acquisition handler."""
    
    SUPPORTED_FORMATS = [
        "raw", "lime", "aff4", "winpmem", "dumpit", 
        "avml", "vmem", "mem", "hpak", "crash"
    ]
    
    TOOL_SIGNATURES = {
        "winpmem": {"extensions": [".aff4"], "headers": [b"AFF4"]},
        "dumpit": {"extensions": [".raw", ".dmp"], "headers": [b"MDMP"]},
        "avml": {"extensions": [".lime", ".avml"], "headers": [b"LiME"]},
        "lime": {"extensions": [".lime"], "headers": [b"LiME"]},
        "raw": {"extensions": [".raw", ".mem", ".dump", ".bin"], "headers": []},
        "aff4": {"extensions": [".aff4"], "headers": [b"AFF4"]},
    }
    
    def __init__(self):
        self.config = ACQUISITION_CONFIG
        self._ensure_directories()
    
    def _ensure_directories(self) -> None:
        """Ensure required directories exist."""
        MEMORY_DUMPS_DIR.mkdir(parents=True, exist_ok=True)
    
    def calculate_hashes(self, file_path: str) -> Tuple[str, str]:
        """Calculate SHA256 and MD5 hashes for a file."""
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(self.config.chunk_size):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)
        
        return sha256_hash.hexdigest(), md5_hash.hexdigest()
    
    def detect_format(self, file_path: str) -> str:
        """Detect memory dump format from file signatures."""
        path = Path(file_path)
        ext = path.suffix.lower()
        
        # Check extension first
        for fmt, sig in self.TOOL_SIGNATURES.items():
            if ext in sig["extensions"]:
                return fmt
        
        # Check file headers
        with open(file_path, 'rb') as f:
            header = f.read(16)
        
        for fmt, sig in self.TOOL_SIGNATURES.items():
            for magic in sig["headers"]:
                if header.startswith(magic):
                    return fmt
        
        # Default to raw
        return "raw"
    
    def detect_tool(self, file_path: str) -> str:
        """Detect which tool created the memory dump."""
        return self.detect_format(file_path)
    
    def validate_dump(self, file_path: str) -> Dict:
        """Validate a memory dump file."""
        path = Path(file_path)
        results = {
            "valid": False,
            "file_exists": False,
            "file_size": 0,
            "format_detected": None,
            "tool_detected": None,
            "sha256": None,
            "md5": None,
            "errors": [],
            "warnings": []
        }
        
        if not path.exists():
            results["errors"].append("File does not exist")
            return results
        
        results["file_exists"] = True
        results["file_size"] = path.stat().st_size
        
        if results["file_size"] == 0:
            results["errors"].append("File is empty")
            return results
        
        if results["file_size"] > self.config.max_file_size_gb * 1024**3:
            results["warnings"].append(
                f"File exceeds maximum size of {self.config.max_file_size_gb}GB"
            )
        
        # Detect format
        fmt = self.detect_format(file_path)
        results["format_detected"] = fmt
        results["tool_detected"] = self.detect_tool(file_path)
        
        if fmt not in self.SUPPORTED_FORMATS:
            results["warnings"].append(f"Format '{fmt}' may not be fully supported")
        
        # Calculate hashes
        if self.config.verify_integrity:
            sha256, md5 = self.calculate_hashes(file_path)
            results["sha256"] = sha256
            results["md5"] = md5
        
        results["valid"] = len(results["errors"]) == 0
        return results
    
    def acquire_memory(
        self,
        file_path: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        analyst: Optional[str] = None,
        case_number: Optional[str] = None,
        tags: Optional[List[str]] = None,
        system_info: Optional[Dict] = None
    ) -> Dict:
        """
        Process and catalog a memory dump file.
        
        Args:
            file_path: Path to the memory dump file
            name: Descriptive name for the snapshot
            description: Optional description
            analyst: Name of the analyst
            case_number: Associated case number
            tags: List of tags
            system_info: System information dictionary
        
        Returns:
            Dictionary with acquisition results and metadata
        """
        file_path = str(Path(file_path).resolve())
        
        # Validate
        validation = self.validate_dump(file_path)
        if not validation["valid"]:
            return {
                "success": False,
                "errors": validation["errors"],
                "validation": validation
            }
        
        # Generate snapshot ID
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        snapshot_id = f"MEM_{timestamp}_{validation['sha256'][:16]}"
        
        # Create metadata
        metadata = AcquisitionMetadata(
            file_path=file_path,
            snapshot_id=snapshot_id,
            name=name or Path(file_path).name,
            file_size=validation["file_size"],
            sha256_hash=validation["sha256"],
            md5_hash=validation["md5"],
            acquisition_tool=validation["tool_detected"],
            acquisition_format=validation["format_detected"],
            acquisition_time=datetime.now(timezone.utc).isoformat(),
            system_info=system_info or {},
            operating_system=system_info.get("os") if system_info else None,
            architecture=system_info.get("architecture") if system_info else None,
            profile=system_info.get("profile") if system_info else None,
            hostname=system_info.get("hostname") if system_info else None,
            analyst=analyst,
            case_number=case_number,
            notes=description,
            tags=tags or [],
            is_baseline=False,
        )
        
        # Initialize chain of custody
        custody = ChainOfCustodyLog(snapshot_id)
        custody.create_entry(
            action="ACQUISITION",
            performed_by=analyst or "system",
            description=f"Memory dump acquired: {name or file_path}",
            hash_after=validation["sha256"],
            location=file_path
        )
        
        # Save metadata
        metadata_path = MEMORY_DUMPS_DIR / f"{snapshot_id}.json"
        with open(metadata_path, 'w') as f:
            f.write(metadata.to_json())
        
        return {
            "success": True,
            "snapshot_id": snapshot_id,
            "metadata": metadata.to_dict(),
            "validation": validation,
            "metadata_path": str(metadata_path)
        }
    
    def create_baseline_snapshot(
        self,
        file_path: str,
        name: str,
        analyst: Optional[str] = None,
        system_info: Optional[Dict] = None
    ) -> Dict:
        """Create a baseline snapshot for comparison."""
        result = self.acquire_memory(
            file_path=file_path,
            name=name,
            description="Baseline snapshot for comparison analysis",
            analyst=analyst,
            tags=["baseline", "reference"],
            system_info=system_info
        )
        
        if result["success"]:
            self.mark_as_baseline(result["snapshot_id"])
            result["metadata"]["is_baseline"] = True
        
        return result

    def update_metadata_record(self, snapshot_id: str, updates: Dict) -> Optional[Dict]:
        """Update a stored acquisition metadata record and return the updated data."""
        metadata_path = MEMORY_DUMPS_DIR / f"{snapshot_id}.json"
        if not metadata_path.exists():
            return None
        
        with open(metadata_path, 'r') as f:
            data = json.load(f)
        data.update(updates or {})
        with open(metadata_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return data

    def mark_as_baseline(self, snapshot_id: str, findings: Optional[List] = None,
                         metadata: Optional[Dict] = None) -> Optional[Dict]:
        """Mark a snapshot as a baseline and persist its findings so later comparisons have real data.

        If no metadata record exists yet (e.g. the bundled demo snapshot), one is created from *metadata*.
        """
        updates: Dict = {"is_baseline": True}
        if findings is not None:
            updates["aggregated_findings"] = findings
        record_path = MEMORY_DUMPS_DIR / f"{snapshot_id}.json"
        if not record_path.exists() and metadata is not None:
            base = dict(metadata)
            base.setdefault("snapshot_id", snapshot_id)
            base.setdefault("acquisition_time", datetime.now(timezone.utc).isoformat())
            with open(record_path, "w") as f:
                json.dump(base, f, indent=2, default=str)
        return self.update_metadata_record(snapshot_id, updates)

    def get_system_info(self) -> Dict:
        """Collect system information from the current machine."""
        try:
            import platform
            import psutil
            
            return {
                "hostname": platform.node(),
                "os": f"{platform.system()} {platform.release()}",
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                "platform": platform.platform(),
            }
        except ImportError:
            return {
                "hostname": "unknown",
                "os": "unknown",
                "architecture": "unknown",
                "note": "psutil not available"
            }
    
    def list_acquisitions(self) -> List[Dict]:
        """List all memory acquisitions."""
        acquisitions = []
        
        for meta_file in MEMORY_DUMPS_DIR.glob("MEM_*.json"):
            try:
                with open(meta_file, 'r') as f:
                    data = json.load(f)
                acquisitions.append(data)
            except Exception:
                continue
        
        return sorted(acquisitions, key=lambda x: x.get("acquisition_time", ""), reverse=True)
    
    def get_acquisition(self, snapshot_id: str) -> Optional[Dict]:
        """Get a specific acquisition by ID."""
        metadata_path = MEMORY_DUMPS_DIR / f"{snapshot_id}.json"
        
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                return json.load(f)
        return None
    
    def get_chain_of_custody(self, snapshot_id: str) -> Dict:
        """Get chain of custody log for a snapshot."""
        custody = ChainOfCustodyLog(snapshot_id)
        return custody.load_log()
