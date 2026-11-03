# Enterprise Memory Forensics Platform - API Design

## Overview

The platform provides both a programmatic Python API and RESTful endpoints for integration with SOAR platforms, SIEM systems, and automated DFIR workflows.

## Python API

### Core Modules

#### Memory Acquisition

```python
from src.core.acquisition import MemoryAcquisition, AcquisitionMetadata

# Initialize
acq = MemoryAcquisition()

# Acquire memory dump
result = acq.acquire_memory(
    file_path="/path/to/dump.raw",
    name="Incident-2024-001",
    description="Suspected APT activity",
    analyst="John Doe",
    case_number="CASE-2024-001",
    tags=["apt", "incident-response"]
)

# Result contains:
# - snapshot_id: Unique identifier
# - metadata: AcquisitionMetadata object
# - validation: Validation results

# Create baseline
baseline = acq.create_baseline_snapshot(
    file_path="/path/to/baseline.raw",
    name="Windows-10-Base",
    system_info={"os": "Windows 10", "build": "19045"}
)

# List acquisitions
acquisitions = acq.list_acquisitions()

# Get chain of custody
custody = acq.get_chain_of_custody(result["snapshot_id"])
```

#### Analysis Engine

```python
from src.core.analysis_engine import AnalysisOrchestrator

# Initialize
orch = AnalysisOrchestrator()

# Run full analysis
session = orch.run_full_analysis(
    memory_path="/path/to/dump.raw",
    snapshot_id="MEM_20240115_120000_abc123",
    run_volatility=True,
    run_yara=True,
    run_memprocfs=False
)

# Access results
for result in session.engine_results:
    print(f"Engine: {result.engine_name}")
    print(f"Plugin: {result.plugin_name}")
    print(f"Findings: {len(result.findings)}")
    print(f"Status: {result.status}")
    print(f"Execution Time: {result.execution_time:.2f}s")

# Aggregated findings
for finding in session.aggregated_findings:
    print(finding)

# Get process list
processes = orch.get_process_list(session)

# Get network connections
connections = orch.get_network_connections(session)

# Get malfind injections
injections = orch.get_malfind_injections(session)
```

#### Snapshot Comparison

```python
from src.core.snapshot_comparison import SnapshotComparisonEngine

# Initialize
comp = SnapshotComparisonEngine()

# Compare snapshots
result = comp.compare_snapshots(
    baseline_results=baseline_engine_results,
    snapshot_results=current_engine_results,
    baseline_id="MEM_20240101_000000_base",
    snapshot_id="MEM_20240115_120000_abc"
)

# Access differences
print(f"Threat Delta Score: {result.threat_delta_score}")
print(f"Total Changes: {result.changes_detected}")

# New processes
for proc in result.new_processes:
    print(f"NEW: {proc.item_name} - {proc.severity}")

# Hidden processes
for proc in result.hidden_processes:
    print(f"HIDDEN: {proc.item_name} - {proc.confidence:.1f}%")

# DLL changes
for dll in result.dll_changes:
    print(f"DLL: {dll.item_name} - {dll.change_type}")

# Export result
with open("comparison_result.json", "w") as f:
    f.write(result.to_json())
```

#### Threat Detection

```python
from src.core.threat_detection import ThreatDetectionEngine

# Initialize
det = ThreatDetectionEngine()

# Run all detections
detections = det.run_all_detections(
    processes=process_list,
    connections=network_connections,
    services=service_list,
    registry=registry_list,
    command_lines=cmdline_list
)

# Process results
for detection in detections:
    if detection.detected:
        print(f"[{detection.severity.upper()}] {detection.technique}")
        print(f"  ID: {detection.technique_id}")
        print(f"  Confidence: {detection.confidence:.1f}%")
        print(f"  Evidence: {len(detection.evidence)} items")
        print(f"  IOCs: {len(detection.iocs)} items")

# Calculate overall score
scores = det.calculate_overall_score(detections)
print(f"Overall Score: {scores['score']:.1f}/100")
print(f"Level: {scores['level']}")
```

#### VirusTotal-Style Aggregation

```python
from src.core.aggregation_engine import VirusTotalStyleAggregator

# Initialize
agg = VirusTotalStyleAggregator()

# Add engine results
agg.add_engine_result("volatility3", vol_results)
agg.add_engine_result("yara", yara_results)
agg.add_engine_result("heuristic", heuristic_results)

# Correlate findings
findings = agg.correlate_findings()

for finding in findings:
    print(f"Finding: {finding.finding_id}")
    print(f"  Target: {finding.target}")
    print(f"  Confidence: {finding.confidence_score:.1f}%")
    print(f"  Verdict: {finding.final_verdict}")
    print(f"  Engines: {finding.engine_confirmations}/{finding.total_engines}")

# Get distribution
distribution = agg.get_confidence_distribution()
print(distribution)

# Get engine agreement
agreement = agg.get_engine_agreement_stats()
print(agreement)

# Generate report
report = agg.generate_aggregation_report()
```

#### IOC Engine

```python
from src.core.ioc_engine import IOCEngine

# Initialize
ioc_engine = IOCEngine()

# Extract IOCs from analysis results
iocs = ioc_engine.extract_all_iocs(
    processes=process_list,
    connections=network_connections,
    services=service_list,
    strings=memory_strings
)

# Extract from text
text_iocs = ioc_engine.extract_from_string(
    text="Contact 192.168.1.1 or evil.com for C2",
    source="memory_strings"
)

# Get summary
summary = ioc_engine.get_ioc_summary()
print(f"Total IOCs: {summary['total_iocs']}")
print(f"By Type: {summary['by_type']}")

# Export
ioc_engine.export_to_json("iocs.json", iocs)
ioc_engine.export_to_csv("iocs.csv", iocs)
ioc_engine.export_to_stix("iocs_stix.json", iocs)  # STIX 2.1
ioc_engine.export_to_openioc("iocs_openioc.xml", iocs)  # OpenIOC 1.1
```

#### Threat Intelligence

```python
from src.core.threat_intel import ThreatIntelligenceEngine

# Initialize
intel = ThreatIntelligenceEngine(
    vt_api_key="your_vt_key",
    misp_url="https://misp.example.com",
    misp_api_key="your_misp_key",
    otx_api_key="your_otx_key"
)

# Enrich single IOC
results = intel.enrich_ioc("8.8.8.8", "ip")

# VirusTotal result
vt_result = results["virustotal"]
print(f"Detection Ratio: {vt_result.detection_ratio}")
print(f"Community Score: {vt_result.community_score}")
print(f"Tags: {vt_result.tags}")

# Enrich batch
batch = [
    {"value": "8.8.8.8", "type": "ip"},
    {"value": "evil.com", "type": "domain"},
    {"value": "a" * 64, "type": "hash"},
]

results = intel.enrich_iocs_batch(
    iocs=batch,
    progress_callback=lambda done, total: print(f"Progress: {done}/{total}")
)

# Get reputation
reputation = intel.get_ioc_reputation(results["8.8.8.8"])
print(f"Level: {reputation['level']}")
print(f"Score: {reputation['score']}")
```

#### MITRE ATT&CK

```python
from src.core.mitre_attack import MITREAttackMapper

# Initialize
mapper = MITREAttackMapper()

# Map detection
mappings = mapper.map_detection(
    detection_type="process_hollowing",
    evidence=[{"process": "svchost.exe", "pid": 1234}]
)

for mapping in mappings:
    print(f"Technique: {mapping.technique_id} - {mapping.technique_name}")
    print(f"Tactic: {mapping.tactic}")
    print(f"Confidence: {mapping.confidence:.1f}%")

# Generate heatmap
heatmap = mapper.generate_heatmap_data(mappings)
print(heatmap)

# Export for ATT&CK Navigator
navigator_layer = mapper.generate_attack_navigator_layer(mappings)
with open("navigator_layer.json", "w") as f:
    json.dump(navigator_layer, f)
```

#### Timeline

```python
from src.core.timeline import TimelineReconstructor

# Initialize
timeline = TimelineReconstructor()

# Build timeline
entries = timeline.build_timeline(
    processes=process_list,
    dlls=dll_list,
    network=network_connections,
    services=service_list,
    drivers=driver_list,
    injections=injection_list
)

# Get summary
summary = timeline.get_timeline_summary()
print(f"Total Events: {summary['total_events']}")
print(f"Categories: {summary['by_category']}")

# Export
timeline.export_timeline("timeline.json")
```

#### Process Tree

```python
from src.core.process_tree import ProcessTreeBuilder

# Initialize
builder = ProcessTreeBuilder()

# Build tree
tree = builder.build_tree(process_list)

# Analyze
suspicious_chains = builder.get_suspicious_chains()
hidden = builder.get_hidden_processes()
injection_targets = builder.get_injection_targets()
high_risk = builder.get_high_risk_processes(threshold=50.0)

# Plotly data for visualization
plotly_data = builder.generate_plotly_data()
```

#### Reporting

```python
from src.core.reporting import ReportEngine, ReportData

# Prepare report data
report_data = ReportData(
    title="Incident-2024-001 Report",
    case_number="CASE-2024-001",
    analyst="John Doe",
    threat_score=85.5,
    confidence_score=90.0,
    executive_verdict="CRITICAL",
    # ... fill other fields
)

# Generate
engine = ReportEngine()
paths = engine.generate_report(report_data, format="all")

print(f"PDF: {paths.get('pdf')}")
print(f"HTML: {paths.get('html')}")
print(f"JSON: {paths.get('json')}")
```

## REST API (Future)

### Planned Endpoints

```
POST   /api/v1/acquisitions              # Upload memory dump
GET    /api/v1/acquisitions              # List acquisitions
GET    /api/v1/acquisitions/{id}         # Get acquisition details
POST   /api/v1/acquisitions/{id}/analyze # Run analysis
GET    /api/v1/acquisitions/{id}/status  # Check analysis status

GET    /api/v1/snapshots                 # List snapshots
POST   /api/v1/snapshots/compare         # Compare snapshots
GET    /api/v1/snapshots/{id}/processes  # Get process list
GET    /api/v1/snapshots/{id}/network    # Get network connections
GET    /api/v1/snapshots/{id}/timeline   # Get timeline

GET    /api/v1/threats                   # List threats
GET    /api/v1/threats/{id}              # Get threat details
GET    /api/v1/threats/detections        # List detections

GET    /api/v1/iocs                      # List IOCs
POST   /api/v1/iocs/export               # Export IOCs
POST   /api/v1/iocs/enrich               # Enrich IOCs

GET    /api/v1/mitre/heatmap             # Get ATT&CK heatmap
GET    /api/v1/mitre/mappings            # Get technique mappings

POST   /api/v1/reports                   # Generate report
GET    /api/v1/reports/{id}              # Get report
GET    /api/v1/reports/{id}/download     # Download report

GET    /api/v1/analytics/summary         # Get analytics summary
GET    /api/v1/analytics/trends          # Get threat trends
GET    /api/v1/analytics/agreement       # Engine agreement rates
```

### Authentication

```bash
# API Key header
curl -H "X-API-Key: your_api_key" \
     https://forensics.example.com/api/v1/threats

# JWT token
curl -H "Authorization: Bearer <jwt_token>" \
     https://forensics.example.com/api/v1/iocs
```

### Example Requests

```bash
# Upload memory dump
curl -X POST \
  -F "file=@/path/to/dump.raw" \
  -F "name=Incident-001" \
  -F "analyst=John" \
  https://forensics.example.com/api/v1/acquisitions

# Start analysis
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"engines": ["volatility3", "yara"]}' \
  https://forensics.example.com/api/v1/acquisitions/MEM_001/analyze

# Get threats
curl https://forensics.example.com/api/v1/threats?severity=high,critical

# Export IOCs
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"format": "stix", "severity": "high"}' \
  https://forensics.example.com/api/v1/iocs/export
```

## Integration Examples

### SIEM Integration (Splunk)

```python
import requests
import json

# Get threats from platform
response = requests.get(
    "http://forensics:8501/api/v1/threats",
    headers={"X-API-Key": "key"}
)
threats = response.json()

# Send to Splunk HEC
for threat in threats:
    requests.post(
        "https://splunk:8088/services/collector/event",
        headers={"Authorization": "Splunk token"},
        json={"event": threat},
        verify=False
    )
```

### SOAR Integration (Phantom/Splunk SOAR)

```python
def analyze_memory_dump(container_id, dump_path, **kwargs):
    """Phantom playbook action."""
    
    # Upload to forensics platform
    result = requests.post(
        "http://forensics:8501/api/v1/acquisitions",
        files={"file": open(dump_path, "rb")}
    ).json()
    
    # Wait for analysis
    snapshot_id = result["snapshot_id"]
    
    # Get results
    threats = requests.get(
        f"http://forensics:8501/api/v1/snapshots/{snapshot_id}/threats"
    ).json()
    
    # Create artifacts in Phantom
    for threat in threats:
        phantom.add_artifact(
            container=container_id,
            cef_data=threat,
            label="threat"
        )
    
    return threats
```

### TheHive Integration

```python
from thehive4py import TheHiveApi

hive = TheHiveApi("http://thehive:9000", "api_key")

# Get findings from forensics platform
findings = requests.get("http://forensics:8501/api/v1/threats").json()

# Create TheHive case
case = hive.create_case(
    title="Memory Forensics Analysis",
    description="Automated analysis results",
    tlp=2,
    pap=2
)

# Add observables
for ioc in findings["iocs"]:
    hive.create_case_observable(
        case_id=case.id,
        observable_data={
            "dataType": ioc["type"],
            "data": ioc["value"],
            "tlp": 2,
            "ioc": True
        }
    )
```

## Data Models

### Acquisition Request

```json
{
  "file_path": "/path/to/dump.raw",
  "name": "Incident-2024-001",
  "description": "Suspected APT",
  "analyst": "John Doe",
  "case_number": "CASE-001",
  "tags": ["apt", "critical"],
  "system_info": {
    "os": "Windows 10",
    "build": "19045",
    "architecture": "x64"
  }
}
```

### Analysis Result

```json
{
  "session_id": "SESSION_20240115_120000",
  "snapshot_id": "MEM_20240115_120000_abc",
  "status": "completed",
  "engine_results": [
    {
      "engine_name": "volatility3",
      "plugin_name": "windows.pslist.PsList",
      "status": "success",
      "findings_count": 156,
      "execution_time": 12.5
    }
  ],
  "aggregated_findings": [
    {
      "type": "process",
      "process_id": 1234,
      "process_name": "svchost.exe",
      "severity": "high",
      "confidence": 85.5
    }
  ]
}
```

### Threat Detection

```json
{
  "technique": "Process Hollowing",
  "technique_id": "T1055.012",
  "tactic": "Defense Evasion",
  "detected": true,
  "confidence": 85.0,
  "severity": "high",
  "description": "Process hollowing detected",
  "evidence": [
    {
      "process": "svchost.exe",
      "pid": 1234,
      "indicator": "Suspicious parent"
    }
  ],
  "iocs": [
    {
      "type": "process",
      "value": "svchost.exe"
    }
  ]
}
```

### IOC Export (STIX 2.1)

```json
{
  "type": "bundle",
  "id": "bundle--001",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--001",
      "pattern": "[ipv4-addr:value = '192.168.1.100']",
      "pattern_type": "stix",
      "labels": ["malicious-activity"],
      "confidence": 85,
      "x_source": "memory_forensics"
    }
  ]
}
```