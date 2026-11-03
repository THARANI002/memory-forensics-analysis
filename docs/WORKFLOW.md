# Enterprise Memory Forensics Platform - Workflow Diagram

## Complete DFIR Workflow

```mermaid
flowchart TB
    subgraph ACQUISITION["📁 1. Memory Acquisition"]
        A1["Memory Dump Upload<br/>RAW / LiME / AFF4 / VMEM"] --> A2["Format Detection<br/>& Validation"]
        A2 --> A3["SHA256 Hash<br/>Calculation"]
        A3 --> A4["Metadata Extraction<br/>OS / Profile / Arch"]
        A4 --> A5["Chain of Custody<br/>Log Entry"]
        A5 --> A6[("SQLite Database<br/>Snapshot Storage")]
    end

    subgraph ANALYSIS["🔬 2. Multi-Engine Analysis"]
        A6 --> V3["Volatility 3<br/>pslist / psscan / pstree<br/>dlllist / malfind / netscan<br/>svcscan / callbacks / driverirp<br/>modscan / registry.hivelist"]
        A6 --> YARA["YARA Engine<br/>Malware Rules<br/>Shellcode Rules<br/>Cobalt Strike Rules"]
        A6 --> MPF["MemProcFS<br/>Process Analysis"]
        A6 --> REK["Rekall<br/>Memory Analysis"]
    
        V3 --> MERGE["🔄 Result<br/>Aggregation"]
        YARA --> MERGE
        MPF --> MERGE
        REK --> MERGE
    end

    subgraph COMPARISON["🔄 3. Snapshot Comparison"]
        MERGE --> COMP["Comparison Engine<br/>Baseline vs Current"]
        BASE[("Baseline<br/>Snapshot")] --> COMP
        COMP --> COMP_DETECT["Detect Changes:<br/>• New/Missing/Hidden Processes<br/>• DLL Changes<br/>• New Services/Drivers<br/>• Network Changes<br/>• Registry Changes"]
        COMP_DETECT --> DELTA["Threat Delta Score<br/>Calculation"]
    end

    subgraph DETECTION["🎯 4. Threat Detection"]
        MERGE --> TD["Threat Detection Engine"]
        DELTA --> TD
        
        TD --> T1["Process Hollowing<br/>T1055.012"]
        TD --> T2["DLL Injection<br/>T1055.001"]
        TD --> T3["Reflective DLL<br/>T1620"]
        TD --> T4["Doppelgänging<br/>T1055"]
        TD --> T5["AtomBombing<br/>T1055"]
        TD --> T6["Process Herpaderping<br/>T1055"]
        TD --> T7["Rootkit Detection<br/>T1014"]
        TD --> T8["Parent PID Spoofing<br/>T1134.004"]
        TD --> T9["Command Obfuscation<br/>T1027"]
        TD --> T10["Fileless Malware<br/>T1059"]
        TD --> T11["PowerShell Abuse<br/>T1059.001"]
        TD --> T12["Credential Dumping<br/>T1003"]
        TD --> T13["LSASS Access<br/>T1003.001"]
        TD --> T14["Persistence<br/>T1547"]
    end

    subgraph AGGREGATION["⚖️ 5. VT-Style Aggregation"]
        T1 --> AGG
        T2 --> AGG
        T3 --> AGG
        T4 --> AGG
        T5 --> AGG
        T6 --> AGG
        T7 --> AGG
        T8 --> AGG
        T9 --> AGG
        T10 --> AGG
        T11 --> AGG
        T12 --> AGG
        T13 --> AGG
        T14 --> AGG
        
        AGG["Aggregation Engine<br/>Multi-Engine Correlation"]
        
        AGG --> RULE1["Rule: Min 2 Engine<br/>Confirmations"]
        RULE1 --> RULE2["Signature Weight: 1.0<br/>Heuristic Weight: 0.7<br/>Anomaly Weight: 0.5"]
        RULE2 --> CONF["Confidence Score<br/>Calculation"]
    end

    subgraph VERDICT["📊 6. Confidence Verdict"]
        CONF --> VER["Verdict Assignment"]
        
        VER --> V_MAL["≥ 90: Confirmed<br/>Malicious"]
        VER --> V_HIGH["≥ 70: Highly<br/>Suspicious"]
        VER --> V_SUSP["≥ 50: Suspicious"]
        VER --> V_POS["≥ 30: Possibly<br/>Suspicious"]
        VER --> V_BEN["< 30: Likely<br/>Benign"]
    end

    subgraph IOC["🎯 7. IOC Extraction"]
        AGG --> IOC_ENG["IOC Engine"]
        
        IOC_ENG --> IOC_IP["IP Addresses"]
        IOC_ENG --> IOC_DOM["Domains"]
        IOC_ENG --> IOC_URL["URLs"]
        IOC_ENG --> IOC_HASH["File Hashes"]
        IOC_ENG --> IOC_MUT["Mutexes"]
        IOC_ENG --> IOC_REG["Registry Keys"]
        IOC_ENG --> IOC_DLL["DLLs"]
        IOC_ENG --> IOC_PROC["Processes"]
        
        IOC_IP --> IOC_OUT["Multi-Format Export:<br/>JSON / CSV / PDF / STIX 2.1 / OpenIOC"]
        IOC_DOM --> IOC_OUT
        IOC_URL --> IOC_OUT
        IOC_HASH --> IOC_OUT
        IOC_MUT --> IOC_OUT
        IOC_REG --> IOC_OUT
        IOC_DLL --> IOC_OUT
        IOC_PROC --> IOC_OUT
    end

    subgraph INTEL["🌐 8. Threat Intelligence"]
        IOC_IP --> VT["VirusTotal API"]
        IOC_DOM --> VT
        IOC_HASH --> VT
        
        IOC_IP --> MISP["MISP"]
        IOC_HASH --> MISP
        
        IOC_IP --> OTX["AlienVault OTX"]
        IOC_DOM --> OTX
        IOC_HASH --> OTX
        
        VT --> ENRICH["Enriched IOCs:<br/>• Detection Ratios<br/>• Community Scores<br/>• Tags<br/>• First/Last Seen"]
        MISP --> ENRICH
        OTX --> ENRICH
    end

    subgraph MITRE["🎯 9. MITRE ATT&CK"]
        VER --> MITRE_MAP["MITRE ATT&CK<br/>Mapping Engine"]
        
        MITRE_MAP --> MT1["T1055 Process Injection"]
        MITRE_MAP --> MT2["T1055.012 Process Hollowing"]
        MITRE_MAP --> MT3["T1055.001 DLL Injection"]
        MITRE_MAP --> MT4["T1620 Reflective Code Loading"]
        MITRE_MAP --> MT5["T1014 Rootkit"]
        MITRE_MAP --> MT6["T1003.001 LSASS Memory"]
        MITRE_MAP --> MT7["T1056.001 Keylogging"]
        MITRE_MAP --> MT8["T1071 Application Layer Protocol"]
        
        MT1 --> HEAT["ATT&CK Heatmap<br/>Generation"]
        MT2 --> HEAT
        MT3 --> HEAT
        MT4 --> HEAT
        MT5 --> HEAT
        MT6 --> HEAT
        MT7 --> HEAT
        MT8 --> HEAT
        
        HEAT --> NAV["Navigator Layer<br/>Export"]
    end

    subgraph TIMELINE["⏱️ 10. Timeline Reconstruction"]
        AGG --> TL["Timeline Engine"]
        
        TL --> TL1["Process Creation<br/>Events"]
        TL --> TL2["DLL Loading<br/>Events"]
        TL --> TL3["Network Activity<br/>Events"]
        TL --> TL4["Registry<br/>Events"]
        TL --> TL5["Service Creation<br/>Events"]
        TL --> TL6["Driver Loading<br/>Events"]
        TL --> TL7["Memory Injection<br/>Events"]
        
        TL1 --> TL_MERGE["Chronological<br/>Merge"]
        TL2 --> TL_MERGE
        TL3 --> TL_MERGE
        TL4 --> TL_MERGE
        TL5 --> TL_MERGE
        TL6 --> TL_MERGE
        TL7 --> TL_MERGE
    end

    subgraph TREE["🌳 11. Process Tree"]
        AGG --> PT["Process Tree<br/>Builder"]
        
        PT --> PT1["Parent-Child<br/>Relationships"]
        PT1 --> PT2["Suspicious Chain<br/>Detection"]
        PT1 --> PT3["Injection Target<br/>Identification"]
        PT1 --> PT4["Hidden Process<br/>Detection"]
        
        PT2 --> PLOT["Interactive Plotly<br/>Visualization"]
        PT3 --> PLOT
        PT4 --> PLOT
    end

    subgraph REPORT["📑 12. Report Generation"]
        ENRICH --> REP["Report Engine"]
        HEAT --> REP
        TL_MERGE --> REP
        PLOT --> REP
        
        REP --> R_EXEC["Executive Summary"]
        REP --> R_THREAT["Threat Findings"]
        REP --> R_IOC["IOC List"]
        REP --> R_MITRE["MITRE Mapping"]
        REP --> R_TL["Timeline"]
        REP --> R_COMP["Comparison Results"]
        REP --> R_REC["Recommendations"]
        
        R_EXEC --> R_OUT["Output Formats:<br/>PDF / HTML / JSON"]
        R_THREAT --> R_OUT
        R_IOC --> R_OUT
        R_MITRE --> R_OUT
        R_TL --> R_OUT
        R_COMP --> R_OUT
        R_REC --> R_OUT
    end

    subgraph ANALYTICS["📈 13. Historical Analytics"]
        R_OUT --> HIST["Analytics Engine"]
        
        HIST --> H1["Threat Score<br/>Trends"]
        HIST --> H2["IOC Discovery<br/>Trends"]
        HIST --> H3["Detection<br/>Trends"]
        HIST --> H4["Engine Agreement<br/>Rates"]
        
        H1 --> DASH["Dashboard<br/>Metrics"]
        H2 --> DASH
        H3 --> DASH
        H4 --> DASH
    end

    subgraph DB[("🗄️ SQLite Database")]
        direction TB
        DB1["snapshots"]
        DB2["threat_events"]
        DB3["iocs"]
        DB4["timeline_events"]
        DB5["reports"]
        DB6["investigations"]
        DB7["chain_of_custody"]
        DB8["engine_results"]
        DB9["historical_metrics"]
    end

    A6 -.-> DB
    AGG -.-> DB
    IOC_OUT -.-> DB
    ENRICH -.-> DB
    R_OUT -.-> DB
    DASH -.-> DB
```

## Data Flow Diagram

```mermaid
sequenceDiagram
    participant User
    participant Streamlit as Streamlit UI
    participant Acq as Acquisition Module
    participant V3 as Volatility 3
    participant YARA as YARA Engine
    participant Detect as Threat Detection
    participant Agg as Aggregation Engine
    participant IOC as IOC Engine
    participant Intel as Threat Intel
    participant MITRE as MITRE Mapper
    participant Report as Report Engine
    participant DB as SQLite DB

    User->>Streamlit: Upload Memory Dump
    Streamlit->>Acq: acquire_memory()
    Acq->>Acq: Calculate SHA256
    Acq->>Acq: Detect Format
    Acq->>Acq: Validate Dump
    Acq->>DB: Store Metadata
    Acq-->>Streamlit: snapshot_id

    User->>Streamlit: Start Analysis
    Streamlit->>V3: analyze()
    V3->>V3: Run Plugins (pslist, malfind, etc.)
    V3-->>Streamlit: Engine Results

    Streamlit->>YARA: scan_memory()
    YARA->>YARA: Match Rules
    YARA-->>Streamlit: YARA Matches

    Streamlit->>Detect: analyze_processes()
    Detect->>Detect: Detect Techniques
    Detect-->>Streamlit: Detections

    Streamlit->>Agg: correlate_findings()
    Agg->>Agg: Weighted Scoring
    Agg->>Agg: Confidence Calculation
    Agg-->>Streamlit: Aggregated Results

    Streamlit->>IOC: extract_all_iocs()
    IOC->>IOC: Pattern Matching
    IOC-->>Streamlit: IOC List

    Streamlit->>Intel: enrich_ioc()
    Intel->>Intel: Query VT/MISP/OTX
    Intel-->>Streamlit: Enriched IOCs

    Streamlit->>MITRE: map_detection()
    MITRE->>MITRE: Technique Mapping
    MITRE-->>Streamlit: ATT&CK Map

    Streamlit->>Report: generate_report()
    Report->>Report: Build PDF/HTML/JSON
    Report-->>Streamlit: Report Files

    Streamlit->>DB: Store Results
    Streamlit-->>User: Display Dashboard
```

## Engine Correlation Flow

```mermaid
flowchart LR
    subgraph INPUT["Raw Findings"]
        F1["Volatility:<br/>svchost.exe PID 1234<br/>suspicious parent"]
        F2["YARA:<br/>CobaltStrike rule match<br/>in PID 1234"]
        F3["Heuristic:<br/>Unexpected network<br/>connection from PID 1234"]
        F4["Anomaly:<br/>Memory injection<br/>pattern in PID 1234"]
    end

    subgraph CORRELATE["Correlation Engine"]
        MERGE["Target Merge:<br/>PID 1234 / svchost.exe"]
        
        MERGE --> VOTE1["Volatility Vote:<br/>Signature type<br/>Confidence: 75"]
        MERGE --> VOTE2["YARA Vote:<br/>Signature type<br/>Confidence: 95"]
        MERGE --> VOTE3["Heuristic Vote:<br/>Heuristic type<br/>Confidence: 80"]
        MERGE --> VOTE4["Anomaly Vote:<br/>Anomaly type<br/>Confidence: 70"]
    end

    subgraph SCORE["Scoring"]
        VOTE1 --> W1["75 × 1.0 = 75"]
        VOTE2 --> W2["95 × 1.0 = 95"]
        VOTE3 --> W3["80 × 0.7 = 56"]
        VOTE4 --> W4["70 × 0.5 = 35"]
        
        W1 --> SUM["Weighted Sum: 261<br/>Total Weight: 3.2<br/>Base Score: 81.6"]
        W2 --> SUM
        W3 --> SUM
        W4 --> SUM
        
        SUM --> BONUS1["Engine Confirmation:<br/>4/4 engines = +20"]
        SUM --> BONUS2["Diversity Bonus:<br/>2 types = +10"]
        
        BONUS1 --> FINAL["Final Score: 111.6<br/>Capped: 100"]
        BONUS2 --> FINAL
    end

    subgraph VERDICT["Verdict"]
        FINAL --> V["Confidence: 100%<br/>Engines: 4/4<br/>Verdict: CONFIRMED_MALICIOUS"]
    end
```

## Snapshot Comparison Flow

```mermaid
flowchart TB
    subgraph BASE["Baseline Snapshot"]
        B1["Processes:<br/>explorer.exe, lsass.exe,<br/>svchost.exe × 8, csrss.exe"]
        B2["Services:<br/>Dnscache, Dhcp,<br/>Windows Update"]
        B3["Network:<br/>Local connections only"]
        B4["DLLs:<br/>System32 libraries"]
    end

    subgraph SNAPSHOT["Current Snapshot"]
        S1["Processes:<br/>explorer.exe, lsass.exe,<br/>svchost.exe × 9, csrss.exe,<br/>cmd.exe, powershell.exe"]
        S2["Services:<br/>Dnscache, Dhcp,<br/>Windows Update,<br/>SuspiciousSvc"]
        S3["Network:<br/>Local + 192.168.100.50:4444"]
        S4["DLLs:<br/>System32 + temp\susp.dll"]
    end

    BASE --> COMPARE["Snapshot<br/>Comparison<br/>Engine"]
    SNAPSHOT --> COMPARE

    COMPARE --> DIFF1["🔴 NEW PROCESSES:<br/>cmd.exe, powershell.exe"]
    COMPARE --> DIFF2["🟡 NEW SERVICE:<br/>SuspiciousSvc (auto-start)"]
    COMPARE --> DIFF3["🔴 NEW CONNECTION:<br/>192.168.100.50:4444<br/>(External, Suspicious Port)"]
    COMPARE --> DIFF4["🔴 NEW DLL:<br/>temp\susp.dll"]
    COMPARE --> DIFF5["🟢 MISSING: None"]
    COMPARE --> DIFF6["🔴 HIDDEN:<br/>Potential svchost.exe<br/>duplicate"]

    DIFF1 --> SCORE["Threat Delta<br/>Score Calculation"]
    DIFF2 --> SCORE
    DIFF3 --> SCORE
    DIFF4 --> SCORE
    DIFF5 --> SCORE
    DIFF6 --> SCORE

    SCORE --> RESULT["Delta Score: 72.5<br/>Risk Level: HIGH<br/>Recommendation:<br/>Immediate Investigation"]
```

## Database Schema Overview

```mermaid
erDiagram
    SNAPSHOTS ||--o{ THREAT_EVENTS : contains
    SNAPSHOTS ||--o{ TIMELINE_EVENTS : contains
    SNAPSHOTS ||--o{ INVESTIGATIONS : has
    THREAT_EVENTS ||--o{ IOCS : generates
    INVESTIGATIONS ||--o{ REPORTS : produces
    SNAPSHOTS ||--o{ CHAIN_OF_CUSTODY : tracks
    SNAPSHOTS ||--o{ ENGINE_RESULTS : stores

    SNAPSHOTS {
        int id PK
        string name
        string file_path
        int file_size
        string sha256_hash
        string acquisition_tool
        string acquisition_format
        json system_info
        boolean is_baseline
        datetime created_at
        json chain_of_custody
    }

    THREAT_EVENTS {
        int id PK
        int snapshot_id FK
        string event_type
        string severity
        float confidence
        string title
        string process_name
        int process_id
        string detection_engine
        string mitre_technique
        json indicators
        float score
    }

    IOCS {
        int id PK
        int threat_event_id FK
        string ioc_type
        text value
        float confidence
        json enrichment_data
        json virustotal_data
        json misp_data
        json otx_data
    }

    TIMELINE_EVENTS {
        int id PK
        int snapshot_id FK
        datetime event_time
        string event_type
        string category
        string process_name
        int process_id
        json details
        string significance
    }

    INVESTIGATIONS {
        int id PK
        string title
        string case_number
        string status
        int snapshot_id FK
        int baseline_snapshot_id FK
        string analyst
        datetime started_at
    }

    REPORTS {
        int id PK
        int investigation_id FK
        string report_type
        string file_path
        float threat_score
        float confidence_score
        string executive_verdict
        int total_threats
    }

    CHAIN_OF_CUSTODY {
        int id PK
        int snapshot_id FK
        string action
        string performed_by
        datetime performed_at
        string hash_before
        string hash_after
        string verification_status
    }
```