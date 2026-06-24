# 0xAnalyst/WebshellDetection-WMI-Yara

ASPX webshell detection using WMI permanent event subscriptions, YARA rules, Sigma rules, and PowerShell behavioral monitors. Covers static file scanning, process chain analysis, memory scanning, network telemetry, and SIEM correlation.

![Threat Hunting](https://img.shields.io/badge/purpose-threat%20hunting-blue)
![Platform](https://img.shields.io/badge/platform-IIS%20%2F%20Windows-lightgrey)
![YARA](https://img.shields.io/badge/rules-YARA-green)
![Sigma](https://img.shields.io/badge/rules-Sigma-blue)

---

## Repository structure

```
WebshellDetection-WMI-Yara/
├── README.md
├── index.html                         # GitHub Pages card view
│
├── existing/                          # Original detection files
│   ├── WMIWebShellmonitor.ps1
│   └── rules.yar
│
├── yara/                              # Static YARA rules
│   ├── aspx_dinvoke.yar
│   ├── aspx_assembly_load.yar
│   ├── aspx_etw_amsi_patch.yar
│   ├── aspx_syscall_stub.yar
│   └── aspx_roslyn_eval.yar
│
├── wmi/                               # WMI behavioral monitors
│   ├── WMIWebShellmonitor.ps1         # Enhanced original
│   ├── WMIProcessChainMonitor.ps1
│   └── WMINetworkMonitor.ps1
│
├── process-chain/                     # Process lineage rules
│   ├── w3wp_child_process.yar
│   ├── lolbin_from_iis.yar
│   └── impersonation_from_iis.yar
│
├── memory/                            # In-memory scanning rules
│   ├── reflective_pe_memory.yar
│   └── ntdll_unhook_memory.yar
│
├── network/                           # Network-based detection
│   ├── doh_c2_detection.yar
│   └── websocket_persistence.yar
│
└── sigma/                             # Sigma rules for SIEM
    ├── webshell_process_chain.yml
    ├── iis_outbound_connection.yml
    └── etw_amsi_tamper.yml
```

---

## Detection layers

| Layer | Method | Files | What it catches |
|-------|--------|-------|-----------------|
| Static | YARA file scan | `yara/` | Dynamic P/Invoke, Assembly.Load, ETW/AMSI patches, syscall stubs, Roslyn eval |
| Behavioral | WMI event subscription | `wmi/` | File drops, anomalous child processes, unexpected outbound connections |
| Process chain | YARA + Sysmon | `process-chain/` | w3wp.exe spawning shells, LOLBin abuse, token impersonation |
| Memory | YARA -p (process scan) | `memory/` | Reflective PE loads, ntdll unhooking, MZ in non-image memory |
| Network | YARA + NetFlow | `network/` | DoH C2 traffic, long-lived WebSocket from IIS |
| SIEM | Sigma rules | `sigma/` | Cross-event correlation: process chain + network + tamper in Splunk/Elastic/Sentinel |

---

## YARA rules

### Static file rules — `yara/`

| Rule file | Detects | ATT&CK |
|-----------|---------|--------|
| `aspx_dinvoke.yar` | Dynamic P/Invoke via GetProcAddress, no DllImport | T1106 · T1027 |
| `aspx_assembly_load.yar` | Assembly.Load() + XOR decode loop | T1027 · T1620 |
| `aspx_etw_amsi_patch.yar` | EtwEventWrite / AmsiScanBuffer byte-patch sequences | T1562.001 · T1562.006 |
| `aspx_syscall_stub.yar` | Direct syscall stubs, Heaven's Gate patterns | T1055 · T1562.006 |
| `aspx_roslyn_eval.yar` | CSharpScript.EvaluateAsync, Microsoft.CodeAnalysis imports | T1027.010 |

### Process chain rules — `process-chain/`

| Rule file | Detects | ATT&CK |
|-----------|---------|--------|
| `w3wp_child_process.yar` | cmd.exe / powershell.exe / wscript.exe as w3wp.exe children | T1059.001 · T1059.003 |
| `lolbin_from_iis.yar` | MSBuild, regsvr32, mshta, certutil, bitsadmin from IIS | T1127.001 · T1218 |
| `impersonation_from_iis.yar` | Token impersonation, CreateProcessAsUser from IIS context | T1134.001 · T1548.002 |

### Memory rules — `memory/`

| Rule file | Detects | ATT&CK |
|-----------|---------|--------|
| `reflective_pe_memory.yar` | MZ/PE headers in non-image memory regions of w3wp.exe | T1620 · T1055 |
| `ntdll_unhook_memory.yar` | Two ntdll base addresses in one process (fresh-mapped copy) | T1562.001 · T1055 |

### Network rules — `network/`

| Rule file | Detects | ATT&CK |
|-----------|---------|--------|
| `doh_c2_detection.yar` | High-entropy DNS names in DoH queries over port 443 | T1071.004 |
| `websocket_persistence.yar` | Long-lived WebSocket upgrades from w3wp.exe to external hosts | T1071.001 |

---

## WMI monitors — `wmi/`

| Script | Trigger | Alert |
|--------|---------|-------|
| `WMIWebShellmonitor.ps1` | New ASP/ASPX file in web root | YARA match → log + optional webhook |
| `WMIProcessChainMonitor.ps1` | Child process creation from w3wp.exe | Anomalous child → log + alert |
| `WMINetworkMonitor.ps1` | Outbound network connection from IIS PID | External connection → log + alert |

### Setup

```powershell
# Set your paths
$YaraPath    = "C:\tools\yara\yara64.exe"
$RulesPath   = "C:\WebshellDetection\yara\"
$WebRoot     = "C:\inetpub\wwwroot"
$LogFile     = "C:\logs\webshell_detections.txt"
$WebhookUrl  = "https://hooks.slack.com/services/YOUR/WEBHOOK"  # optional

# Run the monitor (run as Administrator)
.\wmi\WMIWebShellmonitor.ps1
```

---

## Sigma rules — `sigma/`

| Rule file | Log source | Correlates | SIEM targets |
|-----------|-----------|------------|--------------|
| `webshell_process_chain.yml` | Sysmon EID 1 | w3wp.exe → shell/LOLBin spawn | Splunk, Elastic, Sentinel |
| `iis_outbound_connection.yml` | Sysmon EID 3 | w3wp.exe → external outbound | Splunk, Elastic, Sentinel |
| `etw_amsi_tamper.yml` | Security EID 4656/4657 | AMSI registry access + ETW session modification | Splunk, Elastic, Sentinel |

### Convert Sigma to your SIEM

```bash
# Splunk
sigma convert -t splunk sigma/webshell_process_chain.yml

# Elastic
sigma convert -t eql sigma/iis_outbound_connection.yml

# Microsoft Sentinel
sigma convert -t kusto sigma/etw_amsi_tamper.yml
```

---

## Coverage map vs webshells repo

| Webshell technique | Detection method | Rule |
|-------------------|-----------------|------|
| `CreateProcess_Dynamic.aspx` | Static YARA | `aspx_dinvoke.yar` |
| `WinExec_Syscall.aspx` | Static YARA | `aspx_syscall_stub.yar` |
| `ShellExecuteEx_Runas.aspx` | Process chain | `impersonation_from_iis.yar` |
| `NtCreateProcess_Unhook.aspx` | Memory scan | `ntdll_unhook_memory.yar` |
| `CreateProcessAsUser_Impersonate.aspx` | Process chain | `impersonation_from_iis.yar` |
| `WMI_Com_ETW_AMSI_Patch.aspx` | Static YARA | `aspx_etw_amsi_patch.yar` |
| `InMemory_Assembly_XOR.aspx` | Static YARA | `aspx_assembly_load.yar` |
| `COMShell.aspx` | Behavioral WMI | `WMIProcessChainMonitor.ps1` |
| `DoHShell.aspx` | Network YARA | `doh_c2_detection.yar` |
| `WebSocketShell.aspx` | Network YARA | `websocket_persistence.yar` |
| `ETWPatchShell.aspx` | Static YARA | `aspx_etw_amsi_patch.yar` |
| `ReflectivePEShell.aspx` | Memory scan | `reflective_pe_memory.yar` |

---

## References

- [MITRE ATT&CK — Web Shell T1505.003](https://attack.mitre.org/techniques/T1505/003/)
- [Sigma Rules — SigmaHQ](https://github.com/SigmaHQ/sigma)
- [YARA Documentation](https://yara.readthedocs.io/)
- [NSA/CISA Web Shell Advisory](https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF)
- [Sysmon Configuration — SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)

---

> **Disclaimer:** All detection tools are for authorized threat hunting and security monitoring in environments you own or have explicit permission to monitor.
