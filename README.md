# 🔬 VGT Malware Hunter X-Ray (MHX) — Experimental Windows EDR (R&D Project)

[![License: AGPLv3](https://img.shields.io/badge/License_(MHX)-AGPLv3-green?style=for-the-badge)](LICENSE)
[![License: MIT](https://img.shields.io/badge/License_(C%23_Core)-MIT-blue?style=for-the-badge)](LICENSE-MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11-0078D6?style=for-the-badge&logo=windows)](https://microsoft.com)
[![Version](https://img.shields.io/badge/Version-3.1_PLATIN-brightgreen?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-R%26D_/_Experimental-yellow?style=for-the-badge)](#)
[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

> *AGPLv3 (MHX Core) / MIT (C# Native Engine) — Open Source. Open Knowledge.*

---

## ⚠️ DISCLAIMER: EXPERIMENTAL R&D PROJECT

VGT Malware Hunter X-Ray is a **Proof of Concept (PoC)** exploring behavioral endpoint detection using PowerShell, .NET/C# interop, and Windows native APIs. It is **not** a replacement for enterprise EDR solutions.

**Architectural limitations to be aware of:**

- Runs as a PowerShell daemon — subject to PowerShell execution constraints and startup latency
- Detection runs on a 2-second polling interval — real-time kernel-level hooks are not implemented
- Process termination via `Stop-Process` can be circumvented by sufficiently privileged malware
- The AMSI integrity check relies on known patch signatures — novel bypass techniques may go undetected

**For production environments**, we recommend established solutions like Microsoft Defender for Endpoint, CrowdStrike, or SentinelOne alongside this tool — not instead of them.

---

## 💎 Support the Project

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://www.paypal.com/paypalme/dergoldenelotus)

| Method | Address |
|---|---|
| **PayPal** | [paypal.me/dergoldenelotus](https://www.paypal.com/paypalme/dergoldenelotus) |
| **Bitcoin** | `bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm` |
| **ETH / USDT (ERC-20)** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |

---

## 🔬 What is VGT MHX?

VGT Malware Hunter X-Ray started as an experiment: **Can we build a meaningful behavioral EDR daemon using only PowerShell + C# interop, running as a background system tray process?**

Version 3.1 is the current peak of this exploration. It combines four detection engines operating in a unified 2-second heartbeat loop — process lineage validation, command-line heuristics, network threat intelligence, and native AMSI memory integrity scanning via `ReadProcessMemory`.

```
The goal was never to replace kernel-level EDR.
The goal was to understand what is possible in userspace — and where the ceiling is.
```

---

## 🛡️ Detection Engines

### Engine 1 — Process Lineage Validation
Enforces strict parent-child process relationships for critical system processes. A `lsass.exe` spawned by anything other than `wininit.exe` is terminated immediately.

### Engine 2 — KillerDom Command-Line Heuristics
Compiled regex signatures scan process command-line arguments for known malicious patterns: obfuscated PowerShell, Base64-encoded payloads, JNDI injection strings, cryptocurrency miners, and Living-off-the-Land (LotL) abuse patterns.

### Engine 3 — Network & Threat Intelligence
Monitors established TCP connections against live threat feeds (Feodo Tracker, Spamhaus DROP/EDROP, CINS Score). Untrusted processes with external connections that fail path and whitelist validation are terminated. Masquerading detection via path verification.

### Engine 4 — AMSI Memory Integrity Scanner
Uses `ReadProcessMemory` via P/Invoke to inspect the in-memory bytes of `AmsiScanBuffer` in all high-risk LotL processes. Detects known AMSI bypass techniques at the memory level:

| Byte Signature | Technique |
|---|---|
| `B8 57 00 07 80` | `mov eax, 0x80070057` — returns `E_INVALIDARG` |
| `EB` / `E9` | Unconditional JMP — hooks/redirects scan function |
| `C3` | `RET` — immediate return, skips scan entirely |
| `31 C0 C3` | `xor eax, eax; ret` — returns clean result without scanning |

---

## 🗺️ MITRE ATT&CK Coverage

| Technique ID | Technique Name | Engine |
|---|---|---|
| **T1055** | Process Injection | Engine 4 (AMSI Memory Scan) |
| **T1548.002** | Abuse Elevation Control — Bypass UAC | Engine 1 (Lineage) |
| **T1134** | Access Token Manipulation | Engine 1 (Lineage) |
| **T1036** | Masquerading | Engine 3 (Path Verification) |
| **T1036.005** | Match Legitimate Name or Location | Engine 3 |
| **T1059.001** | Command & Scripting — PowerShell | Engine 2 (KillerDom) |
| **T1059.003** | Command & Scripting — Windows Command Shell | Engine 2 (KillerDom) |
| **T1027** | Obfuscated Files or Information | Engine 2 (Base64/Hex Detection) |
| **T1027.010** | Command Obfuscation | Engine 2 (KillerDom) |
| **T1218** | System Binary Proxy Execution (LotL) | Engine 2 (KillerDom) |
| **T1218.005** | Mshta | Engine 2 |
| **T1218.010** | Regsvr32 | Engine 2 |
| **T1218.011** | Rundll32 | Engine 2 |
| **T1105** | Ingress Tool Transfer (certutil/bitsadmin) | Engine 2 (KillerDom) |
| **T1071** | Application Layer Protocol (C2) | Engine 3 (TI Feeds) |
| **T1071.001** | Web Protocols — C2 Beaconing | Engine 3 |
| **T1562.001** | Impair Defenses — Disable or Modify Tools | Engine 4 (AMSI Patch) |
| **T1055.001** | DLL Injection | Engine 3 (Temp DLL Detection) |
| **T1547.001** | Boot/Logon Autostart — Registry Run Keys | Scheduled Task Persistence |
| **T1078** | Valid Accounts (Credential Theft via LSASS) | Engine 1 (lsass Lineage Guard) |

---

## ⚙️ Installation & Configuration

### Requirements

- Windows 10 / Windows 11
- PowerShell 5.1+
- Administrator privileges (required for `SeDebugPrivilege` and `ReadProcessMemory`)
- .NET Framework 4.x (pre-installed on all modern Windows)

### Step 1 — Configure your Whitelist

> **⚠️ Do this before running. The network engine will terminate untrusted processes with external connections.**

Open the script and locate the `VGT CONFIGURATION` section:

```powershell
# --- VGT CONFIGURATION ---
$Script:WhitelistedNetworkProcs = @(
    "chrome", "firefox", "msedge",   # Browsers
    "VSCodium", "code",               # Editors
    "ollama",                         # Local AI
    "svchost", "MpDefenderCoreService", "MsMpEng",  # System
    "Discord", "Spotify", "Telegram"  # Apps
    # ADD YOUR OWN SOFTWARE HERE
)
```

Add any process names you want to whitelist. Use the exact process name as shown in Task Manager (without `.exe`).

### Step 2 — Configure Threat Intelligence Feeds

Locate the `THREAT INTELLIGENCE FUNCTIONS` section and add or replace feed URLs as needed:

```powershell
$feeds = @(
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://www.spamhaus.org/drop/edrop.txt",
    "https://cinsscore.com/list/ci-badguys.txt"
    # ADD YOUR OWN THREAT INTEL FEEDS HERE (plain IP list format)
)
```

Feeds are synced every 4 hours in a background job. Any feed returning plain-text IPv4 addresses (one per line) is supported.

### Step 3 — Run

```powershell
# Right-click → Run with PowerShell (as Administrator)
# Or from an elevated terminal:
powershell.exe -ExecutionPolicy Bypass -File .\vgt-mhx.ps1
```

The daemon will:
1. Auto-elevate to Administrator if not already elevated
2. Hide its own console window
3. Register a Scheduled Task (`VGT-MHX`) for autostart on login
4. Appear in the system tray
5. Start the 4-hour TI feed sync immediately

### System Tray Controls

Right-click the tray icon to:
- **Open Incident Log** — view all detections in Notepad
- **Stop Hunter** — cleanly shut down the daemon

---

## 📋 Incident Log

All detections are written to:
```
C:\ProgramData\VGT_Omega\incidents.log
```

And to the Windows Event Log under:
```
Source: VGT-MHX
Log:    Application
```

| Event ID | Meaning |
|---|---|
| `202` | Untrusted process with external network connection |
| `203` | Masquerading detected — known process name, wrong path |
| `204` | Suspicious DLL loaded from Temp directory |
| `301` | Critical process lineage breach |
| `666` | KillerDom strike — malicious command-line detected |
| `999` | AMSI memory patch detected and process neutralized |

---

## 📜 License

This project uses a dual-license model:

| Component | License |
|---|---|
| **MHX Core** (PowerShell daemon, detection engines, TI sync) | **AGPLv3** |
| **C# Native Engine** (`VGT.Security.XDR` — `Win32TokenXDR`, `MemoryScanner`) | **MIT** |

The C# core is MIT-licensed to allow embedding in other projects without AGPLv3 copyleft obligations.

---

## 📚 Learning Resources & Further Reading

This project explores the boundaries of what PowerShell + P/Invoke can do for endpoint security. If you want to go deeper into the concepts implemented here:

- **AMSI Internals:** [Microsoft AMSI Documentation](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- **Process Injection Techniques:** [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
- **Living-off-the-Land Binaries:** [LOLBAS Project](https://lolbas-project.github.io/)
- **Threat Intelligence Feeds:** [abuse.ch](https://abuse.ch/), [Spamhaus](https://www.spamhaus.org/)
- **Next Steps (Kernel-Level):** eBPF, Windows ETW (Event Tracing for Windows), kernel callbacks via `PsSetCreateProcessNotifyRoutine`

---

## 🔗 VGT Windows Defense Ecosystem

| Tool | Type | Purpose |
|---|---|---|
| 🔬 **VGT MHX** | **R&D / Experimental** | Behavioral EDR daemon — AMSI, Lineage, Network, KillerDom |
| 🔥 **[VGT Windows Firewall Burner](https://github.com/visiongaiatechnology/vgt-windows-burner)** | **Preventive** | 280,000+ APT IPs blocked in native Windows Firewall |
| 🔍 **[VGT Civilian Checker](https://github.com/visiongaiatechnology/Winsyssec)** | **Audit** | Windows security posture assessment |
| ⚔️ **[VGT Auto-Punisher](https://github.com/visiongaiatechnology/vgt-auto-punisher)** | **Linux R&D** | Experimental userspace IDS for Linux servers |

---

## 🏢 About VisionGaia Technology

[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

VisionGaia Technology is an R&D collective exploring experimental architectures, AI integration, and cybersecurity paradigms. We build to learn, we break things to understand them, and we share the results.

---

*VGT Malware Hunter X-Ray v3.1 PLATIN — Experimental Windows EDR // Process Lineage + KillerDom + Network TI + AMSI Memory Integrity*
