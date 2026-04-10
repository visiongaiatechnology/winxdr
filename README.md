# 👁️ VGT Malware Hunter X-Ray — Community Edition

[![License](https://img.shields.io/badge/License-AGPLv3-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=for-the-badge&logo=windows)](https://microsoft.com/windows)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell)](https://microsoft.com/powershell)
[![Edition](https://img.shields.io/badge/Edition-Community_Lite-orange?style=for-the-badge)](#)
[![Type](https://img.shields.io/badge/Type-Behavioral_EDR-red?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-STABLE-brightgreen?style=for-the-badge)](#)
[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)
[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://www.paypal.com/paypalme/dergoldenelotus)

> *"Signatures are dead. Watch the behavior."*
> *AGPLv3 — For Humans, not for SaaS Corporations.*

---

## ⚠️ DISCLAIMER: EXPERIMENTAL R&D PROJECT

This project is a **Proof of Concept (PoC)** Windows Security Layer. It is **not** a Enterprise Plugin, and can be unsafe.

**Do not use this in critical production environments.** For enterprise-grade kernel-level protection, we recommend established Solutions.


## ⚠️ Community Lite Edition

> **This is the Community Lite Edition** — the open-source foundation of our internal EDR architecture, released to give Blue Teams a powerful behavioral detection baseline.
>
> The full **VGT MHX Enterprise Tier** — including SeDebugPrivilege Token Injection, Memory God-Mode, Zero-Trust Path Validation, and advanced heuristics — is deployed internally on our TIER-5 Sovereign systems and is **not publicly available.**
>
> This release is intentional. The foundation is real. The ceiling is yours to build.

---

## 🚨 Why Traditional AV Is Dead

Traditional antivirus scanners rely on static file signatures. Against modern fileless malware and Living off the Land (LotL) attacks, they are completely blind.

| Traditional AV | VGT MHX Community Edition |
|---|---|
| ❌ Static file signatures | ✅ Pure behavioral analysis |
| ❌ Blind to fileless attacks | ✅ Detects in-memory execution |
| ❌ No process lineage tracking | ✅ Strict parent-child enforcement |
| ❌ No LotL detection | ✅ Live argument monitoring |
| ❌ No C2 network correlation | ✅ Real-time threat feed matching |
| ❌ Visible, bypassable | ✅ Runs as invisible background daemon |

---
<img width="2816" height="1536" alt="Gemini_Generated_Image_ks7khwks7khwks7k" src="https://github.com/user-attachments/assets/2f835894-05c1-47ea-90a8-f8ca37650462" />



## 🧬 The Three Core Engines

### Engine 1 — Strict Lineage Tracking
Detects **Process Hollowing** and **Injection** in real-time by enforcing parent-child process rules.

```
winword.exe spawns cmd.exe
    → Lineage rule violated
    → Process terminated before payload executes
    → Incident logged to Windows Event Log
```

Legitimate processes have predictable parent relationships. Malware breaks these rules. MHX enforces them.

### Engine 2 — Living off the Land (LotL) Prevention
Monitors process arguments live. Encoded or obfuscated PowerShell commands outside of admin sessions are terminated immediately.

```
powershell.exe -enc <base64payload>
    → LotL signature detected
    → Process terminated
    → Toast notification fired
```

Attackers love using built-in Windows tools — `powershell.exe`, `cmd.exe`, `wscript.exe` — to avoid detection. MHX watches the arguments, not just the binary.

### Engine 3 — Zero-Trust Network Monitor
Continuously correlates all established TCP connections against global C2 threat intelligence feeds. If a process phones home to a known C2 server, the socket owner is killed.

```
chrome.exe → ESTABLISHED → 185.220.101.47 (known C2)
    → Process terminated
    → C2 connection severed
    → Incident logged
```

Feeds updated every 12 hours automatically via background job.

---

## 🏛️ Architecture

```
Windows System Timer (3s heartbeat)
    ↓
ENGINE 1: Lineage Tracking
    → Get-CimInstance Win32_Process
    → Validate parent-child relationships
    → Terminate on violation → Log → Toast
    ↓
ENGINE 2: LotL Detection
    → Get-Process with CommandLine filter
    → Match suspicious argument patterns
    → Terminate on match → Log → Toast
    ↓
ENGINE 3: C2 Network Monitor
    → Get-NetTCPConnection (ESTABLISHED)
    → Cross-reference against ThreatIPs hashtable
    → Terminate on match → Log → Toast
    ↓
BACKGROUND JOB: TI Sync (every 12h)
    → Feodo Tracker
    → Spamhaus DROP
    → [Community: add more feeds]
    ↓
SYSTEM TRAY: Persistent daemon
    → Invisible mode (hidden window)
    → Right-click → View Incident Log
    → Right-click → Exit
```

---

## 🖥️ System Tray Integration

MHX runs completely invisible. No console window. No taskbar entry. Only a system tray icon confirms it is active.

```
System Tray Icon → Right-click:
    ├── View Incident Log    ← Opens incidents.log in Notepad
    ├── ─────────────────
    └── Exit MHX            ← Clean shutdown
```

**Toast Notifications** fire immediately on any detection:

```
⚠️ MHX: Lineage Breach
Process cmd.exe terminated (Invalid Parent: winword.exe)

⚠️ MHX: LotL Activity  
powershell.exe terminated due to suspicious arguments.

⚠️ MHX: C2 Connection Blocked
Target IP: 185.220.101.47
```

---

## 🚀 Installation

### Requirements
- Windows 10 / 11
- PowerShell 5.1+
- Administrator privileges

### Setup

```powershell
# 1. Clone or download
git clone https://github.com/visiongaiatechnology/winxdr.git
cd winxdr

# 2. Run as Administrator (right-click → Run as Administrator)
# Or via PowerShell:
Set-ExecutionPolicy Bypass -Scope Process -Force
.\xdr-communitylite.ps1
```

MHX auto-elevates if not already running as Administrator. The console window hides itself automatically. Check your system tray for the active icon.

### Incident Logs

All detections are written to:
```
C:\ProgramData\MHX_Community\incidents.log
```

And to the Windows Event Log under source `MHX-Community`.

---

## 🔧 Configuration & Contribution

The Community Edition is designed to be extended. Three key areas for contributors:

### 1. Extend the Lineage Matrix
```powershell
$Script:StrictLineage = @{
    "cmd.exe"        = @("explorer.exe", "powershell.exe")
    # Add your rules:
    "powershell.exe" = @("explorer.exe", "services.exe", "svchost.exe")
    "wscript.exe"    = @("explorer.exe")
    "mshta.exe"      = @("explorer.exe")
}
```

### 2. Add Threat Intelligence Feeds
```powershell
$feeds = @(
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://www.spamhaus.org/drop/drop.txt",
    # Add your feeds here:
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://cinsscore.com/list/ci-badguys.txt"
)
```

### 3. Extend the Network Whitelist
```powershell
$Script:WhitelistedNetworkProcs = @(
    "chrome", "firefox", "msedge", "svchost",
    # Add trusted processes for your environment:
    "Teams", "Slack", "zoom"
)
```

---

## 📦 System Specs

```
RUNTIME           PowerShell 5.1+ (native Windows)
DETECTION         Pure behavioral — no signatures
HEARTBEAT         3 seconds
TI_SYNC           Every 12 hours (background job)
VISIBILITY        Zero — hidden window, system tray only
LOGGING           Windows Event Log + flat file
INCIDENT_PATH     C:\ProgramData\MHX_Community\incidents.log
ELEVATION         Auto-elevates if not admin
OVERHEAD          Minimal — timer-based, no continuous polling
```

---

## 🔒 What's NOT in This Edition

This Community Lite Edition intentionally excludes the following features from our internal Enterprise build:

| Feature | Community Edition | Enterprise Tier |
|---|---|---|
| Behavioral Engine | ✅ Core 3 engines | ✅ Extended heuristics |
| Lineage Tracking | ✅ Basic ruleset | ✅ Full Windows process tree |
| LotL Detection | ✅ Keyword matching | ✅ Semantic analysis |
| C2 Detection | ✅ 2 feeds | ✅ 10+ feeds incl. APT trackers |
| SeDebugPrivilege Injection | ❌ | ✅ God-Mode process access |
| Memory Analysis | ❌ | ✅ In-memory scan |
| Zero-Trust Path Validation | ❌ | ✅ Full executable path trust chain |
| DLL Injection Detection | ❌ | ✅ Module path analysis |

> The Enterprise Tier runs on our TIER-5 Sovereign systems. It is not publicly available.

---

## 🤝 Contributing

This is a community project. Pull requests are welcome — especially:

- New lineage rules for common attack vectors
- Additional threat intelligence feed integrations
- LotL keyword pattern improvements
- Documentation and test cases

For security vulnerability reports, please contact: `security@visiongaiatechnology.de`

Licensed under **AGPLv3** — *"For Humans, not for SaaS Corporations."*

---

## 🔗 VGT Windows Security Ecosystem

| Tool | Purpose |
|---|---|
| 👁️ **VGT MHX Community Edition** | Behavioral EDR daemon — watches process behavior |
| 🔍 **[VGT Civilian Checker](https://github.com/visiongaiatechnology/Winsyssec)** | Security posture audit — shows WHERE you are vulnerable |
| 🔥 **[VGT Windows Firewall Burner](https://github.com/visiongaiatechnology/vgt-windows-burner)** | 280,000+ APT IPs burned into Windows Firewall |

> **Recommended stack:** Civilian Checker to audit → Firewall Burner to block known threats → MHX to watch behavior.

---

## ☕ Support the Project

VGT MHX Community Edition is free. If it catches something on your system:

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://www.paypal.com/paypalme/dergoldenelotus)

---

## 🏢 Built by VisionGaia Technology

[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

VisionGaia Technology builds enterprise-grade security and AI tooling — engineered to the DIAMANT VGT SUPREME standard.

> *"We open-sourced the foundation. The ceiling is yours to build."*

---

*Version 1.0 (Community Lite Edition) — VGT Malware Hunter X-Ray // Behavioral EDR Daemon*
