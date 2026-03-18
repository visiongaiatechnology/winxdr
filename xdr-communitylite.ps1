# ==============================================================================
# VISIONGAIA TECHNOLOGY: MALWARE HUNTER X-RAY (COMMUNITY EDITION v1.0)
# REPOSITORY: Open Source EDR / Behavioral Analysis Daemon
# ZWECK: Detektion von Lineage-Breaches, LotL & C2-Beaconing
# ==============================================================================
# DISCLAIMER: This is the Community Edition. Advanced Heuristics, SeDebugPrivilege
# Injection, and Zero-Trust Pathing are reserved for the VGT Enterprise Tier.
# ==============================================================================

$ErrorActionPreference = "SilentlyContinue"

# --- ELEVATION & STEALTH ---
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$Win32ShowWindow = Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);' -Name "Win32ShowWindow" -Namespace "VGT.Security" -PassThru
$Win32ShowWindow::ShowWindow((Get-Process -Id $PID).MainWindowHandle, 0) | Out-Null

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- INFRASTRUCTURE ---
$Script:EventSource = "MHX-Community"
$Script:IncidentLog = "$env:ProgramData\MHX_Community\incidents.log"

if (-not (Test-Path "$env:ProgramData\MHX_Community")) { New-Item -Path "$env:ProgramData\MHX_Community" -ItemType Directory -Force | Out-Null }
if (-not [System.Diagnostics.EventLog]::SourceExists($Script:EventSource)) {
    try { New-EventLog -LogName "Application" -Source $Script:EventSource -ErrorAction Stop } catch {}
}

function Log-Event([int]$Id, [string]$Message) {
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Stamp] ID:$Id - $Message" | Out-File -FilePath $Script:IncidentLog -Append
    Write-EventLog -LogName "Application" -Source $Script:EventSource -EventId $Id -EntryType "Warning" -Message $Message -ErrorAction SilentlyContinue
}

# --- COMMUNITY CONFIGURATION (TODO FOR CONTRIBUTORS) ---

# [1] NETWORK WHITELIST
$Script:WhitelistedNetworkProcs = @("chrome", "firefox", "msedge", "svchost")

# [2] SUSPICIOUS LOTL KEYWORDS
$Script:SuspiciousKeywords = @("-enc ", "bypass", "hidden", "Invoke-WebRequest")

# [3] LINEAGE ENGINE (Community: Add more parent-child rules here!)
$Script:StrictLineage = @{
    # Example: cmd.exe usually spawns from explorer, not from word.exe
    "cmd.exe" = @("explorer.exe", "powershell.exe")
}

$Script:ThreatIPs = @{}
$Script:TISyncJob = $null
$Script:LastSync = Get-Date
$Script:BootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

# --- SYSTEM TRAY UI ---
$Script:NotifyIcon = New-Object System.Windows.Forms.NotifyIcon
$Script:NotifyIcon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon("$env:windir\System32\Taskmgr.exe")
$Script:NotifyIcon.Text = "MHX Community Edition (Active)"
$Script:NotifyIcon.Visible = $true

$ContextMenu = New-Object System.Windows.Forms.ContextMenu
$ContextMenu.MenuItems.Add("View Incident Log", { Start-Process notepad.exe -ArgumentList $Script:IncidentLog }) | Out-Null
$ContextMenu.MenuItems.Add("-") | Out-Null
$ContextMenu.MenuItems.Add("Exit MHX", { $Script:NotifyIcon.Visible = $false; $Script:HunterTimer.Stop(); [System.Windows.Forms.Application]::Exit() }) | Out-Null
$Script:NotifyIcon.ContextMenu = $ContextMenu

function Show-Toast([string]$Title, [string]$Message) {
    $Script:NotifyIcon.ShowBalloonTip(5000, $Title, $Message, [System.Windows.Forms.ToolTipIcon]::Warning)
}

# --- THREAT INTELLIGENCE (BASIC FEEDS) ---
function Start-TISyncJob {
    if ($null -eq $Script:TISyncJob) {
        $Script:TISyncJob = Start-Job -ScriptBlock {
            $feeds = @(
                "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "https://www.spamhaus.org/drop/drop.txt"
                # TODO (Community): Add more reliable C2 blocklists here
            )
            $combinedData = ""
            foreach ($url in $feeds) { try { $combinedData += (Invoke-RestMethod -Uri $url -TimeoutSec 10 -ErrorAction Stop) + "`n" } catch { } }
            return $combinedData
        }
    }
}

function Receive-TISyncJob {
    if ($Script:TISyncJob -and $Script:TISyncJob.State -ne 'Running') {
        if ($Script:TISyncJob.State -eq 'Completed') {
            $TI_Data = Receive-Job -Job $Script:TISyncJob
            if ($TI_Data) {
                $NewThreatIPs = @{}; $Count = 0
                ($TI_Data -split "`n") | ForEach-Object { if ($_ -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})") { $NewThreatIPs[$matches[1]] = $true; $Count++ } }
                if ($Count -gt 0) { $Script:ThreatIPs = $NewThreatIPs }
            }
        }
        Remove-Job -Job $Script:TISyncJob -Force; $Script:TISyncJob = $null
    }
}

# --- CORE X-RAY ENGINE ---
$Script:HunterTimer = New-Object System.Windows.Forms.Timer
$Script:HunterTimer.Interval = 3000 # 3 seconds heartbeat
$Script:HunterTimer.Add_Tick({
    
    Receive-TISyncJob
    $OwnSessionPIDs = (Get-Process -Name "powershell","pwsh" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq [System.Diagnostics.Process]::GetCurrentProcess().SessionId }).Id

    # ENGINE 1: LINEAGE TRACKING
    $AllProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    foreach ($p in $AllProcs) {
        $ProcName = $p.Name.ToLower()
        if ($Script:StrictLineage.ContainsKey($ProcName)) {
            if ($p.CreationDate -lt $Script:BootTime.AddMinutes(2)) { continue }
            $Parent = $AllProcs | Where-Object { $_.ProcessId -eq $p.ParentProcessId }
            if ($Parent -and ($Script:StrictLineage[$ProcName] -notcontains $Parent.Name.ToLower())) {
                Log-Event -Id 101 -Message "Lineage Anomaly: $($p.Name) spawned by $($Parent.Name)"
                Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                if ($?) { Show-Toast "MHX: Lineage Breach" "Process $($p.Name) terminated (Invalid Parent: $($Parent.Name))" }
            }
        }
    }

    # ENGINE 2: LIVING OFF THE LAND (LotL)
    $Proc = Get-Process | Where-Object { ($OwnSessionPIDs -notcontains $_.Id) -and ($_.CommandLine -match "(-enc |bypass|hidden)") }
    foreach ($p in $Proc) {
        Log-Event -Id 102 -Message "LotL Detection: $($p.Name) -> $($p.CommandLine)"
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        if ($?) { Show-Toast "MHX: LotL Activity" "$($p.Name) terminated due to suspicious arguments." }
    }

    # ENGINE 3: THREAT INTEL NETWORK MONITOR
    $Net = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.)" }
    foreach ($n in $Net) {
        if ($Script:ThreatIPs.ContainsKey($n.RemoteAddress)) {
            Stop-Process -Id $n.OwningProcess -Force -ErrorAction SilentlyContinue
            if ($?) { Show-Toast "MHX: C2 Connection Blocked" "Target IP: $($n.RemoteAddress)" }
            Log-Event -Id 103 -Message "C2 Block: Process $($n.OwningProcess) connected to known Threat IP $($n.RemoteAddress)"
        }
    }

    if ((Get-Date) - $Script:LastSync -gt [TimeSpan]::FromHours(12)) { Start-TISyncJob; $Script:LastSync = Get-Date }
})

# --- START THE DAEMON ---
Start-TISyncJob
$Script:HunterTimer.Start()

Show-Toast "MHX Community Edition" "EDR Daemon initialized. Background monitoring active."
[System.Windows.Forms.Application]::Run()
