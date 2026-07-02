<#
.SYNOPSIS
    Read-only security audit for Windows 10/11 focused on the settings and
    infection indicators that commonly lead to stolen personal information.

.DESCRIPTION
    Checks antivirus state, Microsoft Defender configuration, firewall,
    SmartScreen, UAC, Remote Desktop exposure, BitLocker, Windows Update
    recency, and scans autorun locations and scheduled tasks for patterns
    used by infostealer malware. Prints PASS / WARN / FAIL findings with a
    suggested fix for each. Makes NO changes to the system.

.PARAMETER ReportPath
    Optional path to also save the findings as a plain-text report.

.EXAMPLE
    .\Invoke-SecurityCheckup.ps1
    .\Invoke-SecurityCheckup.ps1 -ReportPath "$env:USERPROFILE\Desktop\security-report.txt"

.NOTES
    Run from an elevated (administrator) prompt for complete results.
    Requires Windows PowerShell 5.1 or later.
#>
[CmdletBinding()]
param(
    [string]$ReportPath
)

$script:Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [string]$Area,
        [string]$Check,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Status,
        [string]$Detail,
        [string]$Fix = ''
    )
    $script:Findings.Add([pscustomobject]@{
        Area   = $Area
        Check  = $Check
        Status = $Status
        Detail = $Detail
        Fix    = $Fix
    })
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$isAdmin = Test-IsAdmin
Write-Host ''
Write-Host '=== Windows Security Checkup (read-only) ===' -ForegroundColor Cyan
if (-not $isAdmin) {
    Write-Host 'NOTE: Not running as administrator - some checks will be skipped or incomplete.' -ForegroundColor Yellow
    Add-Finding 'General' 'Administrator rights' 'WARN' 'Checkup was run without administrator rights; results are incomplete.' 'Re-run from an elevated PowerShell (right-click Start -> Terminal (Admin)).'
}

# ---------------------------------------------------------------------------
# 1. Which antivirus is actually protecting this machine?
# ---------------------------------------------------------------------------
Write-Host 'Checking installed antivirus products...'
try {
    $avProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop
    if (-not $avProducts) {
        Add-Finding 'Antivirus' 'Registered antivirus product' 'FAIL' 'No antivirus product is registered with Windows Security Center.' 'Enable Microsoft Defender (Windows Security -> Virus & threat protection) or install a reputable AV.'
    }
    foreach ($av in $avProducts) {
        # productState is a bitmask; the conventional decoding uses the hex string:
        # chars 2-3 = enabled state (10/11 = on), chars 4-5 = definitions (00 = current).
        $hex = '{0:X6}' -f $av.productState
        $enabled = $hex.Substring(2, 2) -in @('10', '11')
        $upToDate = $hex.Substring(4, 2) -eq '00'
        if ($enabled -and $upToDate) {
            Add-Finding 'Antivirus' "$($av.displayName)" 'PASS' 'Enabled with up-to-date definitions.'
        } elseif ($enabled) {
            Add-Finding 'Antivirus' "$($av.displayName)" 'WARN' 'Enabled but definitions look out of date.' 'Open the product and update its definitions; if it will not update, uninstall it and use Microsoft Defender.'
        } else {
            Add-Finding 'Antivirus' "$($av.displayName)" 'FAIL' 'Installed but reporting DISABLED. A disabled AV protects nothing and blocks Defender from taking over.' 'Re-enable it, or uninstall it completely so Microsoft Defender activates automatically.'
        }
    }
} catch {
    Add-Finding 'Antivirus' 'Security Center query' 'INFO' "Could not query Security Center ($($_.Exception.Message)). This is normal on Windows Server."
}

# ---------------------------------------------------------------------------
# 2. Microsoft Defender engine status
# ---------------------------------------------------------------------------
Write-Host 'Checking Microsoft Defender status...'
$mpStatus = $null
$mpPrefs = $null
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    $mpPrefs = Get-MpPreference -ErrorAction Stop
} catch {
    Add-Finding 'Defender' 'Defender service' 'INFO' 'Microsoft Defender is not queryable (usually because a third-party AV is active).'
}

if ($mpStatus) {
    if ($mpStatus.RealTimeProtectionEnabled) {
        Add-Finding 'Defender' 'Real-time protection' 'PASS' 'Files are scanned as they are opened and downloaded.'
    } else {
        Add-Finding 'Defender' 'Real-time protection' 'FAIL' 'Real-time protection is OFF - malware runs unchecked until a manual scan.' 'Run .\Enable-Protections.ps1, or turn it on in Windows Security -> Virus & threat protection -> Manage settings.'
    }

    if ($mpStatus.IsTamperProtected) {
        Add-Finding 'Defender' 'Tamper Protection' 'PASS' 'Malware cannot silently disable Defender.'
    } else {
        Add-Finding 'Defender' 'Tamper Protection' 'FAIL' 'Tamper Protection is OFF - infostealers routinely switch Defender off as their first step.' 'Windows Security -> Virus & threat protection -> Manage settings -> Tamper Protection -> On. (Cannot be scripted, by design.)'
    }

    if ($mpStatus.AntivirusSignatureLastUpdated) {
        $sigAge = (Get-Date) - $mpStatus.AntivirusSignatureLastUpdated
        if ($sigAge.TotalDays -le 7) {
            Add-Finding 'Defender' 'Virus definitions' 'PASS' ("Last updated {0:N1} days ago." -f $sigAge.TotalDays)
        } else {
            Add-Finding 'Defender' 'Virus definitions' 'WARN' ("Definitions are {0:N0} days old." -f $sigAge.TotalDays) 'Run: Update-MpSignature   (or check for Windows Updates).'
        }
    }

    if ($mpStatus.QuickScanEndTime) {
        $scanAge = (Get-Date) - $mpStatus.QuickScanEndTime
        if ($scanAge.TotalDays -gt 14) {
            Add-Finding 'Defender' 'Recent scan' 'WARN' ("Last quick scan finished {0:N0} days ago." -f $scanAge.TotalDays) 'Run: Start-MpScan -ScanType QuickScan'
        } else {
            Add-Finding 'Defender' 'Recent scan' 'PASS' ("Quick scan ran {0:N1} days ago." -f $scanAge.TotalDays)
        }
    } else {
        Add-Finding 'Defender' 'Recent scan' 'WARN' 'No completed quick scan on record.' 'Run: Start-MpScan -ScanType QuickScan'
    }
}

if ($mpPrefs) {
    if ($mpPrefs.MAPSReporting -gt 0) {
        Add-Finding 'Defender' 'Cloud-delivered protection' 'PASS' 'New threats are checked against Microsoft''s cloud in near real-time.'
    } else {
        Add-Finding 'Defender' 'Cloud-delivered protection' 'FAIL' 'Cloud protection is OFF - Defender is limited to signatures that may be hours or days old.' 'Run .\Enable-Protections.ps1'
    }

    if ($mpPrefs.PUAProtection -eq 1) {
        Add-Finding 'Defender' 'Potentially unwanted app blocking' 'PASS' 'Adware/bundleware downloads are blocked.'
    } else {
        Add-Finding 'Defender' 'Potentially unwanted app blocking' 'WARN' 'PUA blocking is off; bundled adware installs freely.' 'Run .\Enable-Protections.ps1'
    }

    if ($mpPrefs.EnableNetworkProtection -eq 1) {
        Add-Finding 'Defender' 'Network protection' 'PASS' 'Connections to known-malicious hosts are blocked system-wide.'
    } else {
        Add-Finding 'Defender' 'Network protection' 'WARN' 'Network protection is off; phishing/malware domains are only blocked inside Edge.' 'Run .\Enable-Protections.ps1'
    }

    switch ([int]$mpPrefs.EnableControlledFolderAccess) {
        1 { Add-Finding 'Defender' 'Controlled Folder Access (ransomware)' 'PASS' 'Untrusted apps cannot modify your Documents/Pictures.' }
        2 { Add-Finding 'Defender' 'Controlled Folder Access (ransomware)' 'INFO' 'Running in audit mode (logging only). Enforce it once no legitimate apps are flagged.' 'Run: .\Enable-Protections.ps1 -ControlledFolderAccess Enabled' }
        default { Add-Finding 'Defender' 'Controlled Folder Access (ransomware)' 'WARN' 'Off - ransomware can encrypt your personal folders unimpeded.' 'Run .\Enable-Protections.ps1 (starts in audit mode).' }
    }

    $asrIds = @($mpPrefs.AttackSurfaceReductionRules_Ids)
    if ($asrIds.Count -ge 8) {
        Add-Finding 'Defender' 'Attack Surface Reduction rules' 'PASS' "$($asrIds.Count) ASR rules configured."
    } elseif ($asrIds.Count -gt 0) {
        Add-Finding 'Defender' 'Attack Surface Reduction rules' 'INFO' "$($asrIds.Count) ASR rules configured; the recommended set is larger." 'Run .\Enable-Protections.ps1'
    } else {
        Add-Finding 'Defender' 'Attack Surface Reduction rules' 'WARN' 'No ASR rules active. These block credential theft from LSASS, malicious Office macros, and script-based droppers.' 'Run .\Enable-Protections.ps1'
    }

    # Exclusions are the hole malware asks users to open ("disable your AV to
    # install"). Non-admins may see "N/A: Must be an administrator..." here.
    $exclusions = @()
    foreach ($e in @($mpPrefs.ExclusionPath))      { if ($e -and $e -notmatch '^N/A') { $exclusions += "Path: $e" } }
    foreach ($e in @($mpPrefs.ExclusionProcess))   { if ($e -and $e -notmatch '^N/A') { $exclusions += "Process: $e" } }
    foreach ($e in @($mpPrefs.ExclusionExtension)) { if ($e -and $e -notmatch '^N/A') { $exclusions += "Extension: $e" } }
    if ($exclusions.Count -gt 0) {
        Add-Finding 'Defender' 'Scan exclusions' 'WARN' ("Defender is configured to IGNORE {0} location(s)/process(es). Cracked-software installers commonly ask for these:`n    {1}" -f $exclusions.Count, ($exclusions -join "`n    ")) 'Remove any you cannot explain: Remove-MpPreference -ExclusionPath "<path>" (or -ExclusionProcess / -ExclusionExtension).'
    } elseif (-not $isAdmin) {
        Add-Finding 'Defender' 'Scan exclusions' 'INFO' 'Exclusions require administrator rights to view; re-run elevated.'
    } else {
        Add-Finding 'Defender' 'Scan exclusions' 'PASS' 'No exclusions - Defender scans everything.'
    }
}

# ---------------------------------------------------------------------------
# 3. Firewall
# ---------------------------------------------------------------------------
Write-Host 'Checking firewall...'
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $off = @($profiles | Where-Object { -not $_.Enabled })
    if ($off.Count -eq 0) {
        Add-Finding 'Firewall' 'Windows Firewall' 'PASS' 'Enabled on all profiles (Domain, Private, Public).'
    } else {
        Add-Finding 'Firewall' 'Windows Firewall' 'FAIL' ("Disabled on: {0}." -f (($off | ForEach-Object Name) -join ', ')) 'Run .\Enable-Protections.ps1'
    }
} catch {
    Add-Finding 'Firewall' 'Windows Firewall' 'INFO' "Could not query firewall profiles ($($_.Exception.Message))."
}

# ---------------------------------------------------------------------------
# 4. SmartScreen, UAC, Remote Desktop
# ---------------------------------------------------------------------------
Write-Host 'Checking SmartScreen, UAC, and Remote Desktop...'
$smartScreen = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue).SmartScreenEnabled
if ($smartScreen -eq 'Off') {
    Add-Finding 'System' 'SmartScreen' 'FAIL' 'SmartScreen is OFF - no reputation warning before running downloaded programs.' 'Run .\Enable-Protections.ps1'
} elseif ($smartScreen) {
    Add-Finding 'System' 'SmartScreen' 'PASS' "Enabled (mode: $smartScreen)."
} else {
    Add-Finding 'System' 'SmartScreen' 'INFO' 'SmartScreen policy value not set; Windows default (Warn) applies.'
}

$uacPolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
if ($uacPolicy -and $uacPolicy.EnableLUA -eq 1) {
    if ($uacPolicy.ConsentPromptBehaviorAdmin -eq 0) {
        Add-Finding 'System' 'User Account Control' 'FAIL' 'UAC is set to "never notify" - programs can gain admin rights silently.' 'Search Start for "UAC" and move the slider to the default (third) notch.'
    } else {
        Add-Finding 'System' 'User Account Control' 'PASS' 'UAC prompts before programs make system changes.'
    }
} else {
    Add-Finding 'System' 'User Account Control' 'FAIL' 'UAC is disabled - every program you run has full admin control of the PC.' 'Search Start for "UAC" and re-enable it, then reboot.'
}

$rdp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
if ($rdp -and $rdp.fDenyTSConnections -eq 0) {
    Add-Finding 'System' 'Remote Desktop' 'WARN' 'Remote Desktop is ENABLED. If you do not use it, it is a common break-in door for password-guessing attacks.' 'Settings -> System -> Remote Desktop -> Off (if you do not need it).'
} else {
    Add-Finding 'System' 'Remote Desktop' 'PASS' 'Remote Desktop is disabled.'
}

# ---------------------------------------------------------------------------
# 5. Disk encryption and Windows Update recency
# ---------------------------------------------------------------------------
Write-Host 'Checking disk encryption and update recency...'
try {
    $osVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($osVolume.ProtectionStatus -eq 'On') {
        Add-Finding 'System' 'Disk encryption (BitLocker)' 'PASS' 'System drive is encrypted; a stolen laptop does not mean stolen files.'
    } else {
        Add-Finding 'System' 'Disk encryption (BitLocker)' 'WARN' 'System drive is not encrypted.' 'Settings -> Privacy & security -> Device encryption (or search "BitLocker").'
    }
} catch {
    Add-Finding 'System' 'Disk encryption (BitLocker)' 'INFO' 'BitLocker not available on this edition (Windows Home may use "Device encryption" instead - check Settings).'
}

$lastHotfix = Get-HotFix -ErrorAction SilentlyContinue |
    Where-Object { $_.InstalledOn } |
    Sort-Object InstalledOn -Descending |
    Select-Object -First 1
if ($lastHotfix) {
    $patchAge = (Get-Date) - $lastHotfix.InstalledOn
    if ($patchAge.TotalDays -gt 45) {
        Add-Finding 'System' 'Windows Update' 'WARN' ("Newest installed update ({0}) is {1:N0} days old." -f $lastHotfix.HotFixID, $patchAge.TotalDays) 'Settings -> Windows Update -> Check for updates.'
    } else {
        Add-Finding 'System' 'Windows Update' 'PASS' ("Updates are recent (latest: {0}, {1:N0} days ago)." -f $lastHotfix.HotFixID, $patchAge.TotalDays)
    }
} else {
    Add-Finding 'System' 'Windows Update' 'INFO' 'Could not determine update history.'
}

# ---------------------------------------------------------------------------
# 6. Autoruns - where infostealers persist
# ---------------------------------------------------------------------------
Write-Host 'Scanning autorun locations for suspicious entries...'
# Two patterns that together match the classic infostealer launch chain:
# a script host / LOLBin started from a user-writable directory, or an
# encoded PowerShell command anywhere.
$suspiciousHost = '(?i)(wscript|cscript|mshta|regsvr32|rundll32|powershell|pwsh|cmd(\.exe)?\s+/c|curl\s|bitsadmin)'
$userWritable = '(?i)(\\AppData\\|\\Temp\\|%temp%|%appdata%|\\Downloads\\|\\ProgramData\\)'
$encodedPs = '(?i)-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}'

function Test-SuspiciousCommand {
    param([string]$Command)
    if (-not $Command) { return $false }
    if ($Command -match $encodedPs) { return $true }
    return (($Command -match $suspiciousHost) -and ($Command -match $userWritable))
}

$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
$autorunCount = 0
$suspiciousAutoruns = @()
foreach ($key in $runKeys) {
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    foreach ($prop in $props.PSObject.Properties) {
        if ($prop.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
        $autorunCount++
        if (Test-SuspiciousCommand -Command ([string]$prop.Value)) {
            $suspiciousAutoruns += "[$key] $($prop.Name) = $($prop.Value)"
        }
    }
}

$startupFolders = @(
    [Environment]::GetFolderPath('Startup'),
    [Environment]::GetFolderPath('CommonStartup')
)
foreach ($folder in $startupFolders) {
    if ($folder -and (Test-Path $folder)) {
        foreach ($item in Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue) {
            $autorunCount++
            if ($item.Extension -in @('.vbs', '.js', '.jse', '.wsf', '.hta', '.bat', '.cmd', '.ps1')) {
                $suspiciousAutoruns += "[Startup folder] $($item.FullName) (script file in startup)"
            }
        }
    }
}

if ($suspiciousAutoruns.Count -gt 0) {
    Add-Finding 'Malware indicators' 'Suspicious autorun entries' 'FAIL' ("{0} entr{1} match patterns used by infostealers:`n    {2}" -f $suspiciousAutoruns.Count, $(if ($suspiciousAutoruns.Count -eq 1) { 'y' } else { 'ies' }), ($suspiciousAutoruns -join "`n    ")) 'Research each entry before deleting. If unrecognized, run a Microsoft Defender Offline scan and see IF-YOUR-INFO-WAS-STOLEN.md.'
} else {
    Add-Finding 'Malware indicators' 'Autorun entries' 'PASS' "Reviewed $autorunCount autorun entries; none match known-bad patterns (heuristic check, not a guarantee)."
}

# ---------------------------------------------------------------------------
# 7. Scheduled tasks - the other favorite persistence spot
# ---------------------------------------------------------------------------
Write-Host 'Scanning scheduled tasks for suspicious actions...'
$suspiciousTasks = @()
$taskCount = 0
try {
    foreach ($task in Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' }) {
        foreach ($action in @($task.Actions)) {
            if (-not $action.Execute) { continue }
            $taskCount++
            $cmdLine = "$($action.Execute) $($action.Arguments)"
            if (Test-SuspiciousCommand -Command $cmdLine) {
                $suspiciousTasks += "$($task.TaskPath)$($task.TaskName) -> $cmdLine"
            }
        }
    }
    if ($suspiciousTasks.Count -gt 0) {
        Add-Finding 'Malware indicators' 'Suspicious scheduled tasks' 'FAIL' ("{0} task(s) match patterns used by malware:`n    {1}" -f $suspiciousTasks.Count, ($suspiciousTasks -join "`n    ")) 'Research each task before deleting. If unrecognized, run a Microsoft Defender Offline scan and see IF-YOUR-INFO-WAS-STOLEN.md.'
    } else {
        Add-Finding 'Malware indicators' 'Scheduled tasks' 'PASS' "Reviewed $taskCount active task actions; none match known-bad patterns (heuristic check, not a guarantee)."
    }
} catch {
    Add-Finding 'Malware indicators' 'Scheduled tasks' 'INFO' "Could not enumerate scheduled tasks ($($_.Exception.Message))."
}

# ---------------------------------------------------------------------------
# 8. Recent Defender detections - repeated hits mean the source is still there
# ---------------------------------------------------------------------------
if ($mpStatus) {
    Write-Host 'Checking Defender detection history...'
    try {
        $threatNames = @{}
        foreach ($t in @(Get-MpThreat -ErrorAction SilentlyContinue)) {
            $threatNames[[string]$t.ThreatID] = $t.ThreatName
        }
        $recent = @(Get-MpThreatDetection -ErrorAction Stop |
            Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-90) } |
            Sort-Object InitialDetectionTime -Descending)
        if ($recent.Count -gt 0) {
            $lines = foreach ($d in ($recent | Select-Object -First 10)) {
                $name = $threatNames[[string]$d.ThreatID]
                if (-not $name) { $name = "ThreatID $($d.ThreatID)" }
                '{0:yyyy-MM-dd}  {1}' -f $d.InitialDetectionTime, $name
            }
            Add-Finding 'Malware indicators' 'Recent Defender detections' 'WARN' ("Defender flagged {0} threat(s) in the last 90 days (newest first):`n    {1}" -f $recent.Count, ($lines -join "`n    ")) 'Review Windows Security -> Protection history. Repeated trojan/stealer detections mean the source (often cracked downloads) is still active - see IF-YOUR-INFO-WAS-STOLEN.md.'
        } else {
            Add-Finding 'Malware indicators' 'Recent Defender detections' 'PASS' 'No Defender threat detections in the last 90 days.'
        }
    } catch {
        Add-Finding 'Malware indicators' 'Recent Defender detections' 'INFO' 'No detection history available.'
    }
}

# ---------------------------------------------------------------------------
# 9. Hosts file tampering
# ---------------------------------------------------------------------------
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if (Test-Path $hostsPath) {
    $hostsEntries = @(Get-Content -Path $hostsPath -ErrorAction SilentlyContinue |
        Where-Object { $_.Trim() -and $_.Trim() -notmatch '^#' })
    # Entries pointing at 0.0.0.0/localhost merely BLOCK a domain (ad-blockers do
    # this). Entries pointing anywhere else REDIRECT the domain to a server
    # someone controls - much more dangerous.
    $redirects = @($hostsEntries | Where-Object { $_.Trim() -notmatch '^(0\.0\.0\.0|127\.0\.0\.1|::1)\s' })
    if ($redirects.Count -gt 0) {
        Add-Finding 'Malware indicators' 'Hosts file' 'FAIL' ("{0} hosts entr{1} REDIRECT domains to a specific server instead of blocking them - browsing those domains lands on whatever that server chooses to show:`n    {2}" -f $redirects.Count, $(if ($redirects.Count -eq 1) { 'y' } else { 'ies' }), (($redirects | Select-Object -First 15) -join "`n    ")) 'Unless you added these yourself for a reason you can explain, delete them (edit as admin: notepad C:\Windows\System32\drivers\etc\hosts).'
    } elseif ($hostsEntries.Count -gt 0) {
        Add-Finding 'Malware indicators' 'Hosts file' 'INFO' ("The hosts file blocks {0} domain(s) (entries pointing to 0.0.0.0/127.0.0.1). Harmless if you or an ad-blocker added them; malware occasionally uses this to block security sites:`n    {1}" -f $hostsEntries.Count, (($hostsEntries | Select-Object -First 15) -join "`n    ")) 'If you did not add these, remove them (edit as admin: notepad C:\Windows\System32\drivers\etc\hosts).'
    } else {
        Add-Finding 'Malware indicators' 'Hosts file' 'PASS' 'No active redirect entries.'
    }
}

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
$statusColor = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Gray' }
$statusOrder = @{ FAIL = 0; WARN = 1; INFO = 2; PASS = 3 }

Write-Host ''
Write-Host '=== Findings ===' -ForegroundColor Cyan
foreach ($f in ($script:Findings | Sort-Object { $statusOrder[$_.Status] })) {
    Write-Host ("[{0}] " -f $f.Status) -ForegroundColor $statusColor[$f.Status] -NoNewline
    Write-Host ("{0} - {1}" -f $f.Area, $f.Check) -ForegroundColor White
    Write-Host ("       {0}" -f $f.Detail)
    if ($f.Fix -and $f.Status -in @('FAIL', 'WARN')) {
        Write-Host ("       Fix: {0}" -f $f.Fix) -ForegroundColor Cyan
    }
}

$failCount = @($script:Findings | Where-Object Status -eq 'FAIL').Count
$warnCount = @($script:Findings | Where-Object Status -eq 'WARN').Count
$passCount = @($script:Findings | Where-Object Status -eq 'PASS').Count

Write-Host ''
Write-Host '=== Summary ===' -ForegroundColor Cyan
Write-Host ("  {0} passed   {1} warnings   {2} failed" -f $passCount, $warnCount, $failCount)
if ($failCount -gt 0) {
    Write-Host '  Address the FAIL items first - they are the likely routes for data theft.' -ForegroundColor Red
} elseif ($warnCount -gt 0) {
    Write-Host '  No critical failures. Review the warnings when convenient.' -ForegroundColor Yellow
} else {
    Write-Host '  This machine is well configured. If information is still being stolen, the leak is likely off-device: reused/breached passwords or a phished account. See IF-YOUR-INFO-WAS-STOLEN.md.' -ForegroundColor Green
}
Write-Host ''

if ($ReportPath) {
    $lines = @("Windows Security Checkup - $(Get-Date)", '')
    foreach ($f in ($script:Findings | Sort-Object { $statusOrder[$_.Status] })) {
        $lines += "[{0}] {1} - {2}" -f $f.Status, $f.Area, $f.Check
        $lines += "       $($f.Detail)"
        if ($f.Fix) { $lines += "       Fix: $($f.Fix)" }
    }
    $lines += ''
    $lines += "Summary: $passCount passed, $warnCount warnings, $failCount failed"
    $lines | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Host "Report saved to $ReportPath"
}
