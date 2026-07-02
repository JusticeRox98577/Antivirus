#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Turns on the strongest built-in Windows/Microsoft Defender protections,
    most of which are disabled by default.

.DESCRIPTION
    Enables: Defender real-time protection, cloud-delivered protection,
    potentially-unwanted-app blocking, network protection, Controlled Folder
    Access (audit mode by default), Microsoft's recommended Attack Surface
    Reduction rules, Windows Firewall on all profiles, and SmartScreen.
    Every change is announced; use -WhatIf to preview without changing anything.

.PARAMETER ControlledFolderAccess
    Disabled, AuditMode (default), or Enabled. AuditMode only logs which apps
    WOULD be blocked from your personal folders; switch to Enabled after a
    week with no false alarms.

.PARAMETER SkipAsrRules
    Skip configuring Attack Surface Reduction rules.

.PARAMETER RunQuickScan
    Update definitions and start a Defender quick scan when finished.

.EXAMPLE
    .\Enable-Protections.ps1 -WhatIf          # preview
    .\Enable-Protections.ps1                  # apply
    .\Enable-Protections.ps1 -ControlledFolderAccess Enabled -RunQuickScan
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Disabled', 'AuditMode', 'Enabled')]
    [string]$ControlledFolderAccess = 'AuditMode',

    [switch]$SkipAsrRules,

    [switch]$RunQuickScan
)

$script:changed = 0
$script:failed = 0

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    if (-not $PSCmdlet.ShouldProcess($Name, 'Enable')) { return }
    Write-Host "-> $Name..." -NoNewline
    try {
        & $Action
        Write-Host ' done' -ForegroundColor Green
        $script:changed++
    } catch {
        Write-Host " FAILED: $($_.Exception.Message)" -ForegroundColor Red
        $script:failed++
    }
}

Write-Host ''
Write-Host '=== Enabling Windows protections ===' -ForegroundColor Cyan

$defenderAvailable = $true
try {
    Get-MpComputerStatus -ErrorAction Stop | Out-Null
} catch {
    $defenderAvailable = $false
    Write-Host 'Microsoft Defender is not active (a third-party antivirus is probably installed).' -ForegroundColor Yellow
    Write-Host 'Defender-specific steps will be skipped; firewall and SmartScreen will still be configured.' -ForegroundColor Yellow
}

if ($defenderAvailable) {
    Invoke-Step 'Real-time protection' {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    }

    Invoke-Step 'Cloud-delivered protection (advanced) + safe sample submission' {
        # MAPSReporting 2 = Advanced; SubmitSamplesConsent 1 = send safe samples only
        Set-MpPreference -MAPSReporting 2 -SubmitSamplesConsent 1 -ErrorAction Stop
    }

    Invoke-Step 'Cloud block-at-first-sight (high level, 50s timeout)' {
        Set-MpPreference -CloudBlockLevel High -CloudExtendedTimeout 50 -ErrorAction Stop
    }

    Invoke-Step 'Potentially unwanted app (adware/bundleware) blocking' {
        Set-MpPreference -PUAProtection 1 -ErrorAction Stop
    }

    Invoke-Step 'Network protection (blocks known-malicious hosts system-wide)' {
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
    }

    if ($ControlledFolderAccess -ne 'Disabled') {
        Invoke-Step "Controlled Folder Access ($ControlledFolderAccess) - ransomware protection for Documents/Pictures" {
            Set-MpPreference -EnableControlledFolderAccess $ControlledFolderAccess -ErrorAction Stop
        }
    }

    if (-not $SkipAsrRules) {
        # Microsoft's "standard protection" ASR rules plus the most valuable
        # recommended ones for home machines. GUIDs are fixed by Microsoft:
        # https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference
        $asrRules = [ordered]@{
            '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Block credential stealing from LSASS (how infostealers grab Windows passwords)'
            '56A863A9-875E-4185-98A7-B882C64B5CE5' = 'Block abuse of exploited vulnerable signed drivers'
            'E6DB77E5-3DF2-4CF1-B95A-636979351E5B' = 'Block persistence through WMI event subscription'
            'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Block executable content from email clients and webmail'
            'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Block JavaScript/VBScript from launching downloaded executables'
            '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Block execution of potentially obfuscated scripts'
            'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Block Office apps from creating child processes (malicious macros)'
            '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Win32 API calls from Office macros'
            '3B576869-A4EC-4529-8536-B80A7769E899' = 'Block Office apps from creating executable content'
            '26190899-1602-49E8-8B27-EB1D0A1CE869' = 'Block Office communication apps from creating child processes'
            '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' = 'Block Adobe Reader from creating child processes'
            'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Block untrusted/unsigned processes running from USB'
            'C1DB55AB-C21A-4637-BB3F-A12568109D35' = 'Advanced ransomware behavior protection'
        }
        foreach ($id in $asrRules.Keys) {
            Invoke-Step "ASR rule: $($asrRules[$id])" {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
            }
        }
    }
}

Invoke-Step 'Windows Firewall on all profiles (Domain, Private, Public)' {
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction Stop
}

Invoke-Step 'SmartScreen for downloaded apps and files' {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' `
        -Name 'SmartScreenEnabled' -Value 'RequireAdmin' -Type String -ErrorAction Stop
}

# Only repair UAC if it has been weakened; leave stricter user choices alone.
$uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$uac = Get-ItemProperty -Path $uacPath -ErrorAction SilentlyContinue
if (-not $uac -or $uac.EnableLUA -ne 1 -or $uac.ConsentPromptBehaviorAdmin -eq 0) {
    Invoke-Step 'User Account Control (restore default prompt level; reboot required)' {
        Set-ItemProperty -Path $uacPath -Name 'EnableLUA' -Value 1 -Type DWord -ErrorAction Stop
        Set-ItemProperty -Path $uacPath -Name 'ConsentPromptBehaviorAdmin' -Value 5 -Type DWord -ErrorAction Stop
    }
}

if ($RunQuickScan -and $defenderAvailable) {
    Invoke-Step 'Update virus definitions' {
        Update-MpSignature -ErrorAction Stop
    }
    Invoke-Step 'Start quick scan (runs in the background)' {
        Start-MpScan -ScanType QuickScan -ErrorAction Stop
    }
}

Write-Host ''
Write-Host '=== Done ===' -ForegroundColor Cyan
Write-Host "  $script:changed step(s) applied, $script:failed failed."
Write-Host ''
Write-Host 'Two things this script cannot do for you:' -ForegroundColor Yellow
Write-Host '  1. Tamper Protection must be enabled by hand (malware could otherwise abuse the'
Write-Host '     same switch): Windows Security -> Virus & threat protection -> Manage'
Write-Host '     settings -> Tamper Protection -> On.'
Write-Host '  2. If your information was already stolen, hardening this PC is not enough -'
Write-Host '     follow IF-YOUR-INFO-WAS-STOLEN.md to lock down your accounts.'
Write-Host ''
if ($ControlledFolderAccess -eq 'AuditMode') {
    Write-Host 'Controlled Folder Access is in AUDIT mode (logging only). After a week, check'
    Write-Host 'Windows Security -> Virus & threat protection -> Ransomware protection for'
    Write-Host 'blocked-app events, then enforce it with:'
    Write-Host '    .\Enable-Protections.ps1 -ControlledFolderAccess Enabled' -ForegroundColor Cyan
}
