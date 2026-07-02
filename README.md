# Windows Security Toolkit

You asked for "the best antivirus for Windows." Here's the honest answer: **the best
antivirus engine for Windows is already installed on your PC — Microsoft Defender —
but most of its strongest protections are turned off by default.** Independent labs
(AV-TEST, AV-Comparatives) consistently rank a properly configured Defender alongside
the top paid products.

A homemade antivirus engine written from scratch would protect you *worse* than
Defender: real AV products are built by large teams with kernel-level drivers, global
threat-intelligence networks, and hourly signature updates. No standalone script can
replicate that, and pretending otherwise would give you false confidence while your
data keeps leaking.

Just as important: **when personal information gets stolen, the antivirus engine is
usually not the weak point.** The common causes are phishing, reused passwords,
"infostealer" malware bundled with cracked software or fake downloads, and security
features that were silently disabled. This toolkit targets exactly those problems.

## What's in this toolkit

| File | What it does |
|---|---|
| `Invoke-SecurityCheckup.ps1` | **Read-only audit.** Checks ~30 settings and infection indicators: Defender status, real-time/cloud protection, tamper protection, firewall, SmartScreen, UAC, Remote Desktop exposure, BitLocker, Windows Update recency, and suspicious autorun entries / scheduled tasks (a common infostealer persistence trick). Prints PASS / WARN / FAIL with a fix for each finding. Changes nothing. |
| `Enable-Protections.ps1` | **Hardening script.** Turns on Defender's strongest features: real-time protection, cloud-delivered protection, PUA (potentially unwanted app) blocking, network protection, ransomware-focused Controlled Folder Access, and Microsoft's recommended Attack Surface Reduction rules. Also enables the firewall on all profiles and SmartScreen. Every change is announced and supports `-WhatIf`. |
| `IF-YOUR-INFO-WAS-STOLEN.md` | **Recovery checklist.** Since your information has already been stolen, start here — changing passwords in the right order, from the right device, matters more than any scan. |

## Quick start

1. Download or clone this repository onto the Windows PC.
2. Right-click the Start button and choose **Terminal (Admin)** or
   **Windows PowerShell (Admin)**.
3. Allow local scripts for this session only, then run the audit:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   cd path\to\Antivirus
   .\Invoke-SecurityCheckup.ps1
   ```

4. Review the findings. To apply the recommended protections:

   ```powershell
   .\Enable-Protections.ps1              # preview first with:  .\Enable-Protections.ps1 -WhatIf
   ```

5. Run a scan when done:

   ```powershell
   .\Enable-Protections.ps1 -RunQuickScan
   ```

   If the checkup flagged possible infection, run a **Microsoft Defender Offline
   scan** instead (Windows Security → Virus & threat protection → Scan options →
   Microsoft Defender Antivirus (offline scan)). It reboots and scans before Windows
   loads, which catches malware that hides from normal scans.

## Notes and limits

- **Tamper Protection** cannot be enabled by script (by design — malware could abuse
  the same mechanism). Turn it on manually: Windows Security → Virus & threat
  protection → Manage settings → Tamper Protection → On.
- **Controlled Folder Access** defaults to *audit mode* here because enforcement can
  block legitimate apps from writing to Documents/Pictures. After a week with no
  audit noise, enforce it: `.\Enable-Protections.ps1 -ControlledFolderAccess Enabled`.
- If you run a **third-party antivirus**, Defender steps aside automatically. The
  checkup will detect and report whichever product is active. If your current paid AV
  has failed you, uninstalling it and running well-configured Defender is a
  legitimate, well-supported choice — not a downgrade.
- The autorun/scheduled-task checks are **heuristics**: they flag entries that match
  common malware patterns for you to review, they are not a verdict.
- The scripts target Windows 10/11 with Windows PowerShell 5.1+ and require an
  administrator prompt for full results.

## The three habits that matter more than any antivirus

1. **A password manager with unique passwords per site** — one breached site can no
   longer unlock the others.
2. **Two-factor authentication** on email and banking first — email resets every
   other account, so it's the crown jewel.
3. **Never install cracked software, "free" game cheats, or download-site
   installers** — these are the #1 delivery method for the infostealers that empty
   saved browser passwords.
