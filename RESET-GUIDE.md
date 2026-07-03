# Full Reset Guide — Wipe the PC So Nothing Comes Back

A reset erases everything on the Windows drive: every program, every AppData
folder, hidden dot-folders, alternate data streams, registry persistence,
scheduled tasks — all of it. Malware does not survive a "Remove everything"
reset. The only ways it comes back are the **re-infection routes**: infected
files on your backup drive, cloud sync restoring bad data, or re-downloading
the thing that started it. This guide closes each route.

Read this on your phone (github.com → your Antivirus repo) while the PC is
resetting — the PC will be unusable for 1–3 hours.

---

## Phase 1 — Before the reset (30–60 minutes)

1. **Passwords first, from your phone — never from the infected PC.**
   Email → bank → Google/Microsoft → Riot → Discord → Steam → everything else.
   Unique passwords, 2FA on, "sign out all other sessions" on each.
   Your Microsoft account matters most today: you'll sign into it during
   Windows setup, so rotate it now.

2. **Back up personal FILES only** to a USB drive or external disk:
   - YES: Documents, Pictures, Videos, Music, game save folders.
   - NO: anything ending in `.exe`, `.msi`, `.bat`, `.zip` installers,
     anything from Downloads, any program folder, anything from AppData.
   - If you're unsure about a file, leave it — programs and installers are
     all re-downloadable from official sources.

3. **Check your cloud storage from your phone.** Open OneDrive / Google Drive
   on the web and delete any `.exe`, `.zip`, or installer files sitting in
   synced folders — otherwise they sync right back onto the clean PC.

4. **Clear Chrome sync data** (the browser hijack lived inside it):
   on your phone, go to `chrome.google.com/sync` while signed into your
   Google account and choose **Clear data**. Do this BEFORE you sign into
   Chrome on the fresh Windows — otherwise the hijacked settings sync back.

5. **Write down what you'll need after:** Wi-Fi password, Microsoft account
   login (freshly changed), any license keys for paid software.

6. **Second drive?** A reset only wipes the Windows drive (C:). If the PC has
   a D: drive, either back up its personal files and format it too
   (recommended), or at minimum run full Defender + Malwarebytes rootkit
   scans on it after the reset before opening anything on it.

## Phase 2 — The reset itself (1–3 hours, mostly waiting)

1. Settings → System → Recovery → **Reset this PC** → **Remove everything**.
2. Choose **Cloud download** — it fetches a fresh Windows image from
   Microsoft instead of rebuilding from files on the possibly-tainted disk.
   (Needs ~4 GB of internet.)
3. On the "Additional settings" screen the default *"Just remove your files"*
   is fine — the drive is reformatted either way. *"Fully clean the drive"*
   adds hours and only matters if you're selling the PC.
4. Click **Reset** and let it work. The PC reboots several times. Don't
   interrupt it even if it looks stuck for a while.

## Phase 3 — First boot, in this exact order

Order matters: protections go on BEFORE the backup drive goes in.

1. Set up Windows with your Microsoft account (the new password). Decline
   junk offers (trials, Game Pass upsells) — keep it minimal.
2. **Windows Update until empty:** Settings → Windows Update → check,
   install, reboot, repeat until nothing is left.
3. **Verify Tamper Protection is ON** (fresh installs default to on):
   Windows Security → Virus & threat protection → Manage settings.
4. **Re-apply the hardening toolkit.** In an admin PowerShell:
   ```powershell
   git clone -b claude/windows-antivirus-recommendation-eikate https://github.com/JusticeRox98577/Antivirus.git
   cd Antivirus
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\Enable-Protections.ps1
   .\Invoke-SecurityCheckup.ps1
   ```
   (No Git yet? Download the branch ZIP from your repo on github.com.)
5. **Turn on device encryption / BitLocker:** Settings → Privacy & security
   → Device encryption (or search "BitLocker"). Save the recovery key to
   your Microsoft account when asked.

## Phase 4 — Restore data and apps safely

1. Plug in the backup drive **now** (after protections are on). Right-click
   the drive in File Explorer → **Scan with Microsoft Defender** before
   copying anything.
2. Copy your documents/pictures/saves back. Do not run anything from the
   backup drive.
3. Reinstall apps **from official sources only**: Steam from steampowered.com,
   Riot from riotgames.com, Discord from discord.com, browser from its
   official site. No download portals, no torrents of software.
4. **Passwords go in a password manager** (Bitwarden is free), not the
   browser. Turn off the browser's own "offer to save passwords."
5. Sign into Chrome only after Phase 1 step 4 (sync data cleared). Check
   `chrome://extensions` stays empty except what you deliberately add.

## The rules that keep it clean

1. **No cheats, no cracks, no "undetected" anything, ever.** Every version of
   the tool that infected this PC was a trojan. Software that promises to
   evade anti-cheat is built to evade antivirus — that's the same feature.
2. **Never add an antivirus exclusion because an installer tells you to.**
   That instruction is the infection asking you to hold the door.
3. Downloads come from the developer's own site or a real store. If a site
   made you click through three "DOWNLOAD" buttons, close it.
4. Run `.\Invoke-SecurityCheckup.ps1` monthly. It takes a minute and will
   catch new exclusions, disabled protections, and suspicious autoruns.

## How you'll know it worked

- The checkup script comes back green after Phase 3.
- No new Defender detections in the first weeks.
- No unrecognized logins on your accounts (you'll get alerts now that 2FA
  and notifications are on).
- The PC is faster. It genuinely will be.
