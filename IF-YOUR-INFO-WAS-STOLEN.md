# If Your Information Was Stolen — Recovery Checklist

Work through these steps **in order**. The order matters: changing passwords from an
infected PC just hands the thief your new passwords too.

## Step 1 — Assume the PC is compromised until proven otherwise

- Disconnect the PC from Wi-Fi/Ethernet if you suspect active malware.
- Use a **different, clean device** (your phone on mobile data is ideal) for
  Steps 2–4.

## Step 2 — Lock down your email account FIRST

Email is the master key: whoever controls it can reset every other account.
From your phone:

1. Change your email password to something long and unique.
2. Turn on two-factor authentication (an authenticator app, not SMS if possible).
3. Check the account's security page for sessions/devices you don't recognize and
   **sign out all other sessions**.
4. Check for forwarding rules or "app passwords" you didn't create — attackers add
   these to keep access after a password change. Delete any you don't recognize.

## Step 3 — Then banking, then everything else

In this order: bank/credit cards → Amazon/PayPal/payment apps → social media →
everything else.

- Unique password per site. Humans can't do this from memory — use a password
  manager (Bitwarden is free and reputable; Apple/Google's built-in managers are
  fine too).
- Enable two-factor authentication everywhere it's offered.
- Check https://haveibeenpwned.com to see which breaches your email appears in —
  any account listed there with a reused password should be treated as compromised.

## Step 4 — Protect your money and identity

- Turn on transaction alerts in your banking apps.
- Review recent statements for charges you don't recognize; dispute them —
  banks expect these calls and the process is routine.
- **United States:** freeze your credit at all three bureaus (free, takes ~10
  minutes each: Equifax, Experian, TransUnion). This stops anyone opening credit in
  your name. Report identity theft at https://identitytheft.gov.
- Other countries have equivalents — search "credit freeze" + your country.

## Step 5 — Now clean the PC

1. Run the audit: `.\Invoke-SecurityCheckup.ps1` — pay attention to any
   **Malware indicators** findings.
2. Run a **Microsoft Defender Offline scan**: Windows Security → Virus & threat
   protection → Scan options → *Microsoft Defender Antivirus (offline scan)*.
   It reboots and scans before Windows loads, catching malware that hides from
   normal scans.
3. Get a second opinion with the free [Malwarebytes](https://www.malwarebytes.com)
   scanner or [ESET Online Scanner](https://www.eset.com/int/home/online-scanner/).
4. **If an infostealer is found or you still see signs of compromise, reinstall
   Windows** (Settings → System → Recovery → Reset this PC → *Remove everything*).
   It sounds drastic, but modern infostealers hide well enough that a clean
   reinstall is the only way to be certain. Back up personal *files* first —
   documents and photos, not programs.

## Step 6 — Harden, so it doesn't happen again

1. Run `.\Enable-Protections.ps1` (see README).
2. Turn on Tamper Protection by hand (Windows Security → Virus & threat
   protection → Manage settings).
3. **Stop storing passwords in the browser** — browser password stores are the #1
   target of infostealers. Move them to a password manager and delete them from the
   browser (and turn off the browser's "offer to save passwords" setting).
4. Review browser extensions and remove anything you don't actively use.
5. Never install cracked software, game cheats, or installers from download portals
   — these are how most infostealers arrive.

## How do I know it's actually resolved?

- No new unrecognized logins/sessions on your key accounts for a couple of weeks.
- No new fraudulent charges.
- The security checkup comes back clean after the reset/scans.

If fraudulent activity continues *after* you've done all of the above from a clean
device, the leak is likely a breached account or SIM-swap rather than this PC —
contact your mobile carrier to add a port-out PIN, and consider whether anyone else
has access to your accounts or devices.
