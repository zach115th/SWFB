# Simple Windows Firewall Bouncer (SWFB)

**Simple Windows Firewall Bouncer (SWFB)** is a self-contained PowerShell script that automates blocking of brute-force and password spray attacks using Windows Firewall. It scans Windows Security Event Logs for failed logon attempts and blocks suspicious IPs dynamically based on configurable thresholds and patterns, helping protect Windows systems with no third-party dependencies.

---

## Features

- **Automated Blocking:** Detects and blocks IPs with repeated failed logons, password sprays, or distributed username targeting.
- **Adaptive Detection:** Customizable thresholds for failed attempts, username spray, and user spray detection.
- **Self-Healing:** Unblocks IPs automatically after a configurable expiration period.
- **Stateful:** Persists blocked IPs and host info across reboots/runs via a simple JSON file.
- **No External Dependencies:** Uses only built-in Windows PowerShell, Windows Firewall, and standard logs.

---

## How It Works

- **Monitors** Windows Security event log for Event ID 4625 (failed logons).
- **Correlates** source IP, destination port, and username for each failed attempt.
- **Blocks** an IP using Windows Firewall when:
  - It exceeds a set number of failed logons in a time window.
  - It tries to log in as more than a set number of usernames.
  - A single username is targeted from too many source IPs.
- **Manages** firewall rules and keeps a rolling list of blocked/unblocked IPs.

---

## Requirements

- Windows 10/11 or Server (with PowerShell 5.x+).
- Run as Administrator (required to manage firewall rules and read Security log).
- Windows Firewall enabled.

---

## Installation

1. Download `swfb.ps1` to your system.
2. Open PowerShell **as Administrator**.
3. (Optional) Edit the script’s parameter block at the top to fit your environment.

---

## Usage

```powershell
.\swfb.ps1
```

---

## Parameters
| `Parameter`              | `Default`| `Purpose`                                                       |
| ------------------------ | -------- | --------------------------------------------------------------- |
| `FailedAttemptThreshold` | `5`      | Block IP after this many failed logons in the window            |
| `TimeWindowMinutes`      | `5`      | Look for failed logins within this many minutes                 |
| `BlockDurationDays`      | `30`     | How long to keep an IP blocked                                  |
| `Whitelist`              | see code | Array of IPs to never block (e.g. safe admin stations)          |
| `ScanIntervalMinutes`    | `1`      | How often (in minutes) to scan and take action                  |
| `MaxUsernamesPerIp`      | `2`      | Block IP if it tries this many usernames in the window          |
| `MaxIpsPerUsername`      | `2`      | Block all IPs if a username is hit from this many different IPs |

---

## JSON State
The script writes its state to blocked_ips.json in the working directory, containing:
- Blocked IPs, blocked time, and destination port (if available)
- Host public/private IPs and last update time

---

## How To Tune SWFB
- Adjust thresholds for sensitivity. Lower numbers block faster, higher numbers are more tolerant.
- Whitelist trusted IPs to avoid locking yourself out.
- Check blocked_ips.json for history and troubleshooting.
- Review Windows Event Viewer and Firewall logs for context if needed.

---

## FAQ
**Q: Will this lock me out if I use RDP from a dynamic public IP?**
- A: It’s possible. Add your admin IP to the Whitelist parameter.

**Q: Does this catch slow/stealthy attacks?**
- A: SWFB works best for rapid attacks but can detect password/user spray attempts as well.

**Q: Is it safe to run on domain controllers?**
- A: SWFB reads only failed logon events and blocks at the host firewall, but always test carefully in sensitive environments.

---

## Limitations
- Only blocks based on Windows Security events (Event 4625).
- Does not parse custom log sources.
- Not a replacement for full-featured SIEM or IDS/IPS.

---

**Pull requests, suggestions, and improvements are welcome!**

---
