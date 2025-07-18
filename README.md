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
  - It tries to log in as more than a set number of usernames (password spray).
  - A single username is targeted from too many source IPs (user spray).
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
