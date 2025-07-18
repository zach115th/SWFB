# Simple Windows Firewall Bouncer (SWFB)

**Simple Windows Firewall Bouncer (SWFB)** is a PowerShell script for automated brute-force and password spray protection using built-in Windows Firewall. It watches failed logon attempts (Event ID 4625) and dynamically blocks suspicious public IPs—no third-party tools required.

---

## Features

- **Automatic Blocking:** Stops brute-force, password spray, and distributed username attacks.
- **Configurable:** Tune thresholds for failed logons, username spray, and more.
- **Auto-Unblocking:** Removes blocks after a specified duration.
- **Stateful:** Remembers blocked IPs and host info in a JSON file.
- **Zero Dependencies:** Only requires Windows PowerShell and Windows Firewall.

---

## How It Works

- Monitors the Windows Security event log for failed login attempts (`Event ID 4625`).
- Tracks source IPs, usernames, and destination ports.
- Applies firewall blocks when an IP:
    - Hits too many failed logons in the time window.
    - Attempts too many unique usernames (password spray).
    - A single username is targeted from too many IPs (user spray).
- Automatically expires and removes old firewall blocks.
- Persists blocked IPs and host info in `blocked_ips.json`.

---

## Requirements

- Windows 10, 11, or Server with PowerShell 5.x+
- **Run as Administrator** (required for firewall and event log access)
- Windows Firewall enabled

---

## Installation

1. Download `swfb.ps1` to your system.
2. Open PowerShell **as Administrator**.
3. (Optional) Edit the script’s parameter block at the top to fit your environment.

---

## Usage

```powershell
.\swfb.ps1

