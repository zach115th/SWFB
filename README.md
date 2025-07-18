# Simple Windows Firewall Bouncer (SWFB)

**Simple Windows Firewall Bouncer (SWFB)** is a self-contained PowerShell script that automates blocking of brute-force and password spray attacks using Windows Firewall. It scans Windows Security Event Logs for failed logon attempts and blocks suspicious IPs dynamically based on configurable thresholds and patterns, helping protect Windows systems with no third-party dependencies.

---

## Features

- **Automatic Blocking:** Stops brute-force, password spray, and distributed username attacks.
- **Configurable:** Tune thresholds for failed logons, username spray, and more.
- **Auto-Unblocking:** Removes blocks after a specified duration.
- **Stateful:** Remembers blocked IPs and host info in a JSON file.
- **Zero Dependencies:** Only requires Windows PowerShell and Windows Firewall.

---

## How It Works

- Automated Blocking: Detects and blocks IPs with repeated failed logons, password sprays, or distributed username targeting.

- Adaptive Detection: Customizable thresholds for failed attempts, username spray, and user spray detection.

- Self-Healing: Unblocks IPs automatically after a configurable expiration period.

- Stateful: Persists blocked IPs and host info across reboots/runs via a simple JSON file.

- No External Dependencies: Uses only built-in Windows PowerShell, Windows Firewall, and standard logs.

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

