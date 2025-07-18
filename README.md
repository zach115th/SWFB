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

---

## Paramaters

---
