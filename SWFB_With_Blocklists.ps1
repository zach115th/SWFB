param(
    [int]$FailedAttemptThreshold = 5,             # Threshold for number of failed login attempts per IP before blocking
    [int]$TimeWindowMinutes = 5,                  # Time window to look for failed logins
    [int]$BlockDurationDays = 30,                 # How long to keep an IP blocked
    [string[]]$Whitelist = @("8.8.8.8","1.1.1.1"),# List of IPs that are never blocked
    [int]$ScanIntervalMinutes = 1,                # How often the main loop should scan logs
    [int]$MaxUsernamesPerIp = 2,                  # Block IP if it tries more than this many usernames in window
    [int]$MaxIpsPerUsername = 2,                  # Block all IPs if a single username is targeted from this many IPs
    [string[]]$BlocklistUrls = @("https://github.com/zach115th/BlockLists/blob/main/emerging-threats/2025/toolshell/toolshell_ips.txt")                # URLs to txt files containing IPs to block
)

# --- NEW: Download and block IPs from external blocklists ---
function Apply-ExternalBlocklists {
    param([string[]]$Urls)
    if (-not $Urls -or $Urls.Count -eq 0) { return }
    $allBlocklistIps = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($url in $Urls) {
        try {
            Write-Host "Downloading blocklist from $url..."
            $raw = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
            $ips = ($raw.Content -split "`r?`n") | Where-Object {
                $_ -match '^\d{1,3}(\.\d{1,3}){3}$'
            }
            foreach ($ip in $ips) { $allBlocklistIps.Add($ip) | Out-Null }
        } catch {
            Write-Warning "Failed to download or parse $url: $_"
        }
    }
    if ($allBlocklistIps.Count -eq 0) {
        Write-Host "No IPs found in blocklists."
        return
    }
    $ipString = ($allBlocklistIps | Sort-Object) -join ","
    $ruleName = "Block_ExternalBlocklist"
    netsh advfirewall firewall delete rule name="$ruleName" | Out-Null
    netsh advfirewall firewall add rule name="$ruleName" dir=in  action=block remoteip=$ipString | Out-Null
    netsh advfirewall firewall add rule name="$ruleName" dir=out action=block remoteip=$ipString | Out-Null
}
Apply-ExternalBlocklists -Urls $BlocklistUrls
# --- END NEW ---

# File & state variables
$BlockedIPsFile = "blocked_ips.json"                                   # File where state of blocked IPs is stored
$FirewallLog = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"   # Path to Windows firewall log
$script:RecentlyExpired = @()                                          # IPs recently unblocked, to avoid instant re-block
$script:ipToPort = @{}                                                 # Cache: maps IP to last destination port seen

# Host Info & Firewall Logging Setup
try {
    # Try to enable firewall logging for all active profiles, so destination port can be pulled later
    $profiles = Get-NetFirewallProfile -PolicyStore ActiveStore
    foreach ($p in $profiles) {
        Set-NetFirewallProfile -Name $p.Name -LogAllowed True -LogBlocked True -LogFileName $FirewallLog
    }
} catch {
    # If enabling logging fails, print a warning
    Write-Warning "Could not enable firewall logging: $_"
}

try {
    # Find first usable private IPv4 address (ignores loopback, APIPA, etc)
    $LocalIP  = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
        Select-Object -ExpandProperty IPAddress -First 1
    # Query a public IP detection API (ipify)
    $PublicIP = Invoke-RestMethod -Uri 'https://api.ipify.org'
} catch {
    # If any error, just null out public IP (non-fatal)
    $PublicIP = $null
}

# Store host info as an ordered hash, for saving state
$HostInfo = [ordered]@{
    PublicIP = $PublicIP
    PrivateIP = $LocalIP
    LastUpdated = (Get-Date).ToString('o')    # ISO 8601
}

# State Load
if (Test-Path $BlockedIPsFile) {
    # If state file exists, load all saved info and list of blocked IPs
    $data = Get-Content $BlockedIPsFile -Raw | ConvertFrom-Json
    $HostInfo = $data.HostInfo
    $script:BlockedIPs = [object[]]$data.BlockedIPs
} else {
    # Otherwise, start with empty list
    $script:BlockedIPs = @()
}

# Function: Save-BlockedIPs
function Save-BlockedIPs {
    # Refresh last updated timestamp
    $HostInfo.LastUpdated = (Get-Date).ToString('o')
    # Save both host info and currently blocked IPs (for persistence across restarts)
    [ordered]@{
        HostInfo = $HostInfo
        BlockedIPs = $script:BlockedIPs
    } | ConvertTo-Json -Depth 5 | Set-Content $BlockedIPsFile
}

# Function: Is-PublicIP
function Is-PublicIP {
    param([string]$ip)
    # Checks if $ip is a routable/public IP
    if ([IPAddress]::TryParse($ip, [ref]0)) {
        $o = $ip -split '\.'
        # Check for private and reserved blocks
        if ($o[0] -eq '10' -or $o[0] -eq '127' -or ($o[0] -eq '169' -and $o[1] -eq '254') -or 
            ($o[0] -eq '172' -and ($o[1] -ge 16 -and $o[1] -le 31)) -or ($o[0] -eq '192' -and $o[1] -eq '168')) {
            return $false
        }
        return $true
    }
    return $false
}

# Function: ExtractIPPort
function ExtractIPPort {
    param([string]$msg)
    $ip = $null
    $port = $null

    # Pulls source IP from log event if present
    if ($msg -match 'Source Network Address:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})') { $ip = $matches[1] }
    # Pulls source port if present
    if ($msg -match 'Source Port:\s+(\d{1,5})') { $port = $matches[1] }
    # Tries to find inline IP:Port as fallback
    if (-not $ip -and $msg -match '([0-9]{1,3}(?:\.[0-9]{1,3}){3}):(\d{1,5})') {
        $ip = $matches[1]; if (-not $port) { $port = $matches[2] }
    }
    # Final fallback: any lone IP in log message
    if (-not $ip -and $msg -match '([0-9]{1,3}(?:\.[0-9]{1,3}){3})') { $ip = $matches[1] }
    return @{ Ip = $ip; Port = $port }
}

# Function: ExtractUser
function ExtractUser {
    param([string]$msg)
    # Extracts username from event message (ignoring built-in and machine accounts)
    foreach ($m in [regex]::Matches($msg, 'Account Name:\s+([^\s]+)')) {
        $u = $m.Groups[1].Value
        if ($u -and $u -ne '-' -and $u -notmatch '\$$' -and $u -notlike 'SYSTEM' -and $u -notlike 'LOCAL*') {
            return $u
        }
    }
    return $null
}

# Function: Get-DestPortFromFirewallLog
function Get-DestPortFromFirewallLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ip,       # The remote IP to search for
        [Parameter(Mandatory)][datetime]$eventTime  # Approximate event time
    )

    $logPath = $script:FirewallLog
    if (-not (Test-Path $logPath)) {
        Write-Verbose "Firewall log not found at $logPath"
        return $null
    }

    $pattern = '\b' + [regex]::Escape($ip) + '\b'   # Build regex for matching just this IP
    $windowStart = $eventTime.AddSeconds(-10)       # Search 10 seconds before/after event time
    $windowEnd = $eventTime.AddSeconds( 10)

    # Find all matching lines in firewall log for this IP
    $entries = Select-String -Path $logPath -Pattern $pattern |
               ForEach-Object { $_.Line }

    foreach ($line in $entries) {
        $trimmed = $line.Trim()
        # Ignore comments, headers, and blank lines
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) {
            continue
        }

        # pfirewall.log splits on whitespace; expect at least 8 fields
        $parts = $trimmed -split '\s+'
        if ($parts.Count -lt 8) {
            Write-Verbose "Skipping malformed line: $line"
            continue
        }

        # Parse log date and time
        $timeStr = "$($parts[0]) $($parts[1])"
        $logTime = Get-Date $timeStr -ErrorAction SilentlyContinue
        if (-not $logTime) {
            Write-Verbose "Unable to parse date/time from: $timeStr"
            continue
        }

        # If within window, grab the destination port (8th field)
        if ($logTime -ge $windowStart -and $logTime -le $windowEnd) {
            $dstPort = $parts[7]
            Write-Verbose "Matched line at $logTime → DstPort = $dstPort"
            return $dstPort
        }
    }

    Write-Verbose "No matching firewall entry for $ip in window $windowStart - $windowEnd"
    return $null
}

# Function: Remove-OldBlocks
function Remove-OldBlocks {
    $script:RecentlyExpired = @()                    # Clear list of IPs just unblocked
    $cutoff = (Get-Date).AddDays(-$BlockDurationDays)         # Calculate time cutoff for expiration
    $valid = $script:BlockedIPs | Where-Object { $_.BlockedDate } # Only consider entries with a BlockedDate
    # Find expired blocks
    $expired = $valid | Where-Object { ([datetime]$_.BlockedDate) -lt $cutoff }
    foreach ($e in $expired) {
        Write-Host "Removing expired IP $($e.Ip)"
        # Remove firewall rule
        netsh advfirewall firewall delete rule name="Block_$($e.Ip)_FailedLogins" | Out-Null
        # Add to recently expired so it isn't instantly re-blocked
        $script:RecentlyExpired += $e.Ip
    }
    # Keep only non-expired entries
    $script:BlockedIPs = $valid | Where-Object { ([datetime]$_.BlockedDate) -ge $cutoff }
    Save-BlockedIPs
}

# Function: Block-IP
function Block-IP {
    param([string]$ip)
    # Don't block if IP is already blocked, or was just expired this cycle
    if ($script:BlockedIPs.Ip -contains $ip -or $script:RecentlyExpired -contains $ip) { return }
    $port = $script:ipToPort[$ip]   # Pull last known destination port for this IP (may be null)
    $entry = [PSCustomObject]@{ Ip=$ip; Port=$port; BlockedDate=(Get-Date).ToString('o') }
    $script:BlockedIPs = @($script:BlockedIPs) + $entry
    Save-BlockedIPs
    Write-Host "Blocking IP $ip on port $port"
    netsh advfirewall firewall add rule name="Block_${ip}_FailedLogins" dir=in action=block remoteip=$ip | Out-Null
}

# Main Loop
Write-Host "Starting Simple Windows Firewall Bouncer..."
while ($true) {
    # Remove old blocks based on expiration
    Remove-OldBlocks
    # Set search window start time for failed logon events
    $start = (Get-Date).AddMinutes(-$TimeWindowMinutes)
    $failures = @{}; $ipUsers = @{}; $userIps = @{}

    # Parse failed logon (4625) events from Security log
    Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$start } |
      ForEach-Object {
        $evtTime = $_.TimeCreated                       # Logon attempt time
        $r = ExtractIPPort $_.Message                   # Get source IP/Port
        $u = ExtractUser $_.Message                     # Get username
        if ($r.Ip -and $u -and (Is-PublicIP $r.Ip) -and ($Whitelist -notcontains $r.Ip)) {
            # Find destination port (if available) for this IP at this time
            $dest = Get-DestPortFromFirewallLog -ip $r.Ip -eventTime $evtTime
            $script:ipToPort[$r.Ip] = $dest
            
            # Count number of failed attempts from this IP
            if (-not $failures.ContainsKey($r.Ip)) { $failures[$r.Ip] = @() }
            $failures[$r.Ip] += $evtTime
            # Track unique usernames per IP for password spray detection
            if (-not $ipUsers.ContainsKey($r.Ip)) { $ipUsers[$r.Ip] = [System.Collections.Generic.HashSet[string]]::new() }
            $ipUsers[$r.Ip].Add($u) | Out-Null
            # Track unique IPs per username for user spray detection
            if (-not $userIps.ContainsKey($u))  { $userIps[$u]  = [System.Collections.Generic.HashSet[string]]::new() }
            $userIps[$u].Add($r.Ip) | Out-Null
        }
      }

    # Block IPs for repeated failed logins
    foreach ($ip in $failures.Keys) { if ($failures[$ip].Count -ge $FailedAttemptThreshold) { Block-IP $ip } }
    # Block IPs doing password spray (multiple usernames from one IP)
    foreach ($ip in $ipUsers.Keys)    { if ($ipUsers[$ip].Count -ge $MaxUsernamesPerIp) { Block-IP $ip } }
    # Block IPs for user spray (single user, multiple source IPs)
    foreach ($user in $userIps.Keys)  { if ($userIps[$user].Count -ge $MaxIpsPerUsername) { foreach ($ip in $userIps[$user]) { Block-IP $ip } } }

    Write-Host "Cycle complete; sleeping $ScanIntervalMinutes minute(s)."
    Start-Sleep -Seconds ($ScanIntervalMinutes * 60)
}
