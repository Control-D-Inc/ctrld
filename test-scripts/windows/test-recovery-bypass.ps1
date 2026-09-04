# test-recovery-bypass.ps1 — Test DNS intercept recovery bypass (captive portal simulation)
#
# Simulates a captive portal by:
#   1. Discovering ctrld's upstream IPs from active connections
#   2. Blocking them via Windows Firewall rules
#   3. Disabling/re-enabling the wifi adapter to trigger network change
#   4. Verifying recovery bypass forwards to OS/DHCP resolver
#   5. Removing firewall rules and verifying normal operation resumes
#
# SAFE: Uses named firewall rules that are cleaned up on exit.
#
# Usage (run as Administrator):
#   .\test-recovery-bypass.ps1 [-WifiAdapter "Wi-Fi"] [-CtrldLog "C:\temp\dns.log"]
#
# Prerequisites:
#   - ctrld running with --dns-intercept and -v 1 --log C:\temp\dns.log
#   - Run as Administrator

param(
    [string]$WifiAdapter = "Wi-Fi",
    [string]$CtrldLog = "C:\temp\dns.log",
    [int]$BlockDurationSec = 60
)

$ErrorActionPreference = "Stop"
$FwRulePrefix = "ctrld-test-recovery-block"
$BlockedIPs = @()

function Log($msg)  { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor Cyan }
function Pass($msg) { Write-Host "[PASS] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red }
function Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }

# ── Safety: cleanup function ─────────────────────────────────────────────────
function Cleanup {
    Log "═══ CLEANUP ═══"

    # Ensure wifi is enabled
    Log "Ensuring wifi adapter is enabled..."
    try { Enable-NetAdapter -Name $WifiAdapter -Confirm:$false -ErrorAction SilentlyContinue } catch {}

    # Remove all test firewall rules
    Log "Removing test firewall rules..."
    Get-NetFirewallRule -DisplayName "$FwRulePrefix*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Log "Cleanup complete."
}

# Register cleanup on script exit
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Cleanup } -ErrorAction SilentlyContinue
trap { Cleanup; break }

# ── Pre-checks ───────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Fail "Run as Administrator!"
    exit 1
}

if (-not (Test-Path $CtrldLog)) {
    Fail "ctrld log not found at $CtrldLog"
    Write-Host "Start ctrld with: ctrld run --dns-intercept --cd <uid> -v 1 --log $CtrldLog"
    exit 1
}

# Check wifi adapter exists
$adapter = Get-NetAdapter -Name $WifiAdapter -ErrorAction SilentlyContinue
if (-not $adapter) {
    Fail "Wifi adapter '$WifiAdapter' not found"
    Write-Host "Available adapters:"
    Get-NetAdapter | Format-Table Name, Status, InterfaceDescription
    exit 1
}

Log "═══════════════════════════════════════════════════════════"
Log "  Recovery Bypass Test (Captive Portal Simulation)"
Log "═══════════════════════════════════════════════════════════"
Log "Wifi adapter: $WifiAdapter"
Log "ctrld log:    $CtrldLog"
Write-Host ""

# ── Phase 1: Discover upstream IPs ──────────────────────────────────────────
Log "Phase 1: Discovering ctrld upstream IPs from active connections"

$ctrldConns = Get-NetTCPConnection -OwningProcess (Get-Process ctrld* -ErrorAction SilentlyContinue).Id -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq "Established" -and $_.RemotePort -eq 443 }

$upstreamIPs = @()
if ($ctrldConns) {
    $upstreamIPs = $ctrldConns | Select-Object -ExpandProperty RemoteAddress -Unique |
        Where-Object { $_ -notmatch "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)" }

    foreach ($conn in $ctrldConns) {
        Log "  $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)"
    }
}

# Also resolve known Control D endpoints
foreach ($host_ in @("dns.controld.com", "freedns.controld.com")) {
    try {
        $resolved = Resolve-DnsName $host_ -Type A -ErrorAction SilentlyContinue
        $resolved | ForEach-Object { if ($_.IPAddress) { $upstreamIPs += $_.IPAddress } }
    } catch {}
}

$upstreamIPs = $upstreamIPs | Sort-Object -Unique

if ($upstreamIPs.Count -eq 0) {
    Fail "Could not discover any upstream IPs!"
    exit 1
}

Log "Found $($upstreamIPs.Count) upstream IP(s):"
foreach ($ip in $upstreamIPs) { Log "  $ip" }
Write-Host ""

# ── Phase 2: Baseline ───────────────────────────────────────────────────────
Log "Phase 2: Baseline — verify DNS works normally"
$baseline = Resolve-DnsName example.com -Server 127.0.0.1 -Type A -ErrorAction SilentlyContinue
if ($baseline) {
    Pass "Baseline: example.com -> $($baseline[0].IPAddress)"
} else {
    Fail "DNS not working!"
    exit 1
}

$logLinesBefore = (Get-Content $CtrldLog).Count
Log "Log position: line $logLinesBefore"
Write-Host ""

# ── Phase 3: Block upstream IPs via Windows Firewall ────────────────────────
Log "Phase 3: Blocking upstream IPs via Windows Firewall"
foreach ($ip in $upstreamIPs) {
    $ruleName = "$FwRulePrefix-$ip"
    # Remove existing rule if any
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    # Block outbound to this IP
    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block `
        -RemoteAddress $ip -Protocol TCP -RemotePort 443 `
        -Description "Temporary test rule for ctrld recovery bypass test" | Out-Null
    $BlockedIPs += $ip
    Log "  Blocked: $ip (outbound TCP 443)"
}
Pass "All $($upstreamIPs.Count) upstream IPs blocked"
Write-Host ""

# ── Phase 4: Cycle wifi ─────────────────────────────────────────────────────
Log "Phase 4: Cycling wifi to trigger network change event"
Log "  Disabling $WifiAdapter..."
Disable-NetAdapter -Name $WifiAdapter -Confirm:$false
Start-Sleep -Seconds 3

Log "  Enabling $WifiAdapter..."
Enable-NetAdapter -Name $WifiAdapter -Confirm:$false

Log "  Waiting for wifi to reconnect (up to 20s)..."
$wifiUp = $false
for ($i = 0; $i -lt 20; $i++) {
    $status = (Get-NetAdapter -Name $WifiAdapter).Status
    if ($status -eq "Up") {
        # Check for IP
        $ipAddr = (Get-NetIPAddress -InterfaceAlias $WifiAdapter -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        if ($ipAddr) {
            $wifiUp = $true
            Pass "Wifi reconnected: $WifiAdapter -> $ipAddr"
            break
        }
    }
    Start-Sleep -Seconds 1
}

if (-not $wifiUp) {
    Fail "Wifi did not reconnect in 20s!"
    Cleanup
    exit 1
}

Log "  Waiting 5s for ctrld network monitor..."
Start-Sleep -Seconds 5
Write-Host ""

# ── Phase 5: Query and watch for recovery ────────────────────────────────────
Log "Phase 5: Sending queries — upstream blocked, recovery should activate"
Write-Host ""

$recoveryDetected = $false
$bypassActive = $false
$dnsDuringBypass = $false

for ($q = 1; $q -le 30; $q++) {
    $result = $null
    try {
        $result = Resolve-DnsName "example.com" -Server 127.0.0.1 -Type A -DnsOnly -ErrorAction SilentlyContinue
    } catch {}

    if ($result) {
        Log "  Query #$q`: example.com -> $($result[0].IPAddress) ✓"
    } else {
        Log "  Query #$q`: example.com -> FAIL ✗"
    }

    # Check ctrld log for recovery
    $newLogs = Get-Content $CtrldLog | Select-Object -Skip $logLinesBefore
    $logText = $newLogs -join "`n"

    if (-not $recoveryDetected -and ($logText -match "enabling DHCP bypass|triggering recovery|No healthy")) {
        Write-Host ""
        Pass "🎯 Recovery flow triggered!"
        $recoveryDetected = $true
    }

    if (-not $bypassActive -and ($logText -match "Recovery bypass active")) {
        Pass "🔄 Recovery bypass forwarding to OS/DHCP resolver"
        $bypassActive = $true
    }

    if ($recoveryDetected -and $result) {
        Pass "✅ DNS resolves during recovery: example.com -> $($result[0].IPAddress)"
        $dnsDuringBypass = $true
        break
    }

    Start-Sleep -Seconds 2
}

# ── Phase 6: Show log entries ────────────────────────────────────────────────
Write-Host ""
Log "Phase 6: Recovery-related ctrld log entries"
Log "────────────────────────────────────────────"
$newLogs = Get-Content $CtrldLog | Select-Object -Skip $logLinesBefore
$relevant = $newLogs | Where-Object { $_ -match "recovery|bypass|DHCP|unhealthy|upstream.*fail|No healthy|network change|OS resolver" }
if ($relevant) {
    $relevant | Select-Object -First 30 | ForEach-Object { Write-Host "  $_" }
} else {
    Warn "No recovery-related log entries found"
    Get-Content $CtrldLog | Select-Object -Last 10 | ForEach-Object { Write-Host "  $_" }
}

# ── Phase 7: Unblock and verify ─────────────────────────────────────────────
Write-Host ""
Log "Phase 7: Removing firewall blocks"
Get-NetFirewallRule -DisplayName "$FwRulePrefix*" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
$BlockedIPs = @()
Pass "Firewall rules removed"

Log "Waiting for recovery (up to 30s)..."
$logLinesUnblock = (Get-Content $CtrldLog).Count
$recoveryComplete = $false

for ($i = 0; $i -lt 15; $i++) {
    try { Resolve-DnsName example.com -Server 127.0.0.1 -Type A -DnsOnly -ErrorAction SilentlyContinue } catch {}
    $postLogs = (Get-Content $CtrldLog | Select-Object -Skip $logLinesUnblock) -join "`n"
    if ($postLogs -match "recovery complete|disabling DHCP bypass|Upstream.*recovered") {
        $recoveryComplete = $true
        Pass "ctrld recovered — normal operation resumed"
        break
    }
    Start-Sleep -Seconds 2
}

if (-not $recoveryComplete) { Warn "Recovery completion not detected (may need more time)" }

# ── Phase 8: Final check ────────────────────────────────────────────────────
Write-Host ""
Log "Phase 8: Final DNS verification"
Start-Sleep -Seconds 2
$final = Resolve-DnsName example.com -Server 127.0.0.1 -Type A -ErrorAction SilentlyContinue
if ($final) {
    Pass "DNS working: example.com -> $($final[0].IPAddress)"
} else {
    Fail "DNS not resolving"
}

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host ""
Log "═══════════════════════════════════════════════════════════"
Log "  Test Summary"
Log "═══════════════════════════════════════════════════════════"
if ($recoveryDetected) { Pass "Recovery bypass activated" } else { Fail "Recovery bypass NOT activated" }
if ($bypassActive)     { Pass "Queries forwarded to OS/DHCP" } else { Warn "OS resolver forwarding not confirmed" }
if ($dnsDuringBypass)  { Pass "DNS resolved during bypass" } else { Warn "DNS during bypass not confirmed" }
if ($recoveryComplete) { Pass "Normal operation resumed" } else { Warn "Recovery completion not confirmed" }
if ($final)            { Pass "DNS functional at end of test" } else { Fail "DNS broken at end of test" }
Write-Host ""
Log "Full log: Get-Content $CtrldLog | Select-Object -Skip $logLinesBefore"

# Cleanup runs via trap
Cleanup
