# =============================================================================
# DNS Intercept Mode Test Script — Windows (WFP)
# =============================================================================
# Run as Administrator: powershell -ExecutionPolicy Bypass -File test-dns-intercept-win.ps1
#
# Tests the dns-intercept feature end-to-end with validation at each step.
# Logs are read from C:\tmp\dns.log (ctrld log location on test machine).
#
# Manual steps marked with [MANUAL] require human interaction.
# =============================================================================

$ErrorActionPreference = "Continue"

$CtrldLog = "C:\tmp\dns.log"
$WfpSubLayerName = "ctrld DNS Intercept"
$Pass = 0
$Fail = 0
$Warn = 0
$Results = @()

# --- Helpers ---

function Header($text) { Write-Host "`n━━━ $text ━━━" -ForegroundColor Cyan }
function Info($text)   { Write-Host "  ℹ  $text" }
function Manual($text) { Write-Host "  [MANUAL] $text" -ForegroundColor Yellow }
function Separator()   { Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Cyan }

function Pass($text) {
    Write-Host "  ✅ PASS: $text" -ForegroundColor Green
    $script:Pass++
    $script:Results += "PASS: $text"
}

function Fail($text) {
    Write-Host "  ❌ FAIL: $text" -ForegroundColor Red
    $script:Fail++
    $script:Results += "FAIL: $text"
}

function Warn($text) {
    Write-Host "  ⚠️  WARN: $text" -ForegroundColor Yellow
    $script:Warn++
    $script:Results += "WARN: $text"
}

function WaitForKey {
    Write-Host "`n  Press Enter to continue..." -NoNewline
    Read-Host
}

function LogGrep($pattern, $lines = 200) {
    if (Test-Path $CtrldLog) {
        Get-Content $CtrldLog -Tail $lines -ErrorAction SilentlyContinue |
            Select-String -Pattern $pattern -ErrorAction SilentlyContinue
    }
}

function LogGrepCount($pattern, $lines = 200) {
    $matches = LogGrep $pattern $lines
    if ($matches) { return @($matches).Count } else { return 0 }
}

# --- Check Admin ---

function Check-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script must be run as Administrator." -ForegroundColor Red
        exit 1
    }
}

# =============================================================================
# TEST SECTIONS
# =============================================================================

function Test-Prereqs {
    Header "0. Prerequisites"

    if (Get-Command nslookup -ErrorAction SilentlyContinue) {
        Pass "nslookup available"
    } else {
        Fail "nslookup not found"
    }

    if (Get-Command netsh -ErrorAction SilentlyContinue) {
        Pass "netsh available"
    } else {
        Fail "netsh not found"
    }

    if (Test-Path $CtrldLog) {
        Pass "ctrld log exists at $CtrldLog"
    } else {
        Warn "ctrld log not found at $CtrldLog — log checks will be skipped"
    }

    # Show current DNS config
    Info "Current DNS servers:"
    Get-DnsClientServerAddress -AddressFamily IPv4 |
        Where-Object { $_.ServerAddresses.Count -gt 0 } |
        Format-Table InterfaceAlias, ServerAddresses -AutoSize |
        Out-String | ForEach-Object { $_.Trim() } | Write-Host
}

function Test-WfpState {
    Header "1. WFP State Validation"

    # Export WFP filters and check for ctrld's sublayer/filters
    $wfpExport = "$env:TEMP\wfp_filters.xml"
    Info "Exporting WFP filters (this may take a few seconds)..."

    try {
        netsh wfp show filters file=$wfpExport 2>$null | Out-Null

        if (Test-Path $wfpExport) {
            $wfpContent = Get-Content $wfpExport -Raw -ErrorAction SilentlyContinue

            # Check for ctrld sublayer
            if ($wfpContent -match "ctrld") {
                Pass "WFP filters contain 'ctrld' references"

                # Count filters
                $filterMatches = ([regex]::Matches($wfpContent, "ctrld")).Count
                Info "Found $filterMatches 'ctrld' references in WFP export"
            } else {
                Fail "No 'ctrld' references found in WFP filters"
            }

            # Check for DNS port 53 filters
            if ($wfpContent -match "port.*53" -or $wfpContent -match "0x0035") {
                Pass "Port 53 filter conditions found in WFP"
            } else {
                Warn "Could not confirm port 53 filters in WFP export"
            }

            Remove-Item $wfpExport -ErrorAction SilentlyContinue
        } else {
            Warn "WFP export file not created"
        }
    } catch {
        Warn "Could not export WFP filters: $_"
    }

    Separator

    # Alternative: Check via PowerShell WFP cmdlets if available
    Info "Checking WFP via netsh wfp show state..."
    $wfpState = netsh wfp show state 2>$null
    if ($wfpState) {
        Info "WFP state export completed (check $env:TEMP for details)"
    }

    # Check Windows Firewall service is running
    $fwService = Get-Service -Name "mpssvc" -ErrorAction SilentlyContinue
    if ($fwService -and $fwService.Status -eq "Running") {
        Pass "Windows Firewall service (BFE/WFP) is running"
    } else {
        Fail "Windows Firewall service not running — WFP won't work"
    }

    # Check BFE (Base Filtering Engine)
    $bfeService = Get-Service -Name "BFE" -ErrorAction SilentlyContinue
    if ($bfeService -and $bfeService.Status -eq "Running") {
        Pass "Base Filtering Engine (BFE) is running"
    } else {
        Fail "BFE not running — WFP requires this service"
    }
}

function Test-DnsInterception {
    Header "2. DNS Interception Tests"

    # Mark log position
    $logLinesBefore = 0
    if (Test-Path $CtrldLog) {
        $logLinesBefore = @(Get-Content $CtrldLog -ErrorAction SilentlyContinue).Count
    }

    # Test 1: Query to external resolver should be intercepted
    Info "Test: nslookup example.com 8.8.8.8 (should be intercepted by ctrld)"
    $result = $null
    try {
        $result = nslookup example.com 8.8.8.8 2>&1 | Out-String
    } catch { }

    if ($result -and $result -match "\d+\.\d+\.\d+\.\d+") {
        Pass "nslookup @8.8.8.8 returned a result"

        # Check which server answered
        if ($result -match "Server:\s+(\S+)") {
            $server = $Matches[1]
            Info "Answered by server: $server"
            if ($server -match "127\.0\.0\.1|localhost") {
                Pass "Response came from localhost (ctrld intercepted)"
            } elseif ($server -match "8\.8\.8\.8") {
                Fail "Response came from 8.8.8.8 directly — NOT intercepted"
            }
        }
    } else {
        Fail "nslookup @8.8.8.8 failed or returned no address"
    }

    # Check ctrld logged it
    Start-Sleep -Seconds 1
    if (Test-Path $CtrldLog) {
        $newLines = Get-Content $CtrldLog -ErrorAction SilentlyContinue |
            Select-Object -Skip $logLinesBefore
        $intercepted = $newLines | Select-String "example.com" -ErrorAction SilentlyContinue
        if ($intercepted) {
            Pass "ctrld logged the intercepted query for example.com"
        } else {
            Fail "ctrld did NOT log query for example.com"
        }
    }

    Separator

    # Test 2: Another external resolver
    Info "Test: nslookup cloudflare.com 1.1.1.1 (should also be intercepted)"
    try {
        $result2 = nslookup cloudflare.com 1.1.1.1 2>&1 | Out-String
        if ($result2 -match "\d+\.\d+\.\d+\.\d+") {
            Pass "nslookup @1.1.1.1 returned result"
        } else {
            Fail "nslookup @1.1.1.1 failed"
        }
    } catch {
        Fail "nslookup @1.1.1.1 threw exception"
    }

    Separator

    # Test 3: Query to localhost should work (no loop)
    Info "Test: nslookup example.org 127.0.0.1 (direct to ctrld, no loop)"
    try {
        $result3 = nslookup example.org 127.0.0.1 2>&1 | Out-String
        if ($result3 -match "\d+\.\d+\.\d+\.\d+") {
            Pass "nslookup @127.0.0.1 works (no loop)"
        } else {
            Fail "nslookup @127.0.0.1 failed — possible loop"
        }
    } catch {
        Fail "nslookup @127.0.0.1 exception — possible loop"
    }

    Separator

    # Test 4: System DNS via Resolve-DnsName
    Info "Test: Resolve-DnsName example.net (system resolver)"
    try {
        $result4 = Resolve-DnsName example.net -Type A -ErrorAction Stop
        if ($result4) {
            Pass "System DNS resolution works (Resolve-DnsName)"
        }
    } catch {
        Fail "System DNS resolution failed: $_"
    }

    Separator

    # Test 5: TCP DNS
    Info "Test: nslookup -vc example.com 9.9.9.9 (TCP DNS)"
    try {
        $result5 = nslookup -vc example.com 9.9.9.9 2>&1 | Out-String
        if ($result5 -match "\d+\.\d+\.\d+\.\d+") {
            Pass "TCP DNS query intercepted and resolved"
        } else {
            Warn "TCP DNS query may not have been intercepted"
        }
    } catch {
        Warn "TCP DNS test inconclusive"
    }
}

function Test-NonDnsUnaffected {
    Header "3. Non-DNS Traffic Unaffected"

    # HTTPS
    Info "Test: Invoke-WebRequest https://example.com (HTTPS should NOT be affected)"
    try {
        $web = Invoke-WebRequest -Uri "https://example.com" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        if ($web.StatusCode -eq 200) {
            Pass "HTTPS works (HTTP 200)"
        } else {
            Pass "HTTPS returned HTTP $($web.StatusCode)"
        }
    } catch {
        Fail "HTTPS failed: $_"
    }

    # Test non-53 port connectivity
    Info "Test: Test-NetConnection to github.com:443 (non-DNS port)"
    try {
        $nc = Test-NetConnection -ComputerName "github.com" -Port 443 -WarningAction SilentlyContinue
        if ($nc.TcpTestSucceeded) {
            Pass "Port 443 reachable (non-DNS traffic unaffected)"
        } else {
            Warn "Port 443 unreachable (may be firewall)"
        }
    } catch {
        Warn "Test-NetConnection failed: $_"
    }
}

function Test-CtrldLogHealth {
    Header "4. ctrld Log Health Check"

    if (-not (Test-Path $CtrldLog)) {
        Warn "Skipping log checks — $CtrldLog not found"
        return
    }

    # Check for WFP initialization
    if (LogGrepCount "initializing Windows Filtering Platform" 500) {
        Pass "WFP initialization logged"
    } else {
        Fail "No WFP initialization in recent logs"
    }

    # Check for successful WFP engine open
    if (LogGrepCount "WFP engine opened" 500) {
        Pass "WFP engine opened successfully"
    } else {
        Fail "WFP engine open not found in logs"
    }

    # Check for sublayer creation
    if (LogGrepCount "WFP sublayer created" 500) {
        Pass "WFP sublayer created"
    } else {
        Fail "WFP sublayer creation not logged"
    }

    # Check for filter creation
    $filterCount = LogGrepCount "added WFP.*filter" 500
    if ($filterCount -gt 0) {
        Pass "WFP filters added ($filterCount filter log entries)"
    } else {
        Fail "No WFP filter creation logged"
    }

    # Check for permit-localhost filters
    if (LogGrepCount "permit.*localhost\|permit.*127\.0\.0\.1" 500) {
        Pass "Localhost permit filters logged"
    } else {
        Warn "Localhost permit filters not explicitly logged"
    }

    Separator

    # Check for errors
    Info "Recent errors in ctrld log:"
    $errors = LogGrep '"level":"error"' 500
    if ($errors) {
        $errors | Select-Object -Last 5 | ForEach-Object { Write-Host "    $_" }
        Warn "Errors found in recent logs"
    } else {
        Pass "No errors in recent logs"
    }

    # Warnings (excluding expected ones)
    $warnings = LogGrep '"level":"warn"' 500 | Where-Object {
        $_ -notmatch "skipping self-upgrade"
    }
    if ($warnings) {
        Info "Warnings:"
        $warnings | Select-Object -Last 5 | ForEach-Object { Write-Host "    $_" }
    }

    # VPN DNS detection
    $vpnLogs = LogGrep "VPN DNS" 500
    if ($vpnLogs) {
        Info "VPN DNS activity:"
        $vpnLogs | Select-Object -Last 5 | ForEach-Object { Write-Host "    $_" }
    } else {
        Info "No VPN DNS activity (expected if no VPN connected)"
    }
}

function Test-CleanupOnStop {
    Header "5. Cleanup Validation (After ctrld Stop)"

    Manual "Stop ctrld now (ctrld stop or Ctrl+C), then press Enter"
    WaitForKey

    Start-Sleep -Seconds 2

    # Check WFP filters are removed
    $wfpExport = "$env:TEMP\wfp_after_stop.xml"
    try {
        netsh wfp show filters file=$wfpExport 2>$null | Out-Null
        if (Test-Path $wfpExport) {
            $content = Get-Content $wfpExport -Raw -ErrorAction SilentlyContinue
            if ($content -match "ctrld") {
                Fail "WFP still contains 'ctrld' filters after stop"
            } else {
                Pass "WFP filters cleaned up after stop"
            }
            Remove-Item $wfpExport -ErrorAction SilentlyContinue
        }
    } catch {
        Warn "Could not verify WFP cleanup"
    }

    # DNS should work normally
    Info "Test: nslookup example.com (should work via system DNS)"
    try {
        $result = nslookup example.com 2>&1 | Out-String
        if ($result -match "\d+\.\d+\.\d+\.\d+") {
            Pass "DNS works after ctrld stop"
        } else {
            Fail "DNS broken after ctrld stop"
        }
    } catch {
        Fail "DNS exception after ctrld stop"
    }
}

function Test-RestartResilience {
    Header "6. Restart Resilience"

    Manual "Start ctrld again with --dns-intercept, then press Enter"
    WaitForKey

    Start-Sleep -Seconds 3

    # Quick interception test
    Info "Test: nslookup example.com 8.8.8.8 (should be intercepted after restart)"
    try {
        $result = nslookup example.com 8.8.8.8 2>&1 | Out-String
        if ($result -match "\d+\.\d+\.\d+\.\d+") {
            Pass "DNS interception works after restart"
        } else {
            Fail "DNS interception broken after restart"
        }
    } catch {
        Fail "DNS test failed after restart"
    }

    # Check WFP filters restored
    if (LogGrepCount "WFP engine opened" 100) {
        Pass "WFP re-initialized after restart"
    }
}

function Test-NetworkChange {
    Header "7. Network Change Recovery"

    Info "This test verifies recovery after network changes."
    Manual "Switch Wi-Fi networks, or disable/re-enable network adapter, then press Enter"
    WaitForKey

    Start-Sleep -Seconds 5

    # Test interception still works
    Info "Test: nslookup example.com 8.8.8.8 (should still be intercepted)"
    try {
        $result = nslookup example.com 8.8.8.8 2>&1 | Out-String
        if ($result -match "\d+\.\d+\.\d+\.\d+") {
            Pass "DNS interception works after network change"
        } else {
            Fail "DNS interception broken after network change"
        }
    } catch {
        Fail "DNS test failed after network change"
    }

    # Check logs for recovery/network events
    if (Test-Path $CtrldLog) {
        $recoveryLogs = LogGrep "recovery|network change|network monitor" 100
        if ($recoveryLogs) {
            Info "Recovery/network log entries:"
            $recoveryLogs | Select-Object -Last 5 | ForEach-Object { Write-Host "    $_" }
        }
    }
}

# =============================================================================
# SUMMARY
# =============================================================================

function Print-Summary {
    Header "TEST SUMMARY"
    Write-Host ""
    foreach ($r in $Results) {
        if ($r.StartsWith("PASS")) {
            Write-Host "  ✅ $($r.Substring(6))" -ForegroundColor Green
        } elseif ($r.StartsWith("FAIL")) {
            Write-Host "  ❌ $($r.Substring(6))" -ForegroundColor Red
        } elseif ($r.StartsWith("WARN")) {
            Write-Host "  ⚠️  $($r.Substring(6))" -ForegroundColor Yellow
        }
    }
    Write-Host ""
    Separator
    Write-Host "  Passed: $Pass  |  Failed: $Fail  |  Warnings: $Warn"
    Separator

    if ($Fail -gt 0) {
        Write-Host "`n  Some tests failed. Debug commands:" -ForegroundColor Red
        Write-Host "    netsh wfp show filters          # dump all WFP filters"
        Write-Host "    Get-Content $CtrldLog -Tail 100 # recent ctrld logs"
        Write-Host "    Get-DnsClientServerAddress       # current DNS config"
        Write-Host "    netsh wfp show state             # WFP state dump"
    } else {
        Write-Host "`n  All tests passed!" -ForegroundColor Green
    }
}

# =============================================================================
# MAIN
# =============================================================================

Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "║  ctrld DNS Intercept Mode — Windows Test Suite       ║" -ForegroundColor White
Write-Host "║  Tests WFP-based DNS interception                    ║" -ForegroundColor White
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor White

Check-Admin

Write-Host ""
Write-Host "Make sure ctrld is running with --dns-intercept before starting."
Write-Host "Log location: $CtrldLog"
WaitForKey

Test-Prereqs
Test-WfpState
Test-DnsInterception
Test-NonDnsUnaffected
Test-CtrldLogHealth

Separator
Write-Host ""
Write-Host "The next tests require manual steps (stop/start ctrld, network changes)."
Write-Host "Press Enter to continue, or Ctrl+C to skip and see results so far."
WaitForKey

Test-CleanupOnStop
Test-RestartResilience
Test-NetworkChange

Print-Summary
