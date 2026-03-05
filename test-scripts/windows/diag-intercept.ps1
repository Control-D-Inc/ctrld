# diag-intercept.ps1 — Windows DNS Intercept Mode Diagnostic
# Run as Administrator in the same elevated prompt as ctrld
# Usage: .\diag-intercept.ps1

Write-Host "=== CTRLD INTERCEPT MODE DIAGNOSTIC ===" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# 1. Check NRPT rules
Write-Host "--- 1. NRPT Rules ---" -ForegroundColor Yellow
try {
    $nrptRules = Get-DnsClientNrptRule -ErrorAction Stop
    if ($nrptRules) {
        $nrptRules | Format-Table Namespace, NameServers, DisplayName -AutoSize
    } else {
        Write-Host "  NO NRPT RULES FOUND — this is the problem!" -ForegroundColor Red
    }
} catch {
    Write-Host "  Get-DnsClientNrptRule failed: $_" -ForegroundColor Red
}
Write-Host ""

# 2. Check NRPT registry directly
Write-Host "--- 2. NRPT Registry ---" -ForegroundColor Yellow
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\CtrldCatchAll"
if (Test-Path $regPath) {
    Write-Host "  Registry key EXISTS" -ForegroundColor Green
    Get-ItemProperty $regPath | Format-List Name, GenericDNSServers, ConfigOptions, Version
} else {
    Write-Host "  Registry key MISSING at $regPath" -ForegroundColor Red
    # Check parent
    $parentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"
    if (Test-Path $parentPath) {
        Write-Host "  Parent key exists. Children:"
        Get-ChildItem $parentPath | ForEach-Object { Write-Host "    $($_.PSChildName)" }
    } else {
        Write-Host "  Parent DnsPolicyConfig key also missing" -ForegroundColor Red
    }
}
Write-Host ""

# 3. DNS Client service status
Write-Host "--- 3. DNS Client Service ---" -ForegroundColor Yellow
$dnsSvc = Get-Service Dnscache
Write-Host "  Status: $($dnsSvc.Status)  StartType: $($dnsSvc.StartType)"
Write-Host ""

# 4. Interface DNS servers
Write-Host "--- 4. Interface DNS Servers ---" -ForegroundColor Yellow
Get-DnsClientServerAddress | Format-Table InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses -AutoSize
Write-Host ""

# 5. WFP filters check
Write-Host "--- 5. WFP Filters (ctrld sublayer) ---" -ForegroundColor Yellow
try {
    $wfpOutput = netsh wfp show filters
    if (Test-Path "filters.xml") {
        $xml = [xml](Get-Content "filters.xml")
        $ctrldFilters = $xml.wfpdiag.filters.item | Where-Object {
            $_.displayData.name -like "ctrld:*"
        }
        if ($ctrldFilters) {
            Write-Host "  Found $($ctrldFilters.Count) ctrld WFP filter(s):" -ForegroundColor Green
            $ctrldFilters | ForEach-Object {
                Write-Host "    $($_.displayData.name) — action: $($_.action.type)"
            }
        } else {
            Write-Host "  NO ctrld WFP filters found" -ForegroundColor Red
        }
        Remove-Item "filters.xml" -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "  WFP check failed: $_" -ForegroundColor Red
}
Write-Host ""

# 6. DNS resolution tests
Write-Host "--- 6. DNS Resolution Tests ---" -ForegroundColor Yellow

# Test A: Resolve-DnsName (uses DNS Client = respects NRPT)
Write-Host "  Test A: Resolve-DnsName google.com (DNS Client path)" -ForegroundColor White
try {
    $result = Resolve-DnsName google.com -Type A -DnsOnly -ErrorAction Stop
    Write-Host "    OK: $($result.IPAddress -join ', ')" -ForegroundColor Green
} catch {
    Write-Host "    FAILED: $_" -ForegroundColor Red
}

# Test B: Resolve-DnsName to specific server (127.0.0.1)
Write-Host "  Test B: Resolve-DnsName google.com -Server 127.0.0.1" -ForegroundColor White
try {
    $result = Resolve-DnsName google.com -Type A -Server 127.0.0.1 -DnsOnly -ErrorAction Stop
    Write-Host "    OK: $($result.IPAddress -join ', ')" -ForegroundColor Green
} catch {
    Write-Host "    FAILED: $_" -ForegroundColor Red
}

# Test C: Resolve-DnsName blocked domain (should return 0.0.0.0 or NXDOMAIN via Control D)
Write-Host "  Test C: Resolve-DnsName popads.net (should be blocked by Control D)" -ForegroundColor White
try {
    $result = Resolve-DnsName popads.net -Type A -DnsOnly -ErrorAction Stop
    Write-Host "    Result: $($result.IPAddress -join ', ')" -ForegroundColor Yellow
} catch {
    Write-Host "    FAILED/Blocked: $_" -ForegroundColor Yellow
}

# Test D: nslookup (bypasses NRPT - expected to fail with intercept)
Write-Host "  Test D: nslookup google.com 127.0.0.1 (direct, bypasses NRPT)" -ForegroundColor White
$nslookup = & nslookup google.com 127.0.0.1 2>&1
Write-Host "    $($nslookup -join "`n    ")"

Write-Host ""

# 7. Try forcing NRPT reload
Write-Host "--- 7. Force NRPT Reload ---" -ForegroundColor Yellow
Write-Host "  Running: gpupdate /target:computer /force" -ForegroundColor White
& gpupdate /target:computer /force 2>&1 | ForEach-Object { Write-Host "    $_" }
Write-Host ""

# Re-test after gpupdate
Write-Host "  Re-test: Resolve-DnsName google.com" -ForegroundColor White
try {
    $result = Resolve-DnsName google.com -Type A -DnsOnly -ErrorAction Stop
    Write-Host "    OK: $($result.IPAddress -join ', ')" -ForegroundColor Green
} catch {
    Write-Host "    STILL FAILED: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== DIAGNOSTIC COMPLETE ===" -ForegroundColor Cyan
Write-Host "Copy all output above and send it back."
