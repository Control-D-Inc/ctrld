#Requires -RunAsAdministrator
<#
.SYNOPSIS
    NRPT diagnostic script for ctrld DNS intercept troubleshooting.
.DESCRIPTION
    Captures the full NRPT state: registry keys (both GP and direct paths),
    effective policy, active rules, DNS Client service status, and resolver
    config. Run as Administrator.
.EXAMPLE
    .\nrpt-diag.ps1
    .\nrpt-diag.ps1 | Out-File nrpt-diag-output.txt
#>

$ErrorActionPreference = 'SilentlyContinue'

Write-Host "=== NRPT Diagnostic Report ===" -ForegroundColor Cyan
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Computer: $env:COMPUTERNAME"
Write-Host "OS: $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"
Write-Host ""

# --- 1. DNS Client Service ---
Write-Host "=== 1. DNS Client (Dnscache) Service ===" -ForegroundColor Yellow
$svc = Get-Service Dnscache
Write-Host "Status: $($svc.Status)  StartType: $($svc.StartType)"
Write-Host ""

# --- 2. GP Path (Policy store) ---
$gpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"
Write-Host "=== 2. GP Path: $gpPath ===" -ForegroundColor Yellow
$gpKey = Get-Item $gpPath 2>$null
if ($gpKey) {
    Write-Host "Key EXISTS"
    $subkeys = Get-ChildItem $gpPath 2>$null
    if ($subkeys) {
        foreach ($sk in $subkeys) {
            Write-Host ""
            Write-Host "  Subkey: $($sk.PSChildName)" -ForegroundColor Green
            foreach ($prop in $sk.Property) {
                $val = $sk.GetValue($prop)
                $kind = $sk.GetValueKind($prop)
                Write-Host "    $prop ($kind) = $val"
            }
        }
    } else {
        Write-Host "  ** EMPTY (no subkeys) — this blocks NRPT activation! **" -ForegroundColor Red
    }
} else {
    Write-Host "Key does NOT exist (clean state)"
}
Write-Host ""

# --- 3. Direct Path (Service store) ---
$directPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig"
Write-Host "=== 3. Direct Path: $directPath ===" -ForegroundColor Yellow
$directKey = Get-Item $directPath 2>$null
if ($directKey) {
    Write-Host "Key EXISTS"
    $subkeys = Get-ChildItem $directPath 2>$null
    if ($subkeys) {
        foreach ($sk in $subkeys) {
            Write-Host ""
            Write-Host "  Subkey: $($sk.PSChildName)" -ForegroundColor Green
            foreach ($prop in $sk.Property) {
                $val = $sk.GetValue($prop)
                $kind = $sk.GetValueKind($prop)
                Write-Host "    $prop ($kind) = $val"
            }
        }
    } else {
        Write-Host "  ** EMPTY (no subkeys) **" -ForegroundColor Red
    }
} else {
    Write-Host "Key does NOT exist"
}
Write-Host ""

# --- 4. Effective NRPT Rules (what Windows sees) ---
Write-Host "=== 4. Get-DnsClientNrptRule ===" -ForegroundColor Yellow
$rules = Get-DnsClientNrptRule 2>$null
if ($rules) {
    $rules | Format-List Name, Version, Namespace, NameServers, NameEncoding, DnsSecEnabled
} else {
    Write-Host "(none)"
}
Write-Host ""

# --- 5. Effective NRPT Policy (what DNS Client actually applies) ---
Write-Host "=== 5. Get-DnsClientNrptPolicy ===" -ForegroundColor Yellow
$policy = Get-DnsClientNrptPolicy 2>$null
if ($policy) {
    $policy | Format-List Namespace, NameServers, NameEncoding, QueryPolicy
} else {
    Write-Host "(none — DNS Client is NOT honoring any NRPT rules)" -ForegroundColor Red
}
Write-Host ""

# --- 6. Interface DNS servers ---
Write-Host "=== 6. Interface DNS Configuration ===" -ForegroundColor Yellow
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } |
    Format-Table InterfaceAlias, InterfaceIndex, ServerAddresses -AutoSize
Write-Host ""

# --- 7. DNS resolution test ---
Write-Host "=== 7. DNS Resolution Test ===" -ForegroundColor Yellow
Write-Host "Resolve-DnsName example.com (uses DNS Client / NRPT):"
try {
    $result = Resolve-DnsName example.com -Type A -DnsOnly -ErrorAction Stop
    $result | Format-Table Name, Type, IPAddress -AutoSize
} catch {
    Write-Host "  FAILED: $_" -ForegroundColor Red
}
Write-Host ""
Write-Host "nslookup example.com 127.0.0.1 (direct to ctrld, bypasses NRPT):"
$ns = nslookup example.com 127.0.0.1 2>&1
$ns | ForEach-Object { Write-Host "  $_" }
Write-Host ""

# --- 8. Domain join status ---
Write-Host "=== 8. Domain Status ===" -ForegroundColor Yellow
$cs = Get-CimInstance Win32_ComputerSystem
Write-Host "Domain: $($cs.Domain)  PartOfDomain: $($cs.PartOfDomain)"
Write-Host ""

# --- 9. Group Policy NRPT ---
Write-Host "=== 9. GP Result (NRPT section) ===" -ForegroundColor Yellow
Write-Host "(Running gpresult — may take a few seconds...)"
$gp = gpresult /r 2>&1
$gp | Select-String -Pattern "DNS|NRPT|Policy" | ForEach-Object { Write-Host "  $_" }
Write-Host ""

Write-Host "=== End of Diagnostic Report ===" -ForegroundColor Cyan
