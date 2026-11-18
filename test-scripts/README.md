# DNS Intercept Test Scripts

Manual test scripts for verifying DNS intercept mode behavior. These require root/admin privileges and a running ctrld instance.

## Structure

```
test-scripts/
├── darwin/
│   ├── test-recovery-bypass.sh     # Captive portal recovery simulation
│   ├── test-dns-intercept.sh       # Basic pf intercept verification
│   ├── test-pf-group-exemption.sh  # Group-based pf exemption test
│   └── validate-pf-rules.sh        # Dry-run pf rule validation
└── windows/
    ├── test-recovery-bypass.ps1    # Captive portal recovery simulation
    └── test-dns-intercept.ps1      # Basic WFP intercept verification
```

## Prerequisites

- ctrld running with `--intercept-mode dns` (or `--intercept-mode hard`)
- Verbose logging: `-v 1 --log /tmp/dns.log` (macOS) or `--log C:\temp\dns.log` (Windows)
- Root (macOS) or Administrator (Windows)
- For recovery tests: disconnect VPNs (e.g., Tailscale) that provide alternative routes

## Recovery Bypass Test

Simulates a captive portal by blackholing ctrld's upstream DoH IPs and cycling wifi. Verifies that ctrld's recovery bypass activates, discovers DHCP nameservers, and forwards queries to them until the upstream recovers.

### macOS
```bash
sudo bash test-scripts/darwin/test-recovery-bypass.sh en0
```

### Windows (PowerShell as Administrator)
```powershell
.\test-scripts\windows\test-recovery-bypass.ps1 -WifiAdapter "Wi-Fi"
```

## Safety

All scripts clean up on exit (including Ctrl+C):
- **macOS**: Removes route blackholes, re-enables wifi
- **Windows**: Removes firewall rules, re-enables adapter
