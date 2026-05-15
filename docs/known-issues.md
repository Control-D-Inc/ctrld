# Known Issues

This document outlines known issues with ctrld and their current status, workarounds, and recommendations.

## macOS (Darwin) Issues

### Self-Upgrade Issue on Darwin 15.5

**Issue**: ctrld self-upgrading functionality may not work on macOS Darwin 15.5.

**Status**: Under investigation

**Description**: Users on macOS Darwin 15.5 may experience issues when ctrld attempts to perform automatic self-upgrades. The upgrade process would be triggered, but ctrld won't be upgraded.

**Workarounds**:
1. **Recommended**: Upgrade your macOS system to Darwin 15.6 or later, which has been tested and verified to work correctly with ctrld self-upgrade functionality.
2. **Alternative**: Run `ctrld upgrade prod` directly to manually upgrade ctrld to the latest version on Darwin 15.5.

**Affected Versions**: ctrld v1.4.2 and later on macOS Darwin 15.5

**Last Updated**: 05/09/2025

---

## Windows Issues

### VPN `block-outside-dns` Breaks DNS When Using ctrld in DNS Mode

**Issue**: VPN software that uses OpenVPN's `block-outside-dns` directive installs WFP (Windows Filtering Platform) block filters that prevent DNS queries from reaching ctrld's loopback listener.

**Status**: Fixed in v1.5.1

**Description**: When a VPN connects with `block-outside-dns` enabled, OpenVPN adds WFP filters that block all DNS traffic to non-tunnel interfaces — including loopback (`127.0.0.1`). Since ctrld's NRPT catch-all rule routes DNS through the Windows DNS Client to `127.0.0.1:53`, the WFP block filters prevent DNS Client from reaching ctrld, causing all DNS queries to time out.

This affects any VPN client that implements `block-outside-dns` via WFP, including:
- OpenVPN GUI (community)
- Securepoint SSL VPN
- Any OpenVPN-based client that honors the `block-outside-dns` push directive

**Fix**: ctrld now proactively adds WFP "hard permit" filters for DNS to localhost at startup. These use `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` to override block decisions from any other WFP sublayer, ensuring the NRPT → loopback path is always available regardless of VPN state. See `docs/dns-intercept-mode.md` for technical details.

**Affected Versions**: ctrld ≤ v1.5.0 in `dns` intercept mode on Windows

**Last Updated**: 04/28/2026

---

## Contributing to Known Issues

If you encounter an issue not listed here, please:

1. Check the [GitHub Issues](https://github.com/Control-D-Inc/ctrld/issues) to see if it's already reported
2. If not reported, create a new issue with:
   - Detailed description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, version, architecture)
   - ctrld version

## Issue Status Legend

- **Under investigation**: Issue is confirmed and being analyzed
- **Workaround available**: Temporary solution exists while permanent fix is developed
- **Fixed**: Issue has been resolved in a specific version
- **Won't fix**: Issue is acknowledged but will not be addressed due to technical limitations or design decisions
