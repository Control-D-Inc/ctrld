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
