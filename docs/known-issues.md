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

## Merlin Issues

### Daemon Crashing on `Ctrl+C`

**Issue**: `ctrld` daemon terminates unexpectedly after stopping a log tailing command. This typically occurs when running the daemon and the log viewer within the same SSH session on ASUSWRT-Merlin routers.

**Description**

The issue is caused by `Signal Propagation` within a shared `Process Group (PGID)`.

Steps to reproduce:

1. You start the daemon manually: `ctrld start --cd=<uid>`.
2. You view internal logs in the same terminal: `ctrld log tail`.
3. You press `Ctrl+C` to stop viewing logs.
4. The `ctrld` daemon service stops immediately along with the log command.

When you execute commands sequentially in a single interactive SSH session on Merlin, the shell often assigns them to the same Process Group. In Linux, the `SIGINT` signal (triggered by `Ctrl+C`) is not just sent to the foreground application, but is frequently propagated to every process belonging to that specific process group.

Because the `ctrld` daemon remains "attached" to the terminal session's process group, it "hears" the interrupt signal intended for the `log tail` command and shuts down.

**Workarounds**:

To isolate the signals, avoid running the log viewer in the same window as the daemon:
* **Window A:** Start the daemon and leave it running.
* **Window B:** Open a new SSH connection to run `ctrld log tail`.
Because Window B has a different **Session ID** and **Process Group ID**, pressing `Ctrl+C` in Window B will not affect the process in Window A.

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
