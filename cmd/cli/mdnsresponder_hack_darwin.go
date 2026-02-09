package cli

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"tailscale.com/net/netmon"
)

// On macOS, the system daemon mDNSResponder (used for proxy/mDNS/Bonjour discovery)
// listens on UDP and TCP port 53. That conflicts with ctrld when it needs to
// run a DNS proxy on port 53. The kernel does not allow two processes to bind
// the same address/port, so ctrld would fail with "address already in use" if we
// did nothing.
//
// If ctrld started before mDNSResponder and listened only on 127.0.0.1, mDNSResponder
// would bind port 53 on other interfaces, so system processes would use it as the
// DNS resolver instead of ctrld, leading to inconsistent behavior.
//
// This file implements a Darwin-only workaround:
//
//   - We detect at startup whether mDNSResponder is using port 53 (or a
//     persisted marker file exists from a previous run).
//   - When the workaround is active, we force the listener to 0.0.0.0:53 and,
//     before binding, run killall mDNSResponder so that ctrld can bind to port 53.
//   - We use SO_REUSEPORT (see listener setup) so that the socket can be bound
//     even when the port was recently used.
//   - On install we create a marker file in the user's home directory so that
//     the workaround is applied on subsequent starts; on uninstall we remove
//     that file and bounce the en0 interface to restore normal mDNSResponder
//     behavior.
//
// Without this, users on macOS would be unable to run ctrld as the system DNS
// on port 53 when mDNSResponder is active.

var (

	// needMdnsResponderHack determines if a system-specific workaround for mDNSResponder is necessary at runtime.
	needMdnsResponderHack     = mDNSResponderHack()
	mDNSResponderHackFilename = ".mdnsResponderHack"
)

// mDNSResponderHack checks if the mDNSResponder process and its environments meet specific criteria for operation.
func mDNSResponderHack() bool {
	if st, err := os.Stat(mDNSResponderFile()); err == nil && st.Mode().IsRegular() {
		return true
	}
	out, err := lsofCheckPort53()
	if err != nil {
		return false
	}
	if !isMdnsResponderListeningPort53(strings.NewReader(out)) {
		return false
	}
	return true
}

// mDNSResponderFile constructs and returns the absolute path to the mDNSResponder hack file in the user's home directory.
func mDNSResponderFile() string {
	if d, err := userHomeDir(); err == nil && d != "" {
		return filepath.Join(d, mDNSResponderHackFilename)
	}
	return ""
}

// doMdnsResponderCleanup performs cleanup tasks for the mDNSResponder hack file and resets the network interface "en0".
func doMdnsResponderCleanup() {
	fn := mDNSResponderFile()
	if fn == "" {
		return
	}
	if st, err := os.Stat(fn); err != nil || !st.Mode().IsRegular() {
		return
	}
	if err := os.Remove(fn); err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to remove mDNSResponder hack file")
	}

	ifName := "en0"
	if din, err := netmon.DefaultRouteInterface(); err == nil {
		ifName = din
	}
	if err := exec.Command("ifconfig", ifName, "down").Run(); err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to disable en0")
	}
	if err := exec.Command("ifconfig", ifName, "up").Run(); err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to enable en0")
	}
}

// doMdnsResponderHackPostInstall creates a hack file for mDNSResponder if required and logs debug or error messages.
func doMdnsResponderHackPostInstall() {
	if !needMdnsResponderHack {
		return
	}
	fn := mDNSResponderFile()
	if fn == "" {
		return
	}
	if f, err := os.OpenFile(fn, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0400); err != nil {
		mainLog.Load().Warn().Err(err).Msgf("Could not create %s", fn)
	} else {
		if err := f.Close(); err != nil {
			mainLog.Load().Warn().Err(err).Msgf("Could not close %s", fn)
		} else {
			mainLog.Load().Debug().Msgf("Created %s", fn)
		}
	}
}

// killMdnsResponder attempts to terminate the mDNSResponder process by running the "killall" command multiple times.
// Logs any accumulated errors if the attempts to terminate the process fail.
func killMdnsResponder() {
	numAttempts := 10
	errs := make([]error, 0, numAttempts)
	for range numAttempts {
		if err := exec.Command("killall", "mDNSResponder").Run(); err != nil {
			// Exit code 1 means the process not found, do not log it.
			if !strings.Contains(err.Error(), "exit status 1") {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		mainLog.Load().Debug().Err(errors.Join(errs...)).Msg("failed to kill mDNSResponder")
	}
}

// lsofCheckPort53 executes the lsof command to check if any process is listening on port 53 and returns the output.
func lsofCheckPort53() (string, error) {
	cmd := exec.Command("lsof", "+c0", "-i:53", "-n", "-P")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// isMdnsResponderListeningPort53 checks if the output provided by the reader contains an mDNSResponder process.
func isMdnsResponderListeningPort53(r io.Reader) bool {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 && strings.EqualFold(fields[0], "mDNSResponder") {
			return true
		}
	}
	return false
}
