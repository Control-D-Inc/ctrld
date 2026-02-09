//go:build !darwin

package cli

// needMdnsResponderHack determines if a system-specific workaround for mDNSResponder is necessary at runtime.
var needMdnsResponderHack = mDNSResponderHack()

// mDNSResponderHack checks if the mDNSResponder process and its environments meet specific criteria for operation.
func mDNSResponderHack() bool {
	return false
}

// killMdnsResponder attempts to terminate the mDNSResponder process by running the "killall" command multiple times.
// Logs any accumulated errors if the attempts to terminate the process fail.
func killMdnsResponder() {}

// doMdnsResponderCleanup performs cleanup tasks for the mDNSResponder hack file and resets the network interface "en0".
func doMdnsResponderCleanup() {}

// doMdnsResponderHackPostInstall creates a hack file for mDNSResponder if required and logs debug or error messages.
func doMdnsResponderHackPostInstall() {}
