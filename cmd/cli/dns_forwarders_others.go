//go:build !windows

package cli

// removeSavedDnsServerForwarders is a no-op: only Windows domain controllers
// get DNS Server forwarders.
func removeSavedDnsServerForwarders() {}
