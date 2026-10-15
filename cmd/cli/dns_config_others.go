//go:build !darwin

package cli

// runSCUtilDNS has no source of a resolver table outside macOS, so the poller
// finds no change and logs nothing.
func runSCUtilDNS() ([]dnsResolverEntry, error) {
	return nil, nil
}
