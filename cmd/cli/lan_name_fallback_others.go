//go:build !windows

package cli

// newPlatformLanNameFallback returns nil: only Windows Intercept mode needs a
// LAN name fallback. In Standard mode Windows still does its own, and on
// macOS mDNSResponder resolves .local before DNS. See lan_name_fallback.go.
func newPlatformLanNameFallback() *lanNameFallback { return nil }
