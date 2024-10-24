package cli

import "regexp"

// validHostname reports whether hostname is a valid hostname.
// A valid hostname contains 3 -> 64 characters and conform to RFC1123.
func validHostname(hostname string) bool {
	hostnameLen := len(hostname)
	if hostnameLen < 3 || hostnameLen > 64 {
		return false
	}
	validHostnameRfc1123 := regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
	return validHostnameRfc1123.MatchString(hostname)
}
