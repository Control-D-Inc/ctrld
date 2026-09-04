package cli

import (
	"fmt"
	"regexp"
	"strings"
)

// validHostname reports whether hostname is a valid hostname.
// A valid hostname contains 3 -> 64 characters and conform to RFC1123.
// This function validates hostnames to ensure they meet DNS naming standards
// and prevents invalid hostnames from being used in DNS configurations
func validHostname(hostname string) bool {
	hostnameLen := len(hostname)
	if hostnameLen < 3 || hostnameLen > 64 {
		return false
	}
	// RFC1123 regex pattern ensures hostnames follow DNS naming conventions
	// This prevents issues with DNS resolution and system compatibility
	validHostnameRfc1123 := regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
	return validHostnameRfc1123.MatchString(hostname)
}

// isHostnameChar reports whether r is part of validHostname's accepted
// charset (letters, digits, hyphen, dot). It does not check position, so a
// hostname can fail validHostname on structure (length, leading/trailing
// hyphen) while every one of its characters passes here.
func isHostnameChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '-' || r == '.':
		return true
	}
	return false
}

// offendingHostnameChars returns the distinct characters in hostname that
// validHostname's charset does not accept, in first-seen order. Empty when
// every character is accepted - a rejection can still come from structure
// alone (too short, too long, a leading or trailing hyphen).
func offendingHostnameChars(hostname string) string {
	seen := make(map[rune]bool)
	var bad []rune
	for _, r := range hostname {
		if isHostnameChar(r) || seen[r] {
			continue
		}
		seen[r] = true
		bad = append(bad, r)
	}
	return string(bad)
}

// serverFoldedHostnameChars are the characters ControlD's
// DevicesTableModel.formatDeviceName folds to '-' (or strips) when it
// registers a device name server-side. Only '.' can actually reach
// hostnameMayBeFoldedByServer through validateCustomHostnameFlag's guarded
// path: validHostname runs first and already rejects any hostname
// containing a space or a '+' as CUSTOM_HOSTNAME_INVALID, so those two never
// get here from an explicit --custom-hostname value. They stay in this set
// for completeness: a mobile caller can set CustomHostname to an
// OS-derived default directly, without going through
// validateCustomHostnameFlag at all, so a space or '+' can still reach the
// API unvalidated by this client.
const serverFoldedHostnameChars = ". +"

// hostnameMayBeFoldedByServer reports whether hostname contains a character
// ControlD may fold or strip when it registers the device, so the name ctrld
// accepted may not be the name the dashboard ends up showing.
func hostnameMayBeFoldedByServer(hostname string) bool {
	return strings.ContainsAny(hostname, serverFoldedHostnameChars)
}

// customHostnameFailureMessage names the field, the offending character(s)
// when there are any, and the allowed format for CUSTOM_HOSTNAME_INVALID.
// ctrld's accept/reject rule (validHostname) is unchanged - this only
// explains a rejection that used to be a bare fatal exit.
func customHostnameFailureMessage(hostname string) string {
	const allowedFormat = "3-64 characters of letters, digits, hyphens, and dots (RFC1123 hostname format)"
	reason := "is not a valid hostname"
	if bad := offendingHostnameChars(hostname); bad != "" {
		reason = fmt.Sprintf("contains characters a hostname cannot use: %q", bad)
	}
	return fmt.Sprintf("--custom-hostname (CustomHostname) %q %s; allowed format: %s", hostname, reason, allowedFormat)
}
