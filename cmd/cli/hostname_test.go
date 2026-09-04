package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_validHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		valid    bool
	}{
		{"localhost", "localhost", true},
		{"localdomain", "localhost.localdomain", true},
		{"localhost6", "localhost6.localdomain6", true},
		{"ip6", "ip6-localhost", true},
		{"non-domain", "controld", true},
		{"domain", "controld.com", true},
		{"empty", "", false},
		{"min length", "fo", false},
		{"max length", strings.Repeat("a", 65), false},
		{"special char", "foo!", false},
		{"non-ascii", "fooΩ", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.hostname, func(t *testing.T) {
			t.Parallel()
			assert.True(t, validHostname(tc.hostname) == tc.valid)
		})
	}
}

// TestOffendingHostnameChars pins the characters surfaced in the
// CUSTOM_HOSTNAME_INVALID message, so the failure names what is actually
// wrong instead of a bare "invalid hostname".
func TestOffendingHostnameChars(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     string
	}{
		{"single offender", "foo@bar", "@"},
		{"space", "foo bar", " "},
		{"dot is allowed", "foo.bar", ""},
		{"hyphen is allowed", "foo-bar", ""},
		{"distinct offenders in order", "a!b!c#d", "!#"},
		{"structurally invalid but no bad char", strings.Repeat("a", 65), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := offendingHostnameChars(tc.hostname); got != tc.want {
				t.Errorf("offendingHostnameChars(%q) = %q, want %q", tc.hostname, got, tc.want)
			}
		})
	}
}

// TestHostnameMayBeFoldedByServer pins the characters ControlD's
// DevicesTableModel.formatDeviceName folds or strips when it registers a
// device, so a ctrld-accepted name using one gets a heads-up notice instead
// of silently registering under a different name.
func TestHostnameMayBeFoldedByServer(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{"dot", "foo.bar", true},
		{"space", "foo bar", true},
		{"plus", "foo+bar", true},
		{"plain", "foobar", false},
		{"hyphen only", "foo-bar", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostnameMayBeFoldedByServer(tc.hostname); got != tc.want {
				t.Errorf("hostnameMayBeFoldedByServer(%q) = %v, want %v", tc.hostname, got, tc.want)
			}
		})
	}
}

// TestCustomHostnameFailureMessage pins the message shape the T6 contract
// requires: the flag/field name, the offending character(s), and the
// allowed format.
func TestCustomHostnameFailureMessage(t *testing.T) {
	msg := customHostnameFailureMessage("foo@bar")
	for _, want := range []string{"--custom-hostname", "CustomHostname", "@", "allowed format"} {
		if !strings.Contains(msg, want) {
			t.Errorf("customHostnameFailureMessage() = %q, want it to contain %q", msg, want)
		}
	}
}
