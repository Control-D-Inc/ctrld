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
