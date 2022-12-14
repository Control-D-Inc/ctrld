package dnsrcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromString(t *testing.T) {
	tests := []struct {
		name          string
		rcode         string
		expectedRcode int
	}{
		{"valid", "NoError", 0},
		{"upper", "NOERROR", 0},
		{"lower", "noerror", 0},
		{"mix", "nOeRrOr", 0},
		{"invalid", "foo", -1},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expectedRcode, FromString(tc.rcode))
		})
	}
}
