package controld

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseUID(t *testing.T) {
	tests := []struct {
		name         string
		uid          string
		wantUID      string
		wantClientID string
	}{
		{"empty", "", "", ""},
		{"only uid", "abcd1234", "abcd1234", ""},
		{"with client id", "abcd1234/clientID", "abcd1234", "clientID"},
		{"with empty clientID", "abcd1234/", "abcd1234", ""},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotUID, gotClientID := ParseRawUID(tc.uid)
			assert.Equal(t, tc.wantUID, gotUID)
			assert.Equal(t, tc.wantClientID, gotClientID)
		})
	}
}
