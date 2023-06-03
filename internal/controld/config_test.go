//go:build controld

package controld

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchResolverConfig(t *testing.T) {
	tests := []struct {
		name    string
		uid     string
		dev     bool
		wantErr bool
	}{
		{"valid com", "p2", false, false},
		{"valid dev", "p2", true, false},
		{"invalid uid", "abcd1234", false, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := FetchResolverConfig(tc.uid, "dev-test", tc.dev)
			require.False(t, (err != nil) != tc.wantErr, err)
			if !tc.wantErr {
				assert.NotEmpty(t, got.DOH)
			}
		})
	}
}
