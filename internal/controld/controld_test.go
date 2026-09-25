//go:build controld

package controld

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
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

	ctx := context.Background()
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := &ResolverConfigRequest{
				RawUID:   tc.uid,
				Version:  "dev-test",
				Metadata: ctrld.SystemMetadata(ctx),
			}
			got, err := FetchResolverConfig(ctx, req, tc.dev)
			require.False(t, (err != nil) != tc.wantErr, err)
			if !tc.wantErr {
				assert.NotEmpty(t, got.DOH)
			}
		})
	}
}
