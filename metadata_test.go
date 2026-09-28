package ctrld

import (
	"context"
	"testing"
)

func Test_metadata(t *testing.T) {
	m := SystemMetadata(context.Background())
	t.Logf("metadata: %v", m)
}
