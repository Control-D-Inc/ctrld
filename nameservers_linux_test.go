package ctrld

import (
	"context"
	"testing"
)

func Test_virtualInterfaces(t *testing.T) {
	vis := virtualInterfaces(context.Background())
	t.Log(vis)
}
