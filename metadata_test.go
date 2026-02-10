package ctrld

import (
	"context"
	"os"
	"testing"
)

func Test_metadata(t *testing.T) {
	m := SystemMetadata(context.Background())
	t.Logf("metadata: %v", m)
	t.Logf("SUDO_USER: %s", os.Getenv("SUDO_USER"))
	t.Logf("LOGNAME: %s", os.Getenv("LOGNAME"))
	t.Logf("USER: %s", os.Getenv("USER"))
}
