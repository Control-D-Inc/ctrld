//go:build !js && !windows

package resolvconffile

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNameServers(t *testing.T) {
	ns := NameServers("")
	require.NotNil(t, ns)
	t.Log(ns)
}
