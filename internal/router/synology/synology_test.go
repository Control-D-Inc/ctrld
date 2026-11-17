package synology

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
)

// When ctrld listens on port 53 itself, it did not change dnsmasq, so the
// cleanup has nothing to undo. The cleanup must find that listener under a
// key with a leading zero too, because it reads the config from disk with no
// check.
func TestCleanupSkipsDirectListenerWithLeadingZeroKey(t *testing.T) {
	cfg := &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"01": {IP: "0.0.0.0", Port: 53}}}

	require.NoError(t, New(cfg).Cleanup())
}
