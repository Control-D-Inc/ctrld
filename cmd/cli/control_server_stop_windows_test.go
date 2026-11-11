//go:build windows

package cli

import (
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

// On Windows the reload signal is a send on reloadCh, and the send waits while
// the run does not receive, for example during another reload. The stop must
// end that wait too.
func TestControlServerStopEndsReloadSignalWait(t *testing.T) {
	p := &prog{
		cfg:          &ctrld.Config{},
		reloadDoneCh: make(chan struct{}),
		reloadCh:     make(chan struct{}),
	}
	requireStopEndsHandler(t, p, reloadPath, nil, 0)
}
