//go:build !linux

package clientinfo

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
)

// scan populates NDP table using information from system mappings.
func (nd *ndpDiscover) scan() {
	switch runtime.GOOS {
	case "windows":
		data, err := exec.Command("netsh", "interface", "ipv6", "show", "neighbors").Output()
		if err != nil {
			nd.logger.Warn().Err(err).Msg("could not query ndp table")
			return
		}
		nd.scanWindows(bytes.NewReader(data))
	default:
		data, err := exec.Command("ndp", "-an").Output()
		if err != nil {
			nd.logger.Warn().Err(err).Msg("could not query ndp table")
			return
		}
		nd.scanUnix(bytes.NewReader(data))
	}
}

// subscribe watches NDP table changes and update new information to local table.
// This is a stub method, and only works on Linux at this moment.
func (nd *ndpDiscover) subscribe(ctx context.Context) {}
