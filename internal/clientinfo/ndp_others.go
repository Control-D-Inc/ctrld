//go:build !linux

package clientinfo

import (
	"bytes"
	"os/exec"
	"runtime"

	"github.com/Control-D-Inc/ctrld"
)

// scan populates NDP table using information from system mappings.
func (nd *ndpDiscover) scan() {
	switch runtime.GOOS {
	case "windows":
		data, err := exec.Command("netsh", "interface", "ipv6", "show", "neighbors").Output()
		if err != nil {
			ctrld.ProxyLogger.Load().Warn().Err(err).Msg("could not query ndp table")
			return
		}
		nd.scanWindows(bytes.NewReader(data))
	default:
		data, err := exec.Command("ndp", "-an").Output()
		if err != nil {
			ctrld.ProxyLogger.Load().Warn().Err(err).Msg("could not query ndp table")
			return
		}
		nd.scanUnix(bytes.NewReader(data))
	}
}
