//go:build !unix

package cli

import (
	"os"

	"github.com/Control-D-Inc/ctrld"
)

// selfUninstall performs self-uninstallation on non-Unix platforms
func selfUninstall(p *prog, logger *ctrld.Logger) {
	if uninstallInvalidCdUID(p, logger, false) {
		logger.Warn().Msgf("service was uninstalled because device %q does not exist", cdUID)
		os.Exit(0)
	}
}
