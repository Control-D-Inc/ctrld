//go:build !unix

package cli

import (
	"os"

	"github.com/rs/zerolog"
)

func selfUninstall(p *prog, logger zerolog.Logger) {
	if uninstallInvalidCdUID(p, logger, false) {
		logger.Warn().Msgf("service was uninstalled because device %q does not exist", cdUID)
		os.Exit(0)
	}
}
