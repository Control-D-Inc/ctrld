//go:build unix

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/Control-D-Inc/ctrld/internal/controld"
	"github.com/rs/zerolog"
)

func selfUninstall(uninstallErr error, p *prog, logger zerolog.Logger) {
	var uer *controld.UtilityErrorResponse
	if errors.As(uninstallErr, &uer) && uer.ErrorField.Code == controld.InvalidConfigCode {
		if runtime.GOOS == "linux" {
			s, err := newService(p, svcConfig)
			if err != nil {
				logger.Warn().Err(err).Msg("failed to create new service")
			} else {
				selfUninstallLinux(uninstallErr, p, logger)
				_ = s.Stop()
				os.Exit(0)
			}
		}

		bin, err := os.Executable()
		if err != nil {
			logger.Fatal().Err(err).Msg("could not determine executable")
		}
		args := []string{"uninstall"}
		if !deactivationPinNotSet() {
			args = append(args, fmt.Sprintf("--pin=%d", cdDeactivationPin))
		}
		cmd := exec.Command(bin, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			logger.Fatal().Err(err).Msg("could not start self uninstall command")
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		logger.Warn().Msgf("service was uninstalled because device %q does not exist", cdUID)
		_ = cmd.Wait()
		os.Exit(0)
	}
}

func selfUninstallLinux(err error, p *prog, logger zerolog.Logger) {
	if uninstallIfInvalidCdUID(err, p, logger) {
		logger.Warn().Msgf("service was uninstalled because device %q does not exist", cdUID)
	}
}
