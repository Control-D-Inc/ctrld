//go:build unix

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/Control-D-Inc/ctrld"
)

func selfUninstall(p *prog, logger *ctrld.Logger) {
	if runtime.GOOS == "linux" {
		selfUninstallLinux(p, logger)
	}

	bin, err := os.Executable()
	if err != nil {
		logger.Fatal().Err(err).Msg("could not determine executable")
	}
	args := []string{"uninstall"}
	if deactivationPinSet() {
		args = append(args, fmt.Sprintf("--pin=%d", cdDeactivationPin.Load()))
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

func selfUninstallLinux(p *prog, logger *ctrld.Logger) {
	if uninstallInvalidCdUID(p, logger, true) {
		logger.Warn().Msgf("service was uninstalled because device %q does not exist", cdUID)
		os.Exit(0)
	}
}
