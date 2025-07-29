package cli

import (
	"errors"
	"io"
	"net/http"
	"path/filepath"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// Reload implements the logic from cmdReload.Run
func (sc *ServiceCommand) Reload(cmd *cobra.Command, args []string) error {
	status, err := sc.serviceManager.svc.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		mainLog.Load().Warn().Msg("service not installed")
		return nil
	}
	if status == service.StatusStopped {
		mainLog.Load().Warn().Msg("service is not running")
		return nil
	}
	dir, err := socketDir()
	if err != nil {
		mainLog.Load().Fatal().Err(err).Msg("failed to find ctrld home dir")
	}
	cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
	resp, err := cc.post(reloadPath, nil)
	if err != nil {
		mainLog.Load().Fatal().Err(err).Msg("failed to send reload signal to ctrld")
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		mainLog.Load().Notice().Msg("Service reloaded")
	case http.StatusCreated:
		mainLog.Load().Warn().Msg("Service was reloaded, but new config requires service restart.")
		mainLog.Load().Warn().Msg("Restarting service")
		if _, err := sc.serviceManager.svc.Status(); errors.Is(err, service.ErrNotInstalled) {
			mainLog.Load().Warn().Msg("Service not installed")
			return nil
		}
		return sc.Restart(cmd, args)
	default:
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			mainLog.Load().Fatal().Err(err).Msg("could not read response from control server")
		}
		mainLog.Load().Error().Err(err).Msgf("failed to reload ctrld: %s", string(buf))
	}
	return nil
}
