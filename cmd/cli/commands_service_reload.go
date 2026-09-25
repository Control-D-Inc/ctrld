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
	logger := mainLog.Load()
	logger.Debug().Msg("Service reload command started")

	s, _, err := sc.initializeServiceManager()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to initialize service manager")
		return err
	}

	status, err := s.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		logger.Warn().Msg("Service not installed")
		return nil
	}
	if status == service.StatusStopped {
		logger.Warn().Msg("Service is not running")
		return nil
	}

	dir, err := socketDir()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to find ctrld home dir")
	}

	cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
	resp, err := cc.post(reloadPath, nil)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to send reload signal to ctrld")
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		logger.Notice().Msg("Service reloaded")
	case http.StatusCreated:
		logger.Warn().Msg("Service was reloaded, but new config requires service restart.")
		logger.Warn().Msg("Restarting service")
		if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
			logger.Warn().Msg("Service not installed")
			return nil
		}
		return sc.Restart(cmd, args)
	default:
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Fatal().Err(err).Msg("Could not read response from control server")
		}
		logger.Error().Err(err).Msgf("Failed to reload ctrld: %s", string(buf))
	}

	logger.Debug().Msg("Service reload command completed")
	return nil
}
