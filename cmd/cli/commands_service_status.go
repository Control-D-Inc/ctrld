package cli

import (
	"os"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// Status implements the logic from cmdStatus.Run
func (sc *ServiceCommand) Status(cmd *cobra.Command, args []string) error {
	logger := mainLog.Load()
	logger.Debug().Msg("Service status command started")

	s, _, err := sc.initializeServiceManager()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to initialize service manager")
		return err
	}

	status, err := s.Status()
	if err != nil {
		logger.Error().Msg(err.Error())
		os.Exit(1)
	}

	switch status {
	case service.StatusUnknown:
		logger.Notice().Msg("Unknown status")
		os.Exit(2)
	case service.StatusRunning:
		logger.Notice().Msg("Service is running")
		os.Exit(0)
	case service.StatusStopped:
		logger.Notice().Msg("Service is stopped")
		os.Exit(1)
	}

	logger.Debug().Msg("Service status command completed")
	return nil
}
