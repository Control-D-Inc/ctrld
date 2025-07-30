package cli

import (
	"os"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// Status implements the logic from cmdStatus.Run
func (sc *ServiceCommand) Status(cmd *cobra.Command, args []string) error {
	s, _, err := sc.initializeServiceManager()
	if err != nil {
		return err
	}
	status, err := s.Status()
	if err != nil {
		mainLog.Load().Error().Msg(err.Error())
		os.Exit(1)
	}
	switch status {
	case service.StatusUnknown:
		mainLog.Load().Notice().Msg("Unknown status")
		os.Exit(2)
	case service.StatusRunning:
		mainLog.Load().Notice().Msg("Service is running")
		os.Exit(0)
	case service.StatusStopped:
		mainLog.Load().Notice().Msg("Service is stopped")
		os.Exit(1)
	}
	return nil
}
