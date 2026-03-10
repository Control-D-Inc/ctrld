package cli

import (
	"errors"
	"os"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// Stop implements the logic from cmdStop.Run
func (sc *ServiceCommand) Stop(cmd *cobra.Command, args []string) error {
	logger := mainLog.Load()
	logger.Debug().Msg("Service stop command started")

	readConfig(false)
	v.Unmarshal(&cfg)

	s, p, err := sc.initializeServiceManager()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to initialize service manager")
		return err
	}

	p.cfg = &cfg
	if iface == "" {
		iface = "auto"
	}
	p.preRun()
	if ir := runningIface(s); ir != nil {
		p.runningIface = ir.Name
		p.requiredMultiNICsConfig = ir.All
	}

	initInteractiveLogging()

	status, err := s.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		logger.Warn().Msg("Service not installed")
		return nil
	}
	if status == service.StatusStopped {
		logger.Warn().Msg("Service is already stopped")
		return nil
	}

	if err := checkDeactivationPin(s, nil); isCheckDeactivationPinErr(err) {
		logger.Error().Msg("Deactivation pin check failed")
		os.Exit(deactivationPinInvalidExitCode)
	}

	logger.Debug().Msg("Stopping service")
	if doTasks([]task{{s.Stop, true, "Stop"}}) {
		logger.Notice().Msg("Service stopped")
	} else {
		logger.Error().Msg("Service stop failed")
	}

	logger.Debug().Msg("Service stop command completed")
	return nil
}
