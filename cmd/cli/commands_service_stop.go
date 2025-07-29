package cli

import (
	"errors"
	"os"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// Stop implements the logic from cmdStop.Run
func (sc *ServiceCommand) Stop(cmd *cobra.Command, args []string) error {
	s := sc.serviceManager.svc
	p := sc.serviceManager.prog
	readConfig(false)
	v.Unmarshal(&cfg)
	p.cfg = &cfg
	p.preRun()
	if ir := runningIface(s); ir != nil {
		p.runningIface = ir.Name
		p.requiredMultiNICsConfig = ir.All
	}

	initInteractiveLogging()

	status, err := s.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		mainLog.Load().Warn().Msg("service not installed")
		return nil
	}
	if status == service.StatusStopped {
		mainLog.Load().Warn().Msg("service is already stopped")
		return nil
	}

	if err := checkDeactivationPin(s, nil); isCheckDeactivationPinErr(err) {
		os.Exit(deactivationPinInvalidExitCode)
	}
	if doTasks([]task{{s.Stop, true, "Stop"}}) {
		mainLog.Load().Notice().Msg("Service stopped")
	}
	return nil
}
