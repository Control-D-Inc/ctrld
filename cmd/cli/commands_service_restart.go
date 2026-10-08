package cli

import (
	"context"
	"errors"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// Restart implements the logic from cmdRestart.Run
func (sc *ServiceCommand) Restart(cmd *cobra.Command, args []string) error {
	logger := mainLog.Load()
	logger.Debug().Msg("Service restart command started")

	readConfig(false)
	v.Unmarshal(&cfg)
	cdUID = curCdUID()
	cdMode := cdUID != ""

	s, p, err := sc.initializeServiceManager()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to initialize service manager")
		return err
	}

	if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
		logger.Warn().Msg("Service not installed")
		return nil
	}

	p.cfg = &cfg
	if iface == "" {
		iface = autoIface
	}
	p.preRun()
	if ir := runningIface(s); ir != nil {
		p.runningIface = ir.Name
		p.requiredMultiNICsConfig = ir.All
	}

	initInteractiveLogging()

	var validateConfigErr error
	if cdMode {
		logger.Debug().Msg("Validating ControlD remote config")
		validateConfigErr = doValidateCdRemoteConfig(cdUID, false)
		if validateConfigErr != nil {
			logger.Warn().Err(validateConfigErr).Msg("ControlD remote config validation failed")
		}
	}

	if ir := runningIface(s); ir != nil {
		iface = ir.Name
	}

	doRestart := func() bool {
		logger.Debug().Msg("Starting service restart sequence")

		tasks := []task{
			{s.Stop, true, "Stop"},
			{func() error {
				// restore static DNS settings or DHCP
				p.resetDNS(false, true)
				return nil
			}, false, "Cleanup"},
			{func() error {
				time.Sleep(time.Second * 1)
				return nil
			}, false, "Waiting for service to stop"},
		}
		if !doTasks(tasks) {
			logger.Error().Msg("Service stop tasks failed")
			return false
		}
		tasks = []task{
			{s.Start, true, "Start"},
		}
		success := doTasks(tasks)
		if success {
			logger.Debug().Msg("Service restart sequence completed successfully")
		} else {
			logger.Error().Msg("Service restart sequence failed")
		}
		return success
	}

	if doRestart() {
		if dir, err := socketDir(); err == nil {
			timeout := dialSocketControlServerTimeout
			if validateConfigErr != nil {
				timeout = 5 * time.Second
			}
			// Only a ready service counts. Restart replaces nothing, so
			// there is nothing to roll back, but a service that came
			// back without finishing its start must not be reported as
			// restarted cleanly.
			if cc := newReadySocketControlClientWithTimeout(context.TODO(), s, dir, timeout); cc != nil {
				_, _ = cc.post(ifacePath, nil)
				logger.Debug().Msg("Control server ping successful")
			} else {
				logger.Warn().Msgf("Service was restarted, but ctrld did not report ready within %s; check `ctrld status`", timeout)
				return nil
			}
		} else {
			logger.Warn().Err(err).Msg("Service was restarted, but could not ping the control server")
			return nil
		}
		logger.Notice().Msg("Service restarted")
	} else {
		logger.Error().Msg("Service restart failed")
	}

	logger.Debug().Msg("Service restart command completed")
	return nil
}
