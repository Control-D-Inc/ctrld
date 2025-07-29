package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"
)

// Restart implements the logic from cmdRestart.Run
func (sc *ServiceCommand) Restart(cmd *cobra.Command, args []string) error {
	s := sc.serviceManager.svc
	p := sc.serviceManager.prog
	readConfig(false)
	v.Unmarshal(&cfg)
	cdUID = curCdUID()
	cdMode := cdUID != ""

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

	var validateConfigErr error
	if cdMode {
		validateConfigErr = doValidateCdRemoteConfig(cdUID, false)
	}

	if ir := runningIface(s); ir != nil {
		iface = ir.Name
	}
	doRestart := func() bool {
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
			return false
		}
		tasks = []task{
			{s.Start, true, "Start"},
		}
		return doTasks(tasks)
	}

	if doRestart() {
		if dir, err := socketDir(); err == nil {
			timeout := dialSocketControlServerTimeout
			if validateConfigErr != nil {
				timeout = 5 * time.Second
			}
			if cc := newSocketControlClientWithTimeout(context.TODO(), s, dir, timeout); cc != nil {
				_, _ = cc.post(ifacePath, nil)
			} else {
				mainLog.Load().Warn().Err(err).Msg("Service was restarted, but ctrld process may not be ready yet")
			}
		} else {
			mainLog.Load().Warn().Err(err).Msg("Service was restarted, but could not ping the control server")
		}
		mainLog.Load().Notice().Msg("Service restarted")
	} else {
		mainLog.Load().Error().Msg("Service restart failed")
	}
	return nil
}
