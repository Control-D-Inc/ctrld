package cli

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/minio/selfupdate"
	"github.com/spf13/cobra"
)

const (
	upgradeChannelDev     = "dev"
	upgradeChannelProd    = "prod"
	upgradeChannelDefault = "default"
)

// UpgradeCommand handles upgrade-related operations
type UpgradeCommand struct {
	serviceManager *ServiceManager
}

// NewUpgradeCommand creates a new upgrade command handler
func NewUpgradeCommand() (*UpgradeCommand, error) {
	sm, err := NewServiceManager()
	if err != nil {
		return nil, err
	}

	return &UpgradeCommand{
		serviceManager: sm,
	}, nil
}

// Upgrade performs the upgrade operation
func (uc *UpgradeCommand) Upgrade(cmd *cobra.Command, args []string) error {
	upgradeChannel := map[string]string{
		upgradeChannelDefault: "https://dl.controld.dev",
		upgradeChannelDev:     "https://dl.controld.dev",
		upgradeChannelProd:    "https://dl.controld.com",
	}
	if isStableVersion(curVersion()) {
		upgradeChannel[upgradeChannelDefault] = upgradeChannel[upgradeChannelProd]
	}

	bin, err := os.Executable()
	if err != nil {
		mainLog.Load().Fatal().Err(err).Msg("failed to get current ctrld binary path")
	}

	// Create service config with executable path
	sc := &service.Config{
		Name:        ctrldServiceName,
		DisplayName: "Control-D Helper Service",
		Description: "A highly configurable, multi-protocol DNS forwarding proxy",
		Option:      service.KeyValue{},
		Executable:  bin,
	}

	readConfig(false)
	v.Unmarshal(&cfg)
	p := &prog{}
	s, err := newService(p, sc)
	if err != nil {
		mainLog.Load().Error().Msg(err.Error())
		return nil
	}

	if iface == "" {
		iface = "auto"
	}
	p.preRun()
	if ir := runningIface(s); ir != nil {
		p.runningIface = ir.Name
		p.requiredMultiNICsConfig = ir.All
	}

	svcInstalled := true
	if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
		svcInstalled = false
	}

	oldBin := bin + oldBinSuffix
	baseUrl := upgradeChannel[upgradeChannelDefault]
	if len(args) > 0 {
		channel := args[0]
		switch channel {
		case upgradeChannelProd, upgradeChannelDev: // ok
		default:
			mainLog.Load().Fatal().Msgf("uprade argument must be either %q or %q", upgradeChannelProd, upgradeChannelDev)
		}
		baseUrl = upgradeChannel[channel]
	}

	dlUrl := upgradeUrl(baseUrl)
	mainLog.Load().Debug().Msgf("Downloading binary: %s", dlUrl)

	resp, err := getWithRetry(dlUrl, downloadServerIp)
	if err != nil {
		mainLog.Load().Fatal().Err(err).Msg("failed to download binary")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		mainLog.Load().Fatal().Msgf("could not download binary: %s", http.StatusText(resp.StatusCode))
	}

	mainLog.Load().Debug().Msg("Updating current binary")
	if err := selfupdate.Apply(resp.Body, selfupdate.Options{OldSavePath: oldBin}); err != nil {
		if rerr := selfupdate.RollbackError(err); rerr != nil {
			mainLog.Load().Error().Err(rerr).Msg("could not rollback old binary")
		}
		mainLog.Load().Fatal().Err(err).Msg("failed to update current binary")
	}

	doRestart := func() bool {
		if !svcInstalled {
			return true
		}
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
		doTasks(tasks)

		tasks = []task{
			{s.Start, true, "Start"},
		}
		if doTasks(tasks) {
			if dir, err := socketDir(); err == nil {
				if cc := newSocketControlClient(context.TODO(), s, dir); cc != nil {
					_, _ = cc.post(ifacePath, nil)
					return true
				}
			}
		}
		return false
	}

	if svcInstalled {
		mainLog.Load().Debug().Msg("Restarting ctrld service using new binary")
	}

	if doRestart() {
		_ = os.Remove(oldBin)
		_ = os.Chmod(bin, 0755)
		ver := "unknown version"
		out, err := exec.Command(bin, "--version").CombinedOutput()
		if err != nil {
			mainLog.Load().Warn().Err(err).Msg("Failed to get new binary version")
		}
		if after, found := strings.CutPrefix(string(out), "ctrld version "); found {
			ver = after
		}
		mainLog.Load().Notice().Msgf("Upgrade successful - %s", ver)
		return nil
	}

	mainLog.Load().Warn().Msgf("Upgrade failed, restoring previous binary: %s", oldBin)
	if err := os.Remove(bin); err != nil {
		mainLog.Load().Fatal().Err(err).Msg("failed to remove new binary")
	}
	if err := os.Rename(oldBin, bin); err != nil {
		mainLog.Load().Fatal().Err(err).Msg("failed to restore old binary")
	}
	if doRestart() {
		mainLog.Load().Notice().Msg("Restored previous binary successfully")
		return nil
	}

	return nil
}

// InitUpgradeCmd creates the upgrade command with proper logic
func InitUpgradeCmd() *cobra.Command {
	upgradeCmd := &cobra.Command{
		Use:       "upgrade",
		Short:     "Upgrading ctrld to latest version",
		ValidArgs: []string{upgradeChannelDev, upgradeChannelProd},
		Args:      cobra.MaximumNArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			uc, err := NewUpgradeCommand()
			if err != nil {
				return err
			}
			return uc.Upgrade(cmd, args)
		},
	}

	rootCmd.AddCommand(upgradeCmd)

	return upgradeCmd
}
