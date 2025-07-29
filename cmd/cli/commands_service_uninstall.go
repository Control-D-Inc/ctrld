package cli

import (
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Control-D-Inc/ctrld"
)

// Uninstall implements the logic from cmdUninstall.Run
func (sc *ServiceCommand) Uninstall(cmd *cobra.Command, args []string) error {
	s := sc.serviceManager.svc
	p := sc.serviceManager.prog
	readConfig(false)
	v.Unmarshal(&cfg)
	p.cfg = &cfg
	if iface == "" {
		iface = "auto"
	}
	p.preRun()
	if ir := runningIface(s); ir != nil {
		p.runningIface = ir.Name
		p.requiredMultiNICsConfig = ir.All
	}
	if err := checkDeactivationPin(s, nil); isCheckDeactivationPinErr(err) {
		os.Exit(deactivationPinInvalidExitCode)
	}
	uninstall(p, s)
	if cleanup {
		var files []string
		// Config file.
		files = append(files, v.ConfigFileUsed())
		// Log file and backup log file.
		// For safety, only process if log file path is absolute.
		if logFile := normalizeLogFilePath(cfg.Service.LogPath); filepath.IsAbs(logFile) {
			files = append(files, logFile)
			oldLogFile := logFile + oldLogSuffix
			if _, err := os.Stat(oldLogFile); err == nil {
				files = append(files, oldLogFile)
			}
		}
		// Socket files.
		if dir, _ := socketDir(); dir != "" {
			files = append(files, filepath.Join(dir, ctrldControlUnixSock))
			files = append(files, filepath.Join(dir, ctrldLogUnixSock))
		}
		// Static DNS settings files.
		withEachPhysicalInterfaces("", "", func(i *net.Interface) error {
			file := ctrld.SavedStaticDnsSettingsFilePath(i)
			files = append(files, file)
			return nil
		})
		bin, err := os.Executable()
		if err != nil {
			mainLog.Load().Warn().Err(err).Msg("failed to get executable path")
		}
		if bin != "" && supportedSelfDelete {
			files = append(files, bin)
		}
		// Backup file after upgrading.
		oldBin := bin + oldBinSuffix
		if _, err := os.Stat(oldBin); err == nil {
			files = append(files, oldBin)
		}
		for _, file := range files {
			if file == "" {
				continue
			}
			if err := os.Remove(file); err == nil {
				mainLog.Load().Notice().Msgf("removed %s", file)
			}
		}
		// Self-delete the ctrld binary if supported
		if err := selfDeleteExe(); err != nil {
			mainLog.Load().Warn().Err(err).Msg("failed to delete ctrld binary")
		} else {
			if !supportedSelfDelete {
				mainLog.Load().Debug().Msgf("file removed: %s", bin)
			}
		}
	}
	return nil
}
