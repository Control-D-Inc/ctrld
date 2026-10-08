package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Control-D-Inc/ctrld"
)

// Uninstall implements the logic from cmdUninstall.Run
func (sc *ServiceCommand) Uninstall(cmd *cobra.Command, args []string) error {
	logger := mainLog.Load()
	logger.Debug().Msg("Service uninstall command started")

	readConfig(false)
	v.Unmarshal(&cfg)

	s, p, err := sc.initializeServiceManager()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to initialize service manager")
		return err
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

	if err := checkDeactivationPin(s, nil); isCheckDeactivationPinErr(err) {
		logger.Error().Msg("Deactivation pin check failed")
		os.Exit(deactivationPinInvalidExitCode)
	}

	logger.Debug().Msg("Starting service uninstall")
	uninstall(p, s)

	if cleanup {
		logger.Debug().Msg("Performing cleanup operations")
		var files []string
		// Config file.
		files = append(files, v.ConfigFileUsed())
		// Log files. For safety, only remove the log_path chain if that path
		// is absolute.
		logFile := normalizeLogFilePath(cfg.Service.LogPath)
		if !filepath.IsAbs(logFile) {
			logFile = ""
		}
		internalLogs := []string{absHomeDir(logFileName), absHomeDir(journalLogFileName)}
		for _, err := range removeLogFiles(logFile, debugLogBudget(&cfg.Service).backups, internalLogs) {
			logger.Warn().Err(err).Msg("Failed to remove log file")
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
			logger.Warn().Err(err).Msg("Failed to get executable path")
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
				logger.Notice().Str("file", file).Msg("File removed during cleanup")
			} else {
				logger.Debug().Err(err).Str("file", file).Msg("Failed to remove file during cleanup")
			}
		}
		// Self-delete the ctrld binary if supported
		if err := selfDeleteExe(); err != nil {
			logger.Warn().Err(err).Msg("Failed to delete ctrld binary")
		} else {
			if !supportedSelfDelete {
				logger.Debug().Msgf("File removed: %s", bin)
			}
		}

		logger.Debug().Msg("Cleanup operations completed")
	}

	logger.Debug().Msg("Service uninstall command completed")
	return nil
}

// removeLogFiles deletes the log files of this installation and returns what
// it could not remove. A missing file is not an error.
func removeLogFiles(logPath string, backups int, internalPaths []string) []error {
	for _, path := range internalPaths {
		pruneNumberedBackups(path, 0)
	}
	var errs []error
	for _, path := range logFilesToRemove(logPath, backups, internalPaths) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove %s: %w", path, err))
		}
	}
	return errs
}

// logFilesToRemove names the log files of this installation. The log_path
// backups come from the configured count, because log_path can name a file in
// a directory that holds the files of other programs, and a scan of that
// directory would take their files too. An empty logPath leaves the internal
// files alone.
func logFilesToRemove(logPath string, backups int, internalPaths []string) []string {
	var paths []string
	if logPath != "" {
		paths = append(paths, logPath)
		for index := 1; index <= backups; index++ {
			paths = append(paths, fmt.Sprintf("%s.%d", logPath, index))
		}
	}
	return append(paths, internalPaths...)
}
