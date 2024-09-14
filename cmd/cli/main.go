package cli

import (
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/kardianos/service"
	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
)

var (
	configPath        string
	configBase64      string
	daemon            bool
	listenAddress     string
	primaryUpstream   string
	secondaryUpstream string
	domains           []string
	logPath           string
	homedir           string
	cacheSize         int
	cfg               ctrld.Config
	verbose           int
	silent            bool
	cdUID             string
	cdOrg             string
	cdDev             bool
	iface             string
	ifaceStartStop    string
	nextdns           string
	cdUpstreamProto   string
	deactivationPin   int64
	skipSelfChecks    bool
	cleanup           bool
	startOnly         bool

	mainLog       atomic.Pointer[zerolog.Logger]
	consoleWriter zerolog.ConsoleWriter
	noConfigStart bool
)

const (
	cdUidFlagName   = "cd"
	cdOrgFlagName   = "cd-org"
	nextdnsFlagName = "nextdns"
)

func init() {
	l := zerolog.New(io.Discard)
	mainLog.Store(&l)
}

func Main() {
	ctrld.InitConfig(v, "ctrld")
	initCLI()
	if err := rootCmd.Execute(); err != nil {
		mainLog.Load().Error().Msg(err.Error())
		os.Exit(1)
	}
}

func normalizeLogFilePath(logFilePath string) string {
	// In cleanup mode, we always want the full log file path.
	if !cleanup {
		if logFilePath == "" || filepath.IsAbs(logFilePath) || service.Interactive() {
			return logFilePath
		}
	}
	if homedir != "" {
		return filepath.Join(homedir, logFilePath)
	}
	dir, _ := userHomeDir()
	if dir == "" {
		return logFilePath
	}
	return filepath.Join(dir, logFilePath)
}

// initConsoleLogging initializes console logging, then storing to mainLog.
func initConsoleLogging() {
	consoleWriter = zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.TimeFormat = time.StampMilli
	})
	multi := zerolog.MultiLevelWriter(consoleWriter)
	l := mainLog.Load().Output(multi).With().Timestamp().Logger()
	mainLog.Store(&l)
	switch {
	case silent:
		zerolog.SetGlobalLevel(zerolog.NoLevel)
	case verbose == 1:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case verbose > 1:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.NoticeLevel)
	}
}

// initLogging initializes global logging setup.
func initLogging() {
	zerolog.TimeFieldFormat = time.RFC3339 + ".000"
	initLoggingWithBackup(true)
}

// initLoggingWithBackup initializes log setup base on current config.
// If doBackup is true, backup old log file with ".1" suffix.
//
// This is only used in runCmd for special handling in case of logging config
// change in cd mode. Without special reason, the caller should use initLogging
// wrapper instead of calling this function directly.
func initLoggingWithBackup(doBackup bool) {
	writers := []io.Writer{io.Discard}
	if logFilePath := normalizeLogFilePath(cfg.Service.LogPath); logFilePath != "" {
		// Create parent directory if necessary.
		if err := os.MkdirAll(filepath.Dir(logFilePath), 0750); err != nil {
			mainLog.Load().Error().Msgf("failed to create log path: %v", err)
			os.Exit(1)
		}

		// Default open log file in append mode.
		flags := os.O_CREATE | os.O_RDWR | os.O_APPEND
		if doBackup {
			// Backup old log file with .1 suffix.
			if err := os.Rename(logFilePath, logFilePath+oldLogSuffix); err != nil && !os.IsNotExist(err) {
				mainLog.Load().Error().Msgf("could not backup old log file: %v", err)
			} else {
				// Backup was created, set flags for truncating old log file.
				flags = os.O_CREATE | os.O_RDWR
			}
		}
		logFile, err := openLogFile(logFilePath, flags)
		if err != nil {
			mainLog.Load().Error().Msgf("failed to create log file: %v", err)
			os.Exit(1)
		}
		writers = append(writers, logFile)
	}
	writers = append(writers, consoleWriter)
	multi := zerolog.MultiLevelWriter(writers...)
	l := mainLog.Load().Output(multi).With().Logger()
	mainLog.Store(&l)
	// TODO: find a better way.
	ctrld.ProxyLogger.Store(&l)

	zerolog.SetGlobalLevel(zerolog.NoticeLevel)
	logLevel := cfg.Service.LogLevel
	switch {
	case silent:
		zerolog.SetGlobalLevel(zerolog.NoLevel)
		return
	case verbose == 1:
		logLevel = "info"
	case verbose > 1:
		logLevel = "debug"
	}
	if logLevel == "" {
		return
	}
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not set log level")
		return
	}
	zerolog.SetGlobalLevel(level)
}

func initCache() {
	if !cfg.Service.CacheEnable {
		return
	}
	if cfg.Service.CacheSize == 0 {
		cfg.Service.CacheSize = 4096
	}
}
