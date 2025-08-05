package cli

import (
	"io"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/kardianos/service"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

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
	customHostname    string
	cdDev             bool
	iface             string
	ifaceStartStop    string
	nextdns           string
	cdUpstreamProto   string
	deactivationPin   int64
	skipSelfChecks    bool
	cleanup           bool
	startOnly         bool

	mainLog            atomic.Pointer[ctrld.Logger]
	consoleWriter      zapcore.Core
	consoleWriterLevel zapcore.Level
	noConfigStart      bool
)

const (
	cdUidFlagName          = "cd"
	cdOrgFlagName          = "cd-org"
	customHostnameFlagName = "custom-hostname"
	nextdnsFlagName        = "nextdns"
)

func init() {
	l := zap.NewNop()
	mainLog.Store(&ctrld.Logger{Logger: l})
}

func Main() {
	ctrld.InitConfig(v, "ctrld")
	rootCmd := initCLI()
	if err := rootCmd.Execute(); err != nil {
		mainLog.Load().Error().Msg(err.Error())
		os.Exit(1)
	}
}

func normalizeLogFilePath(logFilePath string) string {
	if logFilePath == "" || filepath.IsAbs(logFilePath) || service.Interactive() {
		return logFilePath
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
	consoleWriterLevel = ctrld.NoticeLevel
	switch {
	case silent:
		// For silent mode, use a no-op logger
		l := zap.NewNop()
		mainLog.Store(&ctrld.Logger{Logger: l})
	case verbose == 1:
		// Info level
		consoleWriterLevel = zapcore.InfoLevel
	case verbose > 1:
		// Debug level
		consoleWriterLevel = zapcore.DebugLevel
	}
	consoleWriter = newHumanReadableZapCore(os.Stdout, consoleWriterLevel)
	l := zap.New(consoleWriter)
	mainLog.Store(&ctrld.Logger{Logger: l})
}

// initInteractiveLogging is like initLogging, but the ProxyLogger is discarded
// to be used for all interactive commands.
//
// Current log file config will also be ignored.
func initInteractiveLogging() {
	old := cfg.Service.LogPath
	cfg.Service.LogPath = ""
	initLoggingWithBackup(false)
	cfg.Service.LogPath = old
}

// initLoggingWithBackup initializes log setup base on current config.
// If doBackup is true, backup old log file with ".1" suffix.
//
// This is only used in runCmd for special handling in case of logging config
// change in cd mode. Without special reason, the caller should use initLogging
// wrapper instead of calling this function directly.
func initLoggingWithBackup(doBackup bool) []zapcore.Core {
	var writers []io.Writer
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

	// Create zap cores for different writers
	var cores []zapcore.Core
	cores = append(cores, consoleWriter)

	// Determine log level
	logLevel := cfg.Service.LogLevel
	switch {
	case silent:
		// For silent mode, use a no-op logger
		l := zap.NewNop()
		mainLog.Store(&ctrld.Logger{Logger: l})
		return cores
	case verbose == 1:
		logLevel = "info"
	case verbose > 1:
		logLevel = "debug"
	}

	// Parse log level
	var level zapcore.Level
	switch logLevel {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "notice":
		level = ctrld.NoticeLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel // default level
	}

	consoleWriter.Enabled(level)
	// Add cores for all writers
	for _, writer := range writers {
		core := newMachineFriendlyZapCore(writer, level)
		cores = append(cores, core)
	}

	// Create a multi-core logger
	multiCore := zapcore.NewTee(cores...)
	logger := zap.New(multiCore)
	mainLog.Store(&ctrld.Logger{Logger: logger})

	return cores
}

func initCache() {
	if !cfg.Service.CacheEnable {
		return
	}
	if cfg.Service.CacheSize == 0 {
		cfg.Service.CacheSize = 4096
	}
}
