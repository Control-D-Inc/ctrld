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

// Global variables for CLI configuration and state management
// These are used across multiple commands and need to persist throughout the application lifecycle
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
	rfc1918           bool

	mainLog            atomic.Pointer[ctrld.Logger]
	consoleWriter      zapcore.Core
	consoleWriterLevel zapcore.Level
	noConfigStart      bool
)

// Flag name constants for consistent reference across the codebase
// Using constants prevents typos and makes refactoring easier
const (
	cdUidFlagName          = "cd"
	cdOrgFlagName          = "cd-org"
	customHostnameFlagName = "custom-hostname"
	nextdnsFlagName        = "nextdns"
)

// init initializes the default logger before any CLI commands are executed
// This ensures logging is available even during early initialization phases
func init() {
	l := zap.NewNop()
	mainLog.Store(&ctrld.Logger{Logger: l})
}

// Main is the entry point for the CLI application
// It initializes configuration, sets up the CLI structure, and executes the root command
func Main() {
	ctrld.InitConfig(v, "ctrld")
	rootCmd := initCLI()
	if err := rootCmd.Execute(); err != nil {
		mainLog.Load().Error().Msg(err.Error())
		os.Exit(1)
	}
}

// normalizeLogFilePath converts relative log file paths to absolute paths
// This ensures log files are created in predictable locations regardless of working directory
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
// This sets up human-readable logging output for interactive use
func initConsoleLogging() {
	consoleWriterLevel = ctrld.NoticeLevel
	switch {
	case silent:
		// For silent mode, use a no-op logger to suppress all output
		l := zap.NewNop()
		mainLog.Store(&ctrld.Logger{Logger: l})
	case verbose == 1:
		// Info level provides basic operational information
		consoleWriterLevel = zapcore.InfoLevel
	case verbose > 1:
		// Debug level provides detailed diagnostic information
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
// This prevents log file conflicts during interactive command execution
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
		// This ensures log files can be created even if the directory doesn't exist
		if err := os.MkdirAll(filepath.Dir(logFilePath), 0750); err != nil {
			mainLog.Load().Error().Msgf("Failed to create log path: %v", err)
			os.Exit(1)
		}

		// Default open log file in append mode.
		// This preserves existing log entries across restarts
		flags := os.O_CREATE | os.O_RDWR | os.O_APPEND
		if doBackup {
			// Backup old log file with .1 suffix.
			// This prevents log file corruption during rotation
			if err := os.Rename(logFilePath, logFilePath+oldLogSuffix); err != nil && !os.IsNotExist(err) {
				mainLog.Load().Error().Msgf("Could not backup old log file: %v", err)
			} else {
				// Backup was created, set flags for truncating old log file.
				// This ensures a clean start for the new log file
				flags = os.O_CREATE | os.O_RDWR
			}
		}
		logFile, err := openLogFile(logFilePath, flags)
		if err != nil {
			mainLog.Load().Error().Msgf("Failed to create log file: %v", err)
			os.Exit(1)
		}
		writers = append(writers, logFile)
	}

	// Create zap cores for different writers
	// Multiple cores allow logging to both console and file simultaneously
	var cores []zapcore.Core
	cores = append(cores, consoleWriter)

	// Determine log level based on verbosity and configuration
	// This provides flexible logging control for different use cases
	logLevel := cfg.Service.LogLevel
	switch {
	case silent:
		// For silent mode, use a no-op logger to suppress all output
		l := zap.NewNop()
		mainLog.Store(&ctrld.Logger{Logger: l})
		return cores
	case verbose == 1:
		logLevel = "info"
	case verbose > 1:
		logLevel = "debug"
	}

	// Parse log level string to zapcore.Level
	// This provides human-readable log level configuration
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
	// This enables multi-destination logging (console + file)
	for _, writer := range writers {
		core := newMachineFriendlyZapCore(writer, level)
		cores = append(cores, core)
	}

	// Create a multi-core logger
	// This allows simultaneous logging to multiple destinations
	multiCore := zapcore.NewTee(cores...)
	logger := zap.New(multiCore)
	mainLog.Store(&ctrld.Logger{Logger: logger})

	return cores
}

// initCache initializes DNS cache configuration
// This improves performance by caching frequently requested DNS responses
func initCache() {
	if !cfg.Service.CacheEnable {
		return
	}
	if cfg.Service.CacheSize == 0 {
		// Default cache size provides good balance between memory usage and performance
		cfg.Service.CacheSize = 4096
	}
}
