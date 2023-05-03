package main

import (
	"io"
	"os"
	"path/filepath"
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
	cdUID             string
	iface             string
	ifaceStartStop    string
	setupRouter       bool

	mainLog       = zerolog.New(io.Discard)
	consoleWriter zerolog.ConsoleWriter
)

func main() {
	ctrld.InitConfig(v, "ctrld")
	initCLI()
	initRouterCLI()
	if err := rootCmd.Execute(); err != nil {
		mainLog.Error().Msg(err.Error())
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

func initConsoleLogging() {
	consoleWriter = zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.TimeFormat = time.StampMilli
	})
	multi := zerolog.MultiLevelWriter(consoleWriter)
	mainLog = mainLog.Output(multi).With().Timestamp().Logger()
	switch {
	case verbose == 1:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case verbose > 1:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}
}

func initLogging() {
	writers := []io.Writer{io.Discard}
	if logFilePath := normalizeLogFilePath(cfg.Service.LogPath); logFilePath != "" {
		// Create parent directory if necessary.
		if err := os.MkdirAll(filepath.Dir(logFilePath), 0750); err != nil {
			mainLog.Error().Msgf("failed to create log path: %v", err)
			os.Exit(1)
		}
		// Backup old log file with .1 suffix.
		if err := os.Rename(logFilePath, logFilePath+".1"); err != nil && !os.IsNotExist(err) {
			mainLog.Error().Msgf("could not backup old log file: %v", err)
		}
		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_RDWR, os.FileMode(0o600))
		if err != nil {
			mainLog.Error().Msgf("failed to create log file: %v", err)
			os.Exit(1)
		}
		writers = append(writers, logFile)
	}
	writers = append(writers, consoleWriter)
	multi := zerolog.MultiLevelWriter(writers...)
	mainLog = mainLog.Output(multi).With().Timestamp().Logger()
	// TODO: find a better way.
	ctrld.ProxyLog = mainLog

	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	logLevel := cfg.Service.LogLevel
	switch {
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
		mainLog.Warn().Err(err).Msg("could not set log level")
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
