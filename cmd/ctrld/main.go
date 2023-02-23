package main

import (
	"io"
	"log"
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

	bootstrapDNS = "76.76.2.0"

	rootLogger = zerolog.New(io.Discard)
	mainLog    = rootLogger

	cdUID          string
	iface          string
	ifaceStartStop string
)

func main() {
	ctrld.InitConfig(v, "ctrld")
	initCLI()
}

func normalizeLogFilePath(logFilePath string) string {
	if logFilePath == "" || filepath.IsAbs(logFilePath) || service.Interactive() {
		return logFilePath
	}
	if homedir != "" {
		return filepath.Join(homedir, logFilePath)
	}
	dir, _ := os.UserHomeDir()
	if dir == "" {
		return logFilePath
	}
	return filepath.Join(dir, logFilePath)
}

func initLogging() {
	writers := []io.Writer{io.Discard}
	if logFilePath := normalizeLogFilePath(cfg.Service.LogPath); logFilePath != "" {
		// Create parent directory if necessary.
		if err := os.MkdirAll(filepath.Dir(logFilePath), 0750); err != nil {
			log.Printf("failed to create log path: %v", err)
			os.Exit(1)
		}
		// Backup old log file with .1 suffix.
		if err := os.Rename(logFilePath, logFilePath+".1"); err != nil && !os.IsNotExist(err) {
			log.Printf("could not backup old log file: %v", err)
		}
		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_RDWR, os.FileMode(0o600))
		if err != nil {
			log.Printf("failed to create log file: %v", err)
			os.Exit(1)
		}
		writers = append(writers, logFile)
	}
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	consoleWriter := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.TimeFormat = time.StampMilli
	})
	writers = append(writers, consoleWriter)
	multi := zerolog.MultiLevelWriter(writers...)
	mainLog = mainLog.Output(multi).With().Timestamp().Logger()
	// TODO: find a better way.
	ctrld.ProxyLog = mainLog

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logLevel := cfg.Service.LogLevel
	if verbose > 1 {
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
