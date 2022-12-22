package main

import (
	"fmt"
	"io"
	"os"
	"time"

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
	cacheSize         int
	cfg               ctrld.Config
	verbose           int

	bootstrapDNS = "76.76.2.0"

	rootLogger = zerolog.New(io.Discard)
	mainLog    = rootLogger
	proxyLog   = rootLogger
)

func main() {
	ctrld.InitConfig(v, "config")
	initCLI()
}

func initLogging() {
	writers := []io.Writer{io.Discard}
	isLog := cfg.Service.LogLevel != ""
	if logPath := cfg.Service.LogPath; logPath != "" {
		logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to creating log file: %v", err)
			os.Exit(1)
		}
		isLog = true
		writers = append(writers, logFile)
	}
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	consoleWriter := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.TimeFormat = time.StampMilli
	})
	writers = append(writers, consoleWriter)
	multi := zerolog.MultiLevelWriter(writers...)
	mainLog = mainLog.Output(multi).With().Timestamp().Str("prefix", "main").Logger()
	if verbose > 0 || isLog {
		proxyLog = proxyLog.Output(multi).With().Timestamp().Logger()
		// TODO: find a better way.
		ctrld.ProxyLog = proxyLog
	}

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
