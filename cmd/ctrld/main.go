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
	configPath string
	daemon     bool
	cfg        ctrld.Config
	verbose    bool

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
	if verbose || isLog {
		consoleWriter := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.TimeFormat = time.StampMilli
		})
		writers = append(writers, consoleWriter)
		multi := zerolog.MultiLevelWriter(writers...)
		mainLog = mainLog.Output(multi).With().Timestamp().Str("prefix", "main").Logger()
		proxyLog = proxyLog.Output(multi).With().Timestamp().Logger()
		// TODO: find a better way.
		ctrld.ProxyLog = proxyLog
	}
	if cfg.Service.LogLevel == "" {
		return
	}
	level, err := zerolog.ParseLevel(cfg.Service.LogLevel)
	if err != nil {
		mainLog.Warn().Err(err).Msg("could not set log level")
		return
	}
	zerolog.SetGlobalLevel(level)
}
