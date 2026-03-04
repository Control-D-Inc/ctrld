package cli

import (
	"encoding/hex"
	"io"
	"net"
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
	interceptMode     string // "", "dns", or "hard" — set via --intercept-mode flag or config
	dnsIntercept      bool   // derived: interceptMode == "dns" || interceptMode == "hard"
	hardIntercept     bool   // derived: interceptMode == "hard"

	mainLog       atomic.Pointer[zerolog.Logger]
	consoleWriter zerolog.ConsoleWriter
	noConfigStart bool
)

const (
	cdUidFlagName          = "cd"
	cdOrgFlagName          = "cd-org"
	customHostnameFlagName = "custom-hostname"
	nextdnsFlagName        = "nextdns"
)

func init() {
	l := zerolog.New(io.Discard)
	mainLog.Store(&l)
}

func Main() {
	// Fast path for pf interception probe subprocess. This runs before cobra
	// initialization to minimize startup time. The parent process spawns us with
	// "pf-probe-send <host> <hex-dns-packet>" and a non-_ctrld GID so pf
	// intercepts the DNS query. If pf rdr is working, the query reaches ctrld's
	// listener; if not, it goes to the real DNS server and ctrld detects the miss.
	if len(os.Args) >= 4 && os.Args[1] == "pf-probe-send" {
		pfProbeSend(os.Args[2], os.Args[3])
		return
	}

	ctrld.InitConfig(v, "ctrld")
	initCLI()
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
		ctrld.ProxyLogger.Store(&l)
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case verbose > 1:
		ctrld.ProxyLogger.Store(&l)
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.NoticeLevel)
	}
}

// initInteractiveLogging is like initLogging, but the ProxyLogger is discarded
// to be used for all interactive commands.
//
// Current log file config will also be ignored.
func initInteractiveLogging() {
	old := cfg.Service.LogPath
	cfg.Service.LogPath = ""
	zerolog.TimeFieldFormat = time.RFC3339 + ".000"
	initLoggingWithBackup(false)
	cfg.Service.LogPath = old
	l := zerolog.New(io.Discard)
	ctrld.ProxyLogger.Store(&l)
}

// initLoggingWithBackup initializes log setup base on current config.
// If doBackup is true, backup old log file with ".1" suffix.
//
// This is only used in runCmd for special handling in case of logging config
// change in cd mode. Without special reason, the caller should use initLogging
// wrapper instead of calling this function directly.
func initLoggingWithBackup(doBackup bool) []io.Writer {
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
		return writers
	case verbose == 1:
		logLevel = "info"
	case verbose > 1:
		logLevel = "debug"
	}
	if logLevel == "" {
		return writers
	}
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not set log level")
		return writers
	}
	zerolog.SetGlobalLevel(level)
	return writers
}

func initCache() {
	if !cfg.Service.CacheEnable {
		return
	}
	if cfg.Service.CacheSize == 0 {
		cfg.Service.CacheSize = 4096
	}
}

// pfProbeSend is a minimal subprocess that sends a pre-built DNS query packet
// to the specified host on port 53. It's invoked by probePFIntercept() with a
// non-_ctrld GID so pf interception applies to the query.
//
// Usage: ctrld pf-probe-send <host> <hex-encoded-dns-packet>
func pfProbeSend(host, hexPacket string) {
	packet, err := hex.DecodeString(hexPacket)
	if err != nil {
		os.Exit(1)
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "53"), time.Second)
	if err != nil {
		os.Exit(1)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = conn.Write(packet)
	// Read response (don't care about result, just need the send to happen)
	buf := make([]byte, 512)
	_, _ = conn.Read(buf)
}
