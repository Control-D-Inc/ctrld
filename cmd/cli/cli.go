package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/cuonglm/osinfo"
	"github.com/go-playground/validator/v10"
	"github.com/kardianos/service"
	"github.com/miekg/dns"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

// selfCheckInternalTestDomain is used for testing ctrld self response to clients.
const selfCheckInternalTestDomain = "ctrld" + loopTestDomain
const (
	windowsForwardersFilename = ".forwarders.txt"
	oldBinSuffix              = "_previous"
	oldLogSuffix              = ".1"
	msgExit                   = "$$EXIT$$"
)

var (
	version = "dev"
	commit  = "none"
)

var (
	v                    = viper.NewWithOptions(viper.KeyDelimiter("::"))
	defaultConfigFile    = "ctrld.toml"
	rootCertPool         *x509.CertPool
	errSelfCheckNoAnswer = errors.New("no response from ctrld listener. You can try to re-launch with flag --skip_self_checks")
)

var basicModeFlags = []string{"listen", "primary_upstream", "secondary_upstream", "domains"}

func isNoConfigStart(cmd *cobra.Command) bool {
	for _, flagName := range basicModeFlags {
		if cmd.Flags().Lookup(flagName).Changed {
			return true
		}
	}
	return false
}

const rootShortDesc = `
        __         .__       .___
  _____/  |________|  |    __| _/
_/ ___\   __\_  __ \  |   / __ |
\  \___|  |  |  | \/  |__/ /_/ |
 \___  >__|  |__|  |____/\____ |
     \/ dns forwarding proxy  \/
`

var rootCmd = &cobra.Command{
	Use:     "ctrld",
	Short:   strings.TrimLeft(rootShortDesc, "\n"),
	Version: curVersion(),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initConsoleLogging()
	},
}

func curVersion() string {
	if version != "dev" && !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if version != "" && version != "dev" {
		return version
	}
	if len(commit) > 7 {
		commit = commit[:7]
	}
	return fmt.Sprintf("%s-%s", version, commit)
}

func initCLI() {
	// Enable opening via explorer.exe on Windows.
	// See: https://github.com/spf13/cobra/issues/844.
	cobra.MousetrapHelpText = ""
	cobra.EnableCommandSorting = false

	rootCmd.PersistentFlags().CountVarP(
		&verbose,
		"verbose",
		"v",
		`verbose log output, "-v" basic logging, "-vv" debug logging`,
	)
	rootCmd.PersistentFlags().BoolVarP(
		&silent,
		"silent",
		"s",
		false,
		`do not write any log output`,
	)
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
	rootCmd.CompletionOptions.HiddenDefaultCmd = true

	initRunCmd()
	startCmd := initStartCmd()
	stopCmd := initStopCmd()
	restartCmd := initRestartCmd()
	reloadCmd := initReloadCmd(restartCmd)
	statusCmd := initStatusCmd()
	uninstallCmd := initUninstallCmd()
	interfacesCmd := initInterfacesCmd()
	initServicesCmd(startCmd, stopCmd, restartCmd, reloadCmd, statusCmd, uninstallCmd, interfacesCmd)
	initClientsCmd()
	initUpgradeCmd()
	InitLogCmd()
}

// isMobile reports whether the current OS is a mobile platform.
func isMobile() bool {
	return runtime.GOOS == "android" || runtime.GOOS == "ios"
}

// isAndroid reports whether the current OS is Android.
func isAndroid() bool {
	return runtime.GOOS == "android"
}

// isStableVersion reports whether vs is a stable semantic version.
func isStableVersion(vs string) bool {
	v, err := semver.NewVersion(vs)
	if err != nil {
		return false
	}
	return v.Prerelease() == ""
}

// RunCobraCommand runs ctrld cli.
func RunCobraCommand(cmd *cobra.Command) {
	noConfigStart = isNoConfigStart(cmd)
	checkStrFlagEmpty(cmd, cdUidFlagName)
	checkStrFlagEmpty(cmd, cdOrgFlagName)
	run(nil, make(chan struct{}))
}

// RunMobile runs the ctrld cli on mobile platforms.
func RunMobile(appConfig *AppConfig, appCallback *AppCallback, stopCh chan struct{}) {
	if appConfig == nil {
		panic("appConfig is nil")
	}
	initConsoleLogging()
	noConfigStart = false
	homedir = appConfig.HomeDir
	verbose = appConfig.Verbose
	cdUID = appConfig.CdUID
	cdUpstreamProto = appConfig.UpstreamProto
	logPath = appConfig.LogPath
	run(appCallback, stopCh)
}

// CheckDeactivationPin checks if deactivation pin is valid
func CheckDeactivationPin(pin int64, stopCh chan struct{}) int {
	deactivationPin = pin
	if err := checkDeactivationPin(nil, stopCh); isCheckDeactivationPinErr(err) {
		return deactivationPinInvalidExitCode
	}
	return 0
}

// run runs ctrld cli with given app callback and stop channel.
func run(appCallback *AppCallback, stopCh chan struct{}) {
	if stopCh == nil {
		mainLog.Load().Fatal().Msg("stopCh is nil")
	}
	waitCh := make(chan struct{})
	p := &prog{
		waitCh:           waitCh,
		stopCh:           stopCh,
		pinCodeValidCh:   make(chan struct{}, 1),
		reloadCh:         make(chan struct{}),
		reloadDoneCh:     make(chan struct{}),
		dnsWatcherStopCh: make(chan struct{}),
		apiReloadCh:      make(chan *ctrld.Config),
		apiForceReloadCh: make(chan struct{}),
		cfg:              &cfg,
		appCallback:      appCallback,
	}
	p.logger.Store(mainLog.Load())
	if homedir == "" {
		if dir, err := userHomeDir(); err == nil {
			homedir = dir
		}
	}
	sockDir := homedir
	if d, err := socketDir(); err == nil {
		sockDir = d
	}
	sockPath := filepath.Join(sockDir, ctrldLogUnixSock)
	if addr, err := net.ResolveUnixAddr("unix", sockPath); err == nil {
		if conn, err := net.Dial(addr.Network(), addr.String()); err == nil {
			lc := &logConn{conn: conn}
			consoleWriter = newHumanReadableZapCore(io.MultiWriter(os.Stdout, lc), consoleWriterLevel)
			p.logConn = lc
		} else {
			if !errors.Is(err, os.ErrNotExist) {
				p.Warn().Err(err).Msg("unable to create log ipc connection")
			}
		}
	} else {
		p.Warn().Err(err).Msgf("unable to resolve socket address: %s", sockPath)
	}
	notifyExitToLogServer := func() {
		if p.logConn != nil {
			_, _ = p.logConn.Write([]byte(msgExit))
		}
	}

	if daemon && runtime.GOOS == "windows" {
		p.Fatal().Msg("Cannot run in daemon mode. Please install a Windows service.")
	}

	if !daemon {
		// We need to call s.Run() as soon as possible to response to the OS manager, so it
		// can see ctrld is running and don't mark ctrld as failed service.
		go func() {
			s, err := newService(p, svcConfig)
			if err != nil {
				p.Fatal().Err(err).Msg("failed create new service")
			}
			if err := s.Run(); err != nil {
				p.Error().Err(err).Msg("failed to start service")
			}
		}()
	}
	writeDefaultConfig := !noConfigStart && configBase64 == ""
	tryReadingConfig(writeDefaultConfig)

	if err := readBase64Config(configBase64); err != nil {
		p.Fatal().Err(err).Msg("failed to read base64 config")
	}
	processNoConfigFlags(noConfigStart)

	// After s.Run() was called, if ctrld is going to be terminated for any reason,
	// write msgExit to p.logConn so others (like "ctrld start") won't have to wait for timeout.
	p.mu.Lock()
	if err := v.Unmarshal(&cfg); err != nil {
		notifyExitToLogServer()
		p.Fatal().Msgf("failed to unmarshal config: %v", err)
	}
	p.mu.Unlock()

	processLogAndCacheFlags()

	// Log config do not have thing to validate, so it's safe to init log here,
	// so it's able to log information in processCDFlags.
	p.initLogging(true)

	p.Info().Msgf("starting ctrld %s", curVersion())
	p.Info().Msgf("os: %s", osVersion())

	// Wait for network up.
	if !ctrldnet.Up() {
		notifyExitToLogServer()
		p.Fatal().Msg("network is not up yet")
	}

	cs, err := newControlServer(filepath.Join(sockDir, ControlSocketName()))
	if err != nil {
		p.Warn().Err(err).Msg("could not create control server")
	}
	p.cs = cs

	oldLogPath := cfg.Service.LogPath
	if uid := cdUIDFromProvToken(); uid != "" {
		cdUID = uid
	}
	if cdUID != "" {
		validateCdUpstreamProtocol()
		if rc, err := processCDFlags(&cfg); err != nil {
			if isMobile() {
				appCallback.Exit(err.Error())
				return
			}

			cdLogger := p.logger.Load().With().Str("mode", "cd")
			// Performs self-uninstallation if the ControlD device does not exist.
			var uer *controld.ErrorResponse
			if errors.As(err, &uer) && uer.ErrorField.Code == controld.InvalidConfigCode {
				_ = uninstallInvalidCdUID(p, cdLogger, false)
			}
			notifyExitToLogServer()
			cdLogger.Fatal().Err(err).Msg("failed to fetch resolver config")
		} else {
			p.mu.Lock()
			p.rc = rc
			p.mu.Unlock()
		}
	}

	updated := updateListenerConfig(&cfg, notifyExitToLogServer)

	if cdUID != "" {
		processLogAndCacheFlags()
	}

	if updated {
		if err := writeConfigFile(&cfg); err != nil {
			notifyExitToLogServer()
			p.Fatal().Err(err).Msg("failed to write config file")
		} else {
			p.Info().Msg("writing config file to: " + defaultConfigFile)
		}
	}

	if newLogPath := cfg.Service.LogPath; newLogPath != "" && oldLogPath != newLogPath {
		// After processCDFlags, log config may change, so reset mainLog and re-init logging.
		l := zap.NewNop()
		mainLog.Store(&ctrld.Logger{Logger: l})

		// Copy logs written so far to new log file if possible.
		if buf, err := os.ReadFile(oldLogPath); err == nil {
			if err := os.WriteFile(newLogPath, buf, os.FileMode(0o600)); err != nil {
				p.Warn().Err(err).Msg("could not copy old log file")
			}
		}
		initLoggingWithBackup(false)
		p.logger.Store(mainLog.Load())
	}

	if err := validateConfig(&cfg); err != nil {
		notifyExitToLogServer()
		os.Exit(1)
	}
	initCache()

	if daemon {
		exe, err := os.Executable()
		if err != nil {
			p.Error().Err(err).Msg("failed to find the binary")
			notifyExitToLogServer()
			os.Exit(1)
		}
		curDir, err := os.Getwd()
		if err != nil {
			p.Error().Err(err).Msg("failed to get current working directory")
			notifyExitToLogServer()
			os.Exit(1)
		}
		// If running as daemon, re-run the command in background, with daemon off.
		cmd := exec.Command(exe, append(os.Args[1:], "-d=false")...)
		cmd.Dir = curDir
		if err := cmd.Start(); err != nil {
			p.Error().Err(err).Msg("failed to start process as daemon")
			notifyExitToLogServer()
			os.Exit(1)
		}
		p.Info().Int("pid", cmd.Process.Pid).Msg("DNS proxy started")
		os.Exit(0)
	}

	p.onStarted = append(p.onStarted, func() {
		for _, lc := range p.cfg.Listener {
			if shouldAllocateLoopbackIP(lc.IP) {
				if err := allocateIP(lc.IP); err != nil {
					p.Error().Err(err).Msgf("could not allocate IP: %s", lc.IP)
				}
			}
		}
		// Configure Windows service failure actions
		_ = ConfigureWindowsServiceFailureActions(ctrldServiceName)
	})
	p.onStopped = append(p.onStopped, func() {
		for _, lc := range p.cfg.Listener {
			if shouldAllocateLoopbackIP(lc.IP) {
				if err := deAllocateIP(lc.IP); err != nil {
					p.Error().Err(err).Msgf("could not de-allocate IP: %s", lc.IP)
				}
			}
		}
	})
	p.onStopped = append(p.onStopped, func() {
		// restore static DNS settings or DHCP
		p.resetDNS(false, true)
		// Iterate over all physical interfaces and restore static DNS if a saved static config exists.
		withEachPhysicalInterfaces("", "restore static DNS", func(i *net.Interface) error {
			file := ctrld.SavedStaticDnsSettingsFilePath(i)
			if _, err := os.Stat(file); err == nil {
				if err := restoreDNS(i); err != nil {
					p.Error().Err(err).Msgf("Could not restore static DNS on interface %s", i.Name)
				} else {
					p.Debug().Msgf("Restored static DNS on interface %s successfully", i.Name)
				}
			}
			return nil
		})
	})

	close(waitCh)
	<-stopCh
}

func writeConfigFile(cfg *ctrld.Config) error {
	if cfu := v.ConfigFileUsed(); cfu != "" {
		defaultConfigFile = cfu
	} else if configPath != "" {
		defaultConfigFile = configPath
	}
	f, err := os.OpenFile(defaultConfigFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0o644))
	if err != nil {
		return err
	}
	defer f.Close()
	if cdUID != "" {
		if _, err := f.WriteString("# AUTO-GENERATED VIA CD FLAG - DO NOT MODIFY\n\n"); err != nil {
			return err
		}
	}
	enc := toml.NewEncoder(f).SetIndentTables(true)
	if err := enc.Encode(&cfg); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

// readConfigFile reads in config file.
//
// - It writes default config file if config file not found if writeDefaultConfig is true.
// - It emits notice message to user if notice is true.
func readConfigFile(writeDefaultConfig, notice bool) bool {
	// If err == nil, there's a config supplied via `--config`, no default config written.
	err := v.ReadInConfig()
	if err == nil {
		if notice {
			mainLog.Load().Notice().Msg("Reading config: " + v.ConfigFileUsed())
		}
		mainLog.Load().Info().Msg("loading config file from: " + v.ConfigFileUsed())
		defaultConfigFile = v.ConfigFileUsed()
		return true
	}

	if !writeDefaultConfig {
		return false
	}

	// If error is viper.ConfigFileNotFoundError, write default config.
	if errors.As(err, &viper.ConfigFileNotFoundError{}) {
		if err := v.Unmarshal(&cfg); err != nil {
			mainLog.Load().Fatal().Msgf("failed to unmarshal default config: %v", err)
		}
		_, _ = tryUpdateListenerConfig(&cfg, func() {}, true)
		addExtraSplitDnsRule(&cfg)
		if err := writeConfigFile(&cfg); err != nil {
			mainLog.Load().Fatal().Msgf("failed to write default config file: %v", err)
		} else {
			fp, err := filepath.Abs(defaultConfigFile)
			if err != nil {
				mainLog.Load().Fatal().Msgf("failed to get default config file path: %v", err)
			}
			if cdUID == "" && nextdns == "" {
				mainLog.Load().Notice().Msg("Generating controld default config: " + fp)
			}
			mainLog.Load().Info().Msg("writing default config file to: " + fp)
		}
		return false
	}

	// If error is viper.ConfigParseError, emit details line and column number.
	if errors.As(err, &viper.ConfigParseError{}) {
		if de := decoderErrorFromTomlFile(v.ConfigFileUsed()); de != nil {
			row, col := de.Position()
			mainLog.Load().Fatal().Msgf("failed to decode config file at line: %d, column: %d, error: %v", row, col, err)
		}
	}

	// Otherwise, report fatal error and exit.
	mainLog.Load().Fatal().Msgf("failed to decode config file: %v", err)
	return false
}

// decoderErrorFromTomlFile parses the invalid toml file, returning the details decoder error.
func decoderErrorFromTomlFile(cf string) *toml.DecodeError {
	if f, _ := os.Open(cf); f != nil {
		defer f.Close()
		var i any
		var de *toml.DecodeError
		if err := toml.NewDecoder(f).Decode(&i); err != nil && errors.As(err, &de) {
			return de
		}
	}
	return nil
}

// readBase64Config reads ctrld config from the base64 input string.
func readBase64Config(configBase64 string) error {
	if configBase64 == "" {
		return nil
	}
	configStr, err := base64.StdEncoding.DecodeString(configBase64)
	if err != nil {
		return fmt.Errorf("invalid base64 config: %w", err)
	}

	// readBase64Config is called when:
	//
	//  - "--base64_config" flag set.
	//  - Reading custom config when "--cd" flag set.
	//
	// So we need to re-create viper instance to discard old one.
	v = viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigType("toml")
	return v.ReadConfig(bytes.NewReader(configStr))
}

func processNoConfigFlags(noConfigStart bool) {
	if !noConfigStart {
		return
	}
	if listenAddress == "" || primaryUpstream == "" {
		mainLog.Load().Fatal().Msg(`"listen" and "primary_upstream" flags must be set in no config mode`)
	}
	processListenFlag()

	endpointAndTyp := func(endpoint string) (string, string) {
		typ := ctrld.ResolverTypeFromEndpoint(endpoint)
		endpoint = strings.TrimPrefix(endpoint, "quic://")
		if after, found := strings.CutPrefix(endpoint, "h3://"); found {
			endpoint = "https://" + after
		}
		return endpoint, typ
	}
	pEndpoint, pType := endpointAndTyp(primaryUpstream)
	puc := &ctrld.UpstreamConfig{
		Name:     pEndpoint,
		Endpoint: pEndpoint,
		Type:     pType,
		Timeout:  5000,
	}
	loggerCtx := ctrld.LoggerCtx(context.Background(), mainLog.Load())
	puc.Init(loggerCtx)
	upstream := map[string]*ctrld.UpstreamConfig{"0": puc}
	if secondaryUpstream != "" {
		sEndpoint, sType := endpointAndTyp(secondaryUpstream)
		suc := &ctrld.UpstreamConfig{
			Name:     sEndpoint,
			Endpoint: sEndpoint,
			Type:     sType,
			Timeout:  5000,
		}
		suc.Init(loggerCtx)
		upstream["1"] = suc
		rules := make([]ctrld.Rule, 0, len(domains))
		for _, domain := range domains {
			rules = append(rules, ctrld.Rule{domain: []string{"upstream.1"}})
		}
		lc := v.Get("listener").(map[string]*ctrld.ListenerConfig)["0"]
		lc.Policy = &ctrld.ListenerPolicyConfig{Name: "My Policy", Rules: rules}
	}
	v.Set("upstream", upstream)
}

// defaultDeactivationPin is the default value for cdDeactivationPin.
// If cdDeactivationPin equals to this default, it means the pin code is not set from Control D API.
const defaultDeactivationPin = -1

// cdDeactivationPin is used in cd mode to decide whether stop and uninstall commands can be run.
var cdDeactivationPin atomic.Int64

func init() {
	cdDeactivationPin.Store(defaultDeactivationPin)
}

// deactivationPinSet indicates if cdDeactivationPin is non-default..
func deactivationPinSet() bool {
	return cdDeactivationPin.Load() != defaultDeactivationPin
}

func processCDFlags(cfg *ctrld.Config) (*controld.ResolverConfig, error) {
	logger := mainLog.Load().With().Str("mode", "cd")
	logger.Info().Msgf("fetching Controld D configuration from API: %s", cdUID)
	bo := backoff.NewBackoff("processCDFlags", logf, 30*time.Second)
	bo.LogLongerThan = 30 * time.Second
	ctx := ctrld.LoggerCtx(context.Background(), logger)
	resolverConfig, err := controld.FetchResolverConfig(ctx, cdUID, rootCmd.Version, cdDev)
	for {
		if errUrlNetworkError(err) {
			bo.BackOff(ctx, err)
			logger.Warn().Msg("could not fetch resolver using bootstrap DNS, retrying...")
			resolverConfig, err = controld.FetchResolverConfig(ctx, cdUID, rootCmd.Version, cdDev)
			continue
		}
		break
	}
	if err != nil {
		if isMobile() {
			return nil, err
		}
		logger.Warn().Err(err).Msg("could not fetch resolver config")
		return nil, err
	}

	if resolverConfig.DeactivationPin != nil {
		logger.Debug().Msg("saving deactivation pin")
		cdDeactivationPin.Store(*resolverConfig.DeactivationPin)
	}

	logger.Info().Msg("generating ctrld config from Control-D configuration")

	*cfg = ctrld.Config{}
	// Fetch config, unmarshal to cfg.
	if resolverConfig.Ctrld.CustomConfig != "" {
		logger.Info().Msg("using defined custom config of Control-D resolver")
		var cfgErr error
		if cfgErr = validateCdRemoteConfig(resolverConfig, cfg); cfgErr == nil {
			setListenerDefaultValue(cfg)
			setNetworkDefaultValue(cfg)
			if cfgErr = validateConfig(cfg); cfgErr == nil {
				return resolverConfig, nil
			}
		}
		mainLog.Load().Warn().Err(err).Msg("disregarding invalid custom config")
	}

	bootstrapIP := func(endpoint string) string {
		u, err := url.Parse(endpoint)
		if err != nil {
			logger.Warn().Err(err).Msgf("no bootstrap IP for invalid endpoint: %s", endpoint)
			return ""
		}
		switch {
		case dns.IsSubDomain(ctrld.FreeDnsDomain, u.Host):
			return ctrld.FreeDNSBoostrapIP
		case dns.IsSubDomain(ctrld.PremiumDnsDomain, u.Host):
			return ctrld.PremiumDNSBoostrapIP
		}
		return ""
	}

	cfg.Upstream = make(map[string]*ctrld.UpstreamConfig)
	cfg.Upstream["0"] = &ctrld.UpstreamConfig{
		BootstrapIP: bootstrapIP(resolverConfig.DOH),
		Endpoint:    resolverConfig.DOH,
		Type:        cdUpstreamProto,
		Timeout:     5000,
	}
	rules := make([]ctrld.Rule, 0, len(resolverConfig.Exclude))
	for _, domain := range resolverConfig.Exclude {
		rules = append(rules, ctrld.Rule{domain: []string{}})
	}
	cfg.Listener = make(map[string]*ctrld.ListenerConfig)
	lc := &ctrld.ListenerConfig{
		Policy: &ctrld.ListenerPolicyConfig{
			Name:  "My Policy",
			Rules: rules,
		},
	}
	cfg.Listener["0"] = lc

	// Set default value.
	setListenerDefaultValue(cfg)
	setNetworkDefaultValue(cfg)

	return resolverConfig, nil
}

// setListenerDefaultValue sets the default value for cfg.Listener if none existed.
func setListenerDefaultValue(cfg *ctrld.Config) {
	if len(cfg.Listener) == 0 {
		cfg.Listener = map[string]*ctrld.ListenerConfig{
			"0": {IP: "", Port: 0},
		}
	}
}

// setListenerDefaultValue sets the default value for cfg.Listener if none existed.
func setNetworkDefaultValue(cfg *ctrld.Config) {
	if len(cfg.Network) == 0 {
		cfg.Network = map[string]*ctrld.NetworkConfig{
			"0": {
				Name:  "Network 0",
				Cidrs: []string{"0.0.0.0/0"},
			},
		}
	}
}

// validateCdRemoteConfig validates the custom config from ControlD if defined.
// This only validate the config syntax. To validate the config rules, calling
// validateConfig with the cfg after calling this function.
func validateCdRemoteConfig(rc *controld.ResolverConfig, cfg *ctrld.Config) error {
	if rc.Ctrld.CustomConfig == "" {
		return nil
	}
	if err := readBase64Config(rc.Ctrld.CustomConfig); err != nil {
		return err
	}
	return v.Unmarshal(&cfg)
}

func processListenFlag() {
	if listenAddress == "" {
		return
	}
	host, portStr, err := net.SplitHostPort(listenAddress)
	if err != nil {
		mainLog.Load().Fatal().Msgf("invalid listener address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		mainLog.Load().Fatal().Msgf("invalid port number: %v", err)
	}
	lc := &ctrld.ListenerConfig{
		IP:   host,
		Port: port,
	}
	v.Set("listener", map[string]*ctrld.ListenerConfig{
		"0": lc,
	})
}

func processLogAndCacheFlags() {
	if logPath != "" {
		cfg.Service.LogPath = logPath
	}
	if logPath != "" && cfg.Service.LogLevel == "" {
		cfg.Service.LogLevel = "debug"
	}

	if cacheSize != 0 {
		cfg.Service.CacheEnable = true
		cfg.Service.CacheSize = cacheSize
	}
	v.Set("service", cfg.Service)
}

func netInterface(ifaceName string) (*net.Interface, error) {
	if ifaceName == "auto" {
		ifaceName = defaultIfaceName()
	}
	var iface *net.Interface
	err := netmon.ForeachInterface(func(i netmon.Interface, prefixes []netip.Prefix) {
		if i.Name == ifaceName {
			iface = i.Interface
		}
	})
	if iface == nil {
		return nil, errors.New("interface not found")
	}
	if _, err := patchNetIfaceName(iface); err != nil {
		return nil, err
	}
	return iface, err
}

func defaultIfaceName() string {
	dri, err := netmon.DefaultRouteInterface()
	if err != nil {
		// On WSL 1, the route table does not have any default route. But the fact that
		// it only uses /etc/resolv.conf for setup DNS, so we can use "lo" here.
		if oi := osinfo.New(); strings.Contains(oi.String(), "Microsoft") {
			return "lo"
		}
		// On linux, it could be either resolvconf or systemd which is managing DNS settings,
		// so the interface name does not matter if there's no default route interface.
		if runtime.GOOS == "linux" {
			return "lo"
		}
		mainLog.Load().Debug().Err(err).Msg("no default route interface found")
		return ""
	}
	return dri
}

// selfCheckStatus performs the end-to-end DNS test by sending query to ctrld listener.
// It returns a boolean to indicate whether the check is succeeded, the actual status
// of ctrld service, and an additional error if any.
//
// We perform two tests:
//
// - Internal testing, ensuring query could be sent from client -> ctrld.
// - External testing, ensuring query could be sent from ctrld -> upstream.
//
// Self-check is considered success only if both tests are ok.
func selfCheckStatus(ctx context.Context, s service.Service, sockDir string) (bool, service.Status, error) {
	status, err := s.Status()
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not get service status")
		return false, service.StatusUnknown, err
	}
	// If ctrld is not running, do nothing, just return the status as-is.
	if status != service.StatusRunning {
		return false, status, nil
	}
	// Skip self checks if set.
	if skipSelfChecks {
		return true, status, nil
	}

	mainLog.Load().Debug().Msg("waiting for ctrld listener to be ready")
	cc := newSocketControlClient(ctx, s, sockDir)
	if cc == nil {
		return false, status, errors.New("could not connect to control server")
	}

	v = viper.NewWithOptions(viper.KeyDelimiter("::"))
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigFile(defaultConfigFile)
	}
	if err := v.ReadInConfig(); err != nil {
		mainLog.Load().Error().Err(err).Msgf("failed to re-read configuration file: %s", v.ConfigFileUsed())
		return false, status, err
	}

	cfg = ctrld.Config{}
	if err := v.Unmarshal(&cfg); err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to update new config")
		return false, status, err
	}

	selfCheckExternalDomain := cfg.FirstUpstream().VerifyDomain()
	if selfCheckExternalDomain == "" {
		// Nothing to do, return the status as-is.
		return true, status, nil
	}

	mainLog.Load().Debug().Msg("ctrld listener is ready")

	lc := cfg.FirstListener()
	addr := net.JoinHostPort(lc.IP, strconv.Itoa(lc.Port))

	mainLog.Load().Debug().Msgf("performing listener test, sending queries to %s", addr)

	if err := selfCheckResolveDomain(context.TODO(), addr, "internal", selfCheckInternalTestDomain); err != nil {
		return false, status, err
	}
	if err := selfCheckResolveDomain(context.TODO(), addr, "external", selfCheckExternalDomain); err != nil {
		return false, status, err
	}
	return true, status, nil
}

// selfCheckResolveDomain performs DNS test query against ctrld listener.
func selfCheckResolveDomain(ctx context.Context, addr, scope string, domain string) error {
	bo := backoff.NewBackoff("self-check", logf, 10*time.Second)
	bo.LogLongerThan = 500 * time.Millisecond
	maxAttempts := 10
	c := new(dns.Client)

	var (
		lastAnswer *dns.Msg
		lastErr    error
	)

	oi := osinfo.New()
	for i := 0; i < maxAttempts; i++ {
		if domain == "" {
			return errors.New("empty test domain")
		}
		m := new(dns.Msg)
		m.SetQuestion(domain+".", dns.TypeA)
		m.RecursionDesired = true
		r, _, exErr := exchangeContextWithTimeout(c, 5*time.Second, m, addr)
		if r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
			mainLog.Load().Debug().Msgf("%s self-check against %q succeeded", scope, domain)
			return nil
		}
		// Return early if this is a connection refused.
		if errConnectionRefused(exErr) {
			return exErr
		}
		// Return early if this is MacOS 15.0 and error is timeout error.
		var e net.Error
		if oi.Name == "darwin" && oi.Version == "15.0" && errors.As(exErr, &e) && e.Timeout() {
			mainLog.Load().Warn().Msg("MacOS 15.0 Sequoia has a bug with the firewall which may prevent ctrld from starting. Disable the MacOS firewall and try again")
			return exErr
		}
		lastAnswer = r
		lastErr = exErr
		bo.BackOff(ctx, fmt.Errorf("ExchangeContext: %w", exErr))
	}
	mainLog.Load().Debug().Msgf("self-check against %q failed", domain)
	loggerCtx := ctrld.LoggerCtx(ctx, mainLog.Load())
	// Ping all upstreams to provide better error message to users.
	for name, uc := range cfg.Upstream {
		if err := uc.ErrorPing(loggerCtx); err != nil {
			mainLog.Load().Err(err).Msgf("failed to connect to upstream.%s, endpoint: %s", name, uc.Endpoint)
		}
	}
	marker := strings.Repeat("=", 32)
	mainLog.Load().Debug().Msg(marker)
	mainLog.Load().Debug().Msgf("listener address       : %s", addr)
	mainLog.Load().Debug().Msgf("last error             : %v", lastErr)
	if lastAnswer != nil {
		mainLog.Load().Debug().Msgf("last answer from ctrld :")
		mainLog.Load().Debug().Msg(marker)
		for _, s := range strings.Split(lastAnswer.String(), "\n") {
			mainLog.Load().Debug().Msgf("%s", s)
		}
	}
	return errSelfCheckNoAnswer
}

func userHomeDir() (string, error) {
	// Mobile platform should provide a rw dir path for this.
	if isMobile() {
		return homedir, nil
	}
	return ctrld.UserHomeDir()
}

// socketDir returns directory that ctrld will create socket file for running controlServer.
func socketDir() (string, error) {
	switch {
	case runtime.GOOS == "windows", isMobile():
		return userHomeDir()
	}
	dir := "/var/run"
	if ok, _ := dirWritable(dir); !ok {
		return userHomeDir()
	}
	return dir, nil
}

// tryReadingConfig is like tryReadingConfigWithNotice, with notice set to false.
func tryReadingConfig(writeDefaultConfig bool) {
	tryReadingConfigWithNotice(writeDefaultConfig, false)
}

// tryReadingConfigWithNotice tries reading in config files, either specified by user or from default
// locations. If notice is true, emitting a notice message to user which config file was read.
func tryReadingConfigWithNotice(writeDefaultConfig, notice bool) {
	// --config is specified.
	if configPath != "" {
		v.SetConfigFile(configPath)
		readConfigFile(false, notice)
		return
	}
	// no config start or base64 config mode.
	if !writeDefaultConfig {
		return
	}
	readConfigWithNotice(writeDefaultConfig, notice)
}

// readConfig calls readConfigWithNotice with notice set to false.
func readConfig(writeDefaultConfig bool) {
	readConfigWithNotice(writeDefaultConfig, false)
}

// readConfigWithNotice calls readConfigFile with config file set to ctrld.toml
// or config.toml for compatible with earlier versions of ctrld.
func readConfigWithNotice(writeDefaultConfig, notice bool) {
	configs := []struct {
		name    string
		written bool
	}{
		// For compatibility, we check for config.toml first, but only read it if exists.
		{"config", false},
		{"ctrld", writeDefaultConfig},
	}

	dir, err := userHomeDir()
	if err != nil {
		mainLog.Load().Fatal().Msgf("failed to get user home dir: %v", err)
	}
	for _, config := range configs {
		ctrld.SetConfigNameWithPath(v, config.name, dir)
		v.SetConfigFile(configPath)
		if readConfigFile(config.written, notice) {
			break
		}
	}
}

func uninstall(p *prog, s service.Service) {
	if _, err := s.Status(); err != nil && errors.Is(err, service.ErrNotInstalled) {
		mainLog.Load().Error().Msg(err.Error())
		return
	}
	tasks := []task{
		{s.Stop, false, "Stop"},
		{s.Uninstall, true, "Uninstall"},
	}
	initInteractiveLogging()
	if doTasks(tasks) {
		// restore static DNS settings or DHCP
		p.resetDNS(false, true)

		// Iterate over all physical interfaces and restore DNS if a saved static config exists.
		withEachPhysicalInterfaces(p.runningIface, "restore static DNS", func(i *net.Interface) error {
			file := ctrld.SavedStaticDnsSettingsFilePath(i)
			if _, err := os.Stat(file); err == nil {
				if err := restoreDNS(i); err != nil {
					mainLog.Load().Error().Err(err).Msgf("Could not restore static DNS on interface %s", i.Name)
				} else {
					mainLog.Load().Debug().Msgf("Restored static DNS on interface %s successfully", i.Name)
					err = os.Remove(file)
					if err != nil {
						mainLog.Load().Debug().Err(err).Msgf("Could not remove saved static DNS file for interface %s", i.Name)
					}
				}
			}
			return nil
		})

		mainLog.Load().Notice().Msg("Service uninstalled")
		return
	}
}

func validateConfig(cfg *ctrld.Config) error {
	if err := ctrld.ValidateConfig(validator.New(), cfg); err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			for _, fe := range ve {
				mainLog.Load().Error().Msgf("invalid config: %s: %s", fe.Namespace(), fieldErrorMsg(fe))
			}
		}
		return err
	}
	return nil
}

// NOTE: Add more case here once new validation tag is used in ctrld.Config struct.
func fieldErrorMsg(fe validator.FieldError) string {
	switch fe.Tag() {
	case "oneof":
		return fmt.Sprintf("must be one of: %q", fe.Param())
	case "min":
		if fe.Kind() == reflect.Map || fe.Kind() == reflect.Slice {
			return fmt.Sprintf("must define at least %s element", fe.Param())
		}
		return fmt.Sprintf("minimum value: %q", fe.Param())
	case "max":
		if fe.Kind() == reflect.Map || fe.Kind() == reflect.Slice {
			return fmt.Sprintf("exceeded maximum number of elements: %s", fe.Param())
		}
		return fmt.Sprintf("maximum value: %q", fe.Param())
	case "len":
		if fe.Kind() == reflect.Slice {
			return fmt.Sprintf("must have at least %s element", fe.Param())
		}
		return fmt.Sprintf("minimum len: %q", fe.Param())
	case "gte":
		return fmt.Sprintf("must be greater than or equal to: %s", fe.Param())
	case "cidr":
		return fmt.Sprintf("invalid value: %s", fe.Value())
	case "required_unless", "required":
		return "value is required"
	case "dnsrcode":
		return fmt.Sprintf("invalid DNS rcode value: %s", fe.Value())
	case "ipstack":
		ipStacks := []string{ctrld.IpStackV4, ctrld.IpStackV6, ctrld.IpStackSplit, ctrld.IpStackBoth}
		return fmt.Sprintf("must be one of: %q", strings.Join(ipStacks, " "))
	case "iporempty":
		return fmt.Sprintf("invalid IP format: %s", fe.Value())
	case "file":
		return fmt.Sprintf("filed does not exist: %s", fe.Value())
	case "http_url":
		return fmt.Sprintf("invalid http/https url: %s", fe.Value())
	}
	return ""
}

func isLoopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func shouldAllocateLoopbackIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	return ip.IsLoopback() && ip.String() != "127.0.0.1"
}

type listenerConfigCheck struct {
	IP   bool
	Port bool
}

// mobileListenerPort returns hardcoded port for mobile platforms.
func mobileListenerPort() int {
	if isAndroid() {
		return 5354
	}
	return 53
}

// mobileListenerIp returns hardcoded listener ip for mobile platforms
func mobileListenerIp() string {
	if isAndroid() {
		return "0.0.0.0"
	}
	return "127.0.0.1"
}

// updateListenerConfig updates the config for listeners if not defined,
// or defined but invalid to be used, e.g: using loopback address other
// than 127.0.0.1 with systemd-resolved.
func updateListenerConfig(cfg *ctrld.Config, notifyToLogServerFunc func()) bool {
	updated, _ := tryUpdateListenerConfig(cfg, notifyToLogServerFunc, true)
	if addExtraSplitDnsRule(cfg) {
		updated = true
	}
	return updated
}

// tryUpdateListenerConfig tries updating listener config with a working one.
// If fatal is true, and there's listen address conflicted, the function do
// fatal error.
func tryUpdateListenerConfig(cfg *ctrld.Config, notifyFunc func(), fatal bool) (updated, ok bool) {
	ok = true
	lcc := make(map[string]*listenerConfigCheck)
	cdMode := cdUID != ""
	nextdnsMode := nextdns != ""
	isDesktop := ctrld.IsDesktopPlatform()
	for n, listener := range cfg.Listener {
		lcc[n] = &listenerConfigCheck{}
		if listener.IP == "" {
			listener.IP = "0.0.0.0"
			// For desktop clients, also stick the listener to the local IP only.
			// Listening on 0.0.0.0 would expose it to the entire local network, potentially
			// creating security vulnerabilities (such as DNS amplification or abusing).
			if isDesktop {
				listener.IP = "127.0.0.1"
			}
			lcc[n].IP = true
		}
		if listener.Port == 0 {
			listener.Port = 53
			lcc[n].Port = true
		}
		// In cd mode, we always try to pick an ip:port pair to work.
		// Same if nextdns resolver is used.
		if cdMode || nextdnsMode {
			lcc[n].IP = true
			lcc[n].Port = true
		}
		updated = updated || lcc[n].IP || lcc[n].Port
	}

	il := mainLog.Load()
	if isMobile() {
		// On Mobile, only use first listener, ignore others.
		firstLn := cfg.FirstListener()
		for k := range cfg.Listener {
			if cfg.Listener[k] != firstLn {
				delete(cfg.Listener, k)
			}
		}
		if cdMode {
			firstLn.IP = mobileListenerIp()
			firstLn.Port = mobileListenerPort()
			clear(lcc)
			updated = true
		}
	}
	var closers []io.Closer
	defer func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}()
	// tryListen attempts to listen on given udp and tcp address.
	// Created listeners will be kept in listeners slice above, and close
	// before function finished.
	tryListen := func(addr string) error {
		udpLn, udpErr := net.ListenPacket("udp", addr)
		if udpLn != nil {
			closers = append(closers, udpLn)
		}
		tcpLn, tcpErr := net.Listen("tcp", addr)
		if tcpLn != nil {
			closers = append(closers, tcpLn)
		}
		return errors.Join(udpErr, tcpErr)
	}

	logMsg := func(e *ctrld.LogEvent, listenerNum int, format string, v ...any) {
		e.MsgFunc(func() string {
			return fmt.Sprintf("listener.%d %s", listenerNum, fmt.Sprintf(format, v...))
		})
	}

	listeners := make([]int, 0, len(cfg.Listener))
	for k := range cfg.Listener {
		n, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		listeners = append(listeners, n)
	}
	sort.Ints(listeners)

	for _, n := range listeners {
		listener := cfg.Listener[strconv.Itoa(n)]
		check := lcc[strconv.Itoa(n)]
		oldIP := listener.IP
		oldPort := listener.Port
		isZeroIP := listener.IP == "0.0.0.0" || listener.IP == "::"

		// Check if we could listen on the current IP + Port, if not, try following thing, pick first one success:
		//    - Try 127.0.0.1:53
		//    - Pick a random port until success.
		localhostIP := func(ipStr string) string {
			if ip := net.ParseIP(ipStr); ip != nil && ip.To4() == nil {
				return "::1"
			}
			return "127.0.0.1"
		}

		// On firewalla, we don't need to check localhost, because the lo interface is excluded in dnsmasq
		// config, so we can always listen on localhost port 53, but no traffic could be routed there.
		tryLocalhost := !isLoopback(listener.IP)
		tryAllPort53 := true
		if isZeroIP && listener.Port == 53 {
			tryAllPort53 = false
		}

		attempts := 0
		maxAttempts := 10
		for {
			if attempts == maxAttempts {
				notifyFunc()
				logMsg(mainLog.Load().Fatal(), n, "could not find available listen ip and port")
			}
			addr := net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port))
			err := tryListen(addr)
			if err == nil {
				break
			}

			logMsg(il.Info().Err(err), n, "error listening on address: %s", addr)

			if !check.IP && !check.Port {
				if fatal {
					notifyFunc()
					logMsg(mainLog.Load().Fatal(), n, "failed to listen: %v", err)
				}
				ok = false
				break
			}
			if tryAllPort53 {
				tryAllPort53 = false
				if check.IP {
					listener.IP = "0.0.0.0"
				}
				if check.Port {
					listener.Port = 53
				}
				if check.IP {
					logMsg(il.Info(), n, "could not listen on address: %s, trying: %s", addr, net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port)))
				}
				continue
			}
			if tryLocalhost {
				tryLocalhost = false
				if check.IP {
					listener.IP = localhostIP(listener.IP)
				}
				if check.Port {
					listener.Port = 53
				}
				if check.IP {
					logMsg(il.Info(), n, "could not listen on address: %s, trying localhost: %s", addr, net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port)))
				}
				continue
			}
			if check.IP && !isZeroIP { // for "0.0.0.0" or "::", we only need to try new port.
				listener.IP = randomLocalIP()
			} else {
				listener.IP = oldIP
			}
			if check.Port {
				listener.Port = randomPort()
			} else {
				listener.Port = oldPort
			}
			if listener.IP == oldIP && listener.Port == oldPort {
				if fatal {
					notifyFunc()
					logMsg(mainLog.Load().Fatal(), n, "could not listen on %s: %v", net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port)), err)
				}
				ok = false
				break
			}
			logMsg(il.Info(), n, "could not listen on address: %s, pick a random ip+port", addr)
			attempts++
		}
	}
	if !ok {
		return
	}

	// Specific case for systemd-resolved.
	if useSystemdResolved {
		if listener := cfg.FirstListener(); listener != nil && listener.Port == 53 {
			n := listeners[0]
			// systemd-resolved does not allow forwarding DNS queries from 127.0.0.53 to loopback
			// ip address, other than "127.0.0.1", so trying to listen on default route interface
			// address instead.
			if ip := net.ParseIP(listener.IP); ip != nil && ip.IsLoopback() && ip.String() != "127.0.0.1" {
				logMsg(il.Info(), n, "using loopback interface do not work with systemd-resolved")
				found := false
				if netIface, _ := net.InterfaceByName(defaultIfaceName()); netIface != nil {
					addrs, _ := netIface.Addrs()
					for _, addr := range addrs {
						if netIP, ok := addr.(*net.IPNet); ok && netIP.IP.To4() != nil {
							addr := net.JoinHostPort(netIP.IP.String(), strconv.Itoa(listener.Port))
							if err := tryListen(addr); err == nil {
								found = true
								listener.IP = netIP.IP.String()
								logMsg(il.Info(), n, "use %s as listener address", listener.IP)
								break
							}
						}
					}
				}
				if !found {
					notifyFunc()
					logMsg(mainLog.Load().Fatal(), n, "could not use %q as DNS nameserver with systemd resolved", listener.IP)
				}
			}
		}
	}
	return
}

func dirWritable(dir string) (bool, error) {
	f, err := os.CreateTemp(dir, "")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	return true, f.Close()
}

func osVersion() string {
	oi := osinfo.New()
	if runtime.GOOS == "freebsd" {
		if ver, _, found := strings.Cut(oi.String(), ":"); found {
			return ver
		}
	}
	return oi.String()
}

// cdUIDFromProvToken fetch UID from ControlD API using provision token.
func cdUIDFromProvToken() string {
	// --cd flag supersedes --cd-org, ignore it if both are supplied.
	if cdUID != "" {
		return ""
	}
	// --cd-org is empty, nothing to do.
	if cdOrg == "" {
		return ""
	}
	// Validate custom hostname if provided.
	if customHostname != "" && !validHostname(customHostname) {
		mainLog.Load().Fatal().Msgf("invalid custom hostname: %q", customHostname)
	}
	req := &controld.UtilityOrgRequest{ProvToken: cdOrg, Hostname: customHostname}
	// Process provision token if provided.
	loggerCtx := ctrld.LoggerCtx(context.Background(), mainLog.Load())
	resolverConfig, err := controld.FetchResolverUID(loggerCtx, req, rootCmd.Version, cdDev)
	if err != nil {
		mainLog.Load().Fatal().Err(err).Msgf("failed to fetch resolver uid with provision token: %s", cdOrg)
	}
	return resolverConfig.UID
}

// removeOrgFlagsFromArgs removes organization flags from command line arguments.
// The flags are:
//
// - "--cd-org"
// - "--custom-hostname"
//
// This is necessary because "ctrld run" only need a valid UID, which could be fetched
// using "--cd-org". So if "ctrld start" have already been called with "--cd-org", we
// already have a valid UID to pass to "ctrld run", so we don't have to force "ctrld run"
// to re-do the already done job.
func removeOrgFlagsFromArgs(sc *service.Config) {
	a := sc.Arguments[:0]
	skip := false
	for _, x := range sc.Arguments {
		if skip {
			skip = false
			continue
		}
		// For "--cd-org XXX"/"--custom-hostname XXX", skip them and mark next arg skipped.
		if x == "--"+cdOrgFlagName || x == "--"+customHostnameFlagName {
			skip = true
			continue
		}
		// For "--cd-org=XXX"/"--custom-hostname=XXX", just skip them.
		if strings.HasPrefix(x, "--"+cdOrgFlagName+"=") ||
			strings.HasPrefix(x, "--"+customHostnameFlagName+"=") {
			continue
		}
		a = append(a, x)
	}
	sc.Arguments = a
}

// newSocketControlClient returns new control client after control server was started.
func newSocketControlClient(ctx context.Context, s service.Service, dir string) *controlClient {
	return newSocketControlClientWithTimeout(ctx, s, dir, dialSocketControlServerTimeout)
}

// newSocketControlClientWithTimeout returns new control client after control server was started.
// The timeoutDuration controls how long to wait for the server.
func newSocketControlClientWithTimeout(ctx context.Context, s service.Service, dir string, timeoutDuration time.Duration) *controlClient {
	// Return early if service is not running.
	if status, err := s.Status(); err != nil || status != service.StatusRunning {
		return nil
	}
	bo := backoff.NewBackoff("self-check", logf, 10*time.Second)
	bo.LogLongerThan = 10 * time.Second

	cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
	timeout := time.NewTimer(timeoutDuration)
	defer timeout.Stop()

	// The socket control server may not start yet, so attempt to ping
	// it until we got a response.
	for {
		_, err := cc.post(startedPath, nil)
		if err == nil {
			// Server was started, stop pinging.
			break
		}
		// The socket control server is not ready yet, backoff for waiting it to be ready.
		bo.BackOff(ctx, err)

		select {
		case <-timeout.C:
			return nil
		case <-ctx.Done():
			return nil
		default:
		}
	}

	return cc
}

func newSocketControlClientMobile(dir string, stopCh chan struct{}) *controlClient {
	bo := backoff.NewBackoff("self-check", logf, 3*time.Second)
	bo.LogLongerThan = 3 * time.Second
	ctx := context.Background()
	cc := newControlClient(filepath.Join(dir, ControlSocketName()))
	for {
		select {
		case <-stopCh:
			return nil
		default:
			_, err := cc.post("/", nil)
			if err == nil {
				return cc
			} else {
				bo.BackOff(ctx, err)
			}
		}
	}
}

// checkStrFlagEmpty validates if a string flag was set to an empty string.
// If yes, emitting a fatal error message.
func checkStrFlagEmpty(cmd *cobra.Command, flagName string) {
	fl := cmd.Flags().Lookup(flagName)
	if !fl.Changed || fl.Value.Type() != "string" {
		return
	}
	if fl.Value.String() == "" {
		mainLog.Load().Fatal().Msgf(`flag "--%s" value must be non-empty`, fl.Name)
	}
}

func validateCdUpstreamProtocol() {
	if cdUID == "" {
		return
	}
	switch cdUpstreamProto {
	case ctrld.ResolverTypeDOH, ctrld.ResolverTypeDOH3:
	default:
		mainLog.Load().Fatal().Msg(`flag "--protocol" must be "doh" or "doh3"`)
	}
}

func validateCdAndNextDNSFlags() {
	if (cdUID != "" || cdOrg != "") && nextdns != "" {
		mainLog.Load().Fatal().Msgf("--%s/--%s could not be used with --%s", cdUidFlagName, cdOrgFlagName, nextdnsFlagName)
	}
}

// removeNextDNSFromArgs removes the --nextdns from command line arguments.
func removeNextDNSFromArgs(sc *service.Config) {
	a := sc.Arguments[:0]
	skip := false
	for _, x := range sc.Arguments {
		if skip {
			skip = false
			continue
		}
		// For "--nextdns XXX", skip it and mark next arg skipped.
		if x == "--"+nextdnsFlagName {
			skip = true
			continue
		}
		// For "--nextdns=XXX", just skip it.
		if strings.HasPrefix(x, "--"+nextdnsFlagName+"=") {
			continue
		}
		a = append(a, x)
	}
	sc.Arguments = a
}

// doGenerateNextDNSConfig generates a working config with nextdns resolver.
func doGenerateNextDNSConfig(uid string) error {
	if uid == "" {
		return nil
	}
	mainLog.Load().Notice().Msgf("Generating nextdns config: %s", defaultConfigFile)
	generateNextDNSConfig(uid)
	updateListenerConfig(&cfg, func() {})
	return writeConfigFile(&cfg)
}

func noticeWritingControlDConfig() error {
	if cdUID != "" {
		mainLog.Load().Notice().Msgf("Generating controld config: %s", defaultConfigFile)
	}
	return nil
}

// deactivationPinInvalidExitCode indicates exit code due to invalid pin code.
const deactivationPinInvalidExitCode = 126

// errInvalidDeactivationPin indicates that the deactivation pin is invalid.
var errInvalidDeactivationPin = errors.New("deactivation pin is invalid")

// errRequiredDeactivationPin indicates that the deactivation pin is required but not provided by users.
var errRequiredDeactivationPin = errors.New("deactivation pin is required to stop or uninstall the service")

// checkDeactivationPin validates if the deactivation pin matches one in ControlD config.
func checkDeactivationPin(s service.Service, stopCh chan struct{}) error {
	mainLog.Load().Debug().Msg("Checking deactivation pin")
	dir, err := socketDir()
	if err != nil {
		mainLog.Load().Err(err).Msg("could not check deactivation pin")
		return err
	}
	mainLog.Load().Debug().Msg("Creating control client")
	var cc *controlClient
	if s == nil {
		cc = newSocketControlClientMobile(dir, stopCh)
	} else {
		cc = newSocketControlClient(context.TODO(), s, dir)
	}
	mainLog.Load().Debug().Msg("Control client done")
	if cc == nil {
		return nil // ctrld is not running.
	}
	data, _ := json.Marshal(&deactivationRequest{Pin: deactivationPin})
	mainLog.Load().Debug().Msg("Posting deactivation request")
	resp, err := cc.post(deactivationPath, bytes.NewReader(data))
	mainLog.Load().Debug().Msg("Posting deactivation request done")
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusBadRequest:
			mainLog.Load().Error().Msg(errRequiredDeactivationPin.Error())
			return errRequiredDeactivationPin // pin is required
		case http.StatusOK:
			return nil // valid pin
		case http.StatusNotFound:
			return nil // the server is running older version of ctrld
		}
	}
	mainLog.Load().Error().Err(err).Msg(errInvalidDeactivationPin.Error())
	return errInvalidDeactivationPin
}

// isCheckDeactivationPinErr reports whether there is an error during check deactivation pin process.
func isCheckDeactivationPinErr(err error) bool {
	return errors.Is(err, errInvalidDeactivationPin) || errors.Is(err, errRequiredDeactivationPin)
}

// ensureUninstall ensures that s.Uninstall will remove ctrld service from system completely.
func ensureUninstall(s service.Service) error {
	maxAttempts := 10
	var err error
	for i := 0; i < maxAttempts; i++ {
		err = s.Uninstall()
		if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.Join(err, errors.New("uninstall failed"))
}

// exchangeContextWithTimeout wraps c.ExchangeContext with the given timeout.
func exchangeContextWithTimeout(c *dns.Client, timeout time.Duration, msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.ExchangeContext(ctx, msg, addr)
}

// curCdUID returns the current ControlD UID used by running ctrld process.
func curCdUID() string {
	if s, _ := newService(&prog{}, svcConfig); s != nil {
		// Configure Windows service failure actions
		if err := ConfigureWindowsServiceFailureActions(ctrldServiceName); err != nil {
			mainLog.Load().Debug().Err(err).Msgf("failed to configure Windows service %s failure actions", ctrldServiceName)
		}
		if dir, _ := socketDir(); dir != "" {
			cc := newSocketControlClient(context.TODO(), s, dir)
			if cc != nil {
				resp, _ := cc.post(cdPath, nil)
				if resp != nil {
					defer resp.Body.Close()
					buf, _ := io.ReadAll(resp.Body)
					return string(buf)
				}
			}
		}
	}
	return ""
}

// goArm returns the GOARM value for the binary.
func goArm() string {
	if runtime.GOARCH != "arm" {
		return ""
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range bi.Settings {
			if setting.Key == "GOARM" {
				return setting.Value
			}
		}
	}
	// Use ARM v5 as a fallback, since it works on all others.
	return "5"
}

// upgradeUrl returns the url for downloading new ctrld binary.
func upgradeUrl(baseUrl string) string {
	dlPath := fmt.Sprintf("%s-%s/ctrld", runtime.GOOS, runtime.GOARCH)
	// Use arm version set during build time, v5 binary can be run on higher arm version system.
	if armVersion := goArm(); armVersion != "" {
		dlPath = fmt.Sprintf("%s-%sv%s/ctrld", runtime.GOOS, runtime.GOARCH, armVersion)
	}
	// linux/amd64 has nocgo version, to support systems that missing some libc (like openwrt).
	if !cgoEnabled && runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		dlPath = fmt.Sprintf("%s-%s-nocgo/ctrld", runtime.GOOS, runtime.GOARCH)
	}
	dlUrl := fmt.Sprintf("%s/%s", baseUrl, dlPath)
	if runtime.GOOS == "windows" {
		dlUrl += ".exe"
	}
	return dlUrl
}

// runningIface returns the value of the iface variable used by ctrld process which is running.
func runningIface(s service.Service) *ifaceResponse {
	if sockDir, err := socketDir(); err == nil {
		if cc := newSocketControlClient(context.TODO(), s, sockDir); cc != nil {
			resp, err := cc.post(ifacePath, nil)
			if err != nil {
				return nil
			}
			defer resp.Body.Close()
			res := &ifaceResponse{}
			if err := json.NewDecoder(resp.Body).Decode(res); err != nil {
				return nil
			}
			return res
		}
	}
	return nil
}

// doValidateCdRemoteConfig fetches and validates custom config for cdUID.
func doValidateCdRemoteConfig(cdUID string, fatal bool) error {
	loggerCtx := ctrld.LoggerCtx(context.Background(), mainLog.Load())
	rc, err := controld.FetchResolverConfig(loggerCtx, cdUID, rootCmd.Version, cdDev)
	if err != nil {
		logger := mainLog.Load().Fatal()
		if !fatal {
			logger = mainLog.Load().Warn()
		}
		logger.Err(err).Err(err).Msgf("failed to fetch resolver uid: %s", cdUID)
		if !fatal {
			return err
		}
	}

	// return earlier if there's no custom config.
	if rc.Ctrld.CustomConfig == "" {
		return nil
	}

	// validateCdRemoteConfig clobbers v, saving it here to restore later.
	oldV := v
	var cfgErr error
	remoteCfg := &ctrld.Config{}
	if cfgErr = validateCdRemoteConfig(rc, remoteCfg); cfgErr == nil {
		setListenerDefaultValue(remoteCfg)
		setNetworkDefaultValue(remoteCfg)
		cfgErr = validateConfig(remoteCfg)
	} else {
		if errors.As(cfgErr, &viper.ConfigParseError{}) {
			if configStr, _ := base64.StdEncoding.DecodeString(rc.Ctrld.CustomConfig); len(configStr) > 0 {
				tmpDir := os.TempDir()
				tmpConfFile := filepath.Join(tmpDir, "ctrld.toml")
				errorLogged := false
				// Write remote config to a temporary file to get details error.
				if we := os.WriteFile(tmpConfFile, configStr, 0600); we == nil {
					if de := decoderErrorFromTomlFile(tmpConfFile); de != nil {
						row, col := de.Position()
						mainLog.Load().Error().Msgf("failed to parse custom config at line: %d, column: %d, error: %s", row, col, de.Error())
						errorLogged = true
					}
					_ = os.Remove(tmpConfFile)
				}
				// If we could not log details error, emit what we have already got.
				if !errorLogged {
					mainLog.Load().Error().Msgf("failed to parse custom config: %v", cfgErr)
				}
			}
		} else {
			mainLog.Load().Error().Msgf("failed to unmarshal custom config: %v", err)
		}
	}
	if cfgErr != nil {
		mainLog.Load().Warn().Msg("disregarding invalid custom config")
	}
	v = oldV
	return nil
}

// uninstallInvalidCdUID performs self-uninstallation because the ControlD device does not exist.
func uninstallInvalidCdUID(p *prog, logger *ctrld.Logger, doStop bool) bool {
	s, err := newService(p, svcConfig)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to create new service")
		return false
	}
	// restore static DNS settings or DHCP
	p.resetDNS(false, true)

	tasks := []task{{s.Uninstall, true, "Uninstall"}}
	if doTasks(tasks) {
		logger.Info().Msg("uninstalled service")
		if doStop {
			_ = s.Stop()
		}
		return true
	}
	return false
}
