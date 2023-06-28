package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cuonglm/osinfo"
	"github.com/go-playground/validator/v10"
	"github.com/kardianos/service"
	"github.com/miekg/dns"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/interfaces"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/certs"
	"github.com/Control-D-Inc/ctrld/internal/controld"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
	"github.com/Control-D-Inc/ctrld/internal/router"
)

var (
	version = "dev"
	commit  = "none"
)

var (
	v                    = viper.NewWithOptions(viper.KeyDelimiter("::"))
	defaultConfigWritten = false
	defaultConfigFile    = "ctrld.toml"
	rootCertPool         *x509.CertPool
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
	PreRun: func(cmd *cobra.Command, args []string) {
		initConsoleLogging()
	},
}

func curVersion() string {
	if version != "dev" && !strings.HasPrefix(version, "v") {
		version = "v" + version
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
		`verbose log output, "-v" basic logging, "-vv" debug level logging`,
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

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the DNS proxy server",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
		},
		Run: func(cmd *cobra.Command, args []string) {
			if daemon && runtime.GOOS == "windows" {
				mainLog.Fatal().Msg("Cannot run in daemon mode. Please install a Windows service.")
			}

			waitCh := make(chan struct{})
			stopCh := make(chan struct{})
			p := &prog{
				waitCh: waitCh,
				stopCh: stopCh,
			}
			if !daemon {
				// We need to call s.Run() as soon as possible to response to the OS manager, so it
				// can see ctrld is running and don't mark ctrld as failed service.
				go func() {
					s, err := newService(p, svcConfig)
					if err != nil {
						mainLog.Fatal().Err(err).Msg("failed create new service")
					}
					if err := s.Run(); err != nil {
						mainLog.Error().Err(err).Msg("failed to start service")
					}
				}()
			}
			noConfigStart := isNoConfigStart(cmd)
			writeDefaultConfig := !noConfigStart && configBase64 == ""
			tryReadingConfig(writeDefaultConfig)

			readBase64Config(configBase64)
			processNoConfigFlags(noConfigStart)
			if err := v.Unmarshal(&cfg); err != nil {
				mainLog.Fatal().Msgf("failed to unmarshal config: %v", err)
			}

			processLogAndCacheFlags()

			// Log config do not have thing to validate, so it's safe to init log here,
			// so it's able to log information in processCDFlags.
			initLogging()

			mainLog.Info().Msgf("starting ctrld %s", curVersion())
			oi := osinfo.New()
			mainLog.Info().Msgf("os: %s", oi.String())

			// Wait for network up.
			if !ctrldnet.Up() {
				mainLog.Fatal().Msg("network is not up yet")
			}

			// Processing --cd flag require connecting to ControlD API, which needs valid
			// time for validating server certificate. Some routers need NTP synchronization
			// to set the current time, so this check must happen before processCDFlags.
			if err := router.PreRun(svcConfig); err != nil {
				mainLog.Fatal().Err(err).Msg("failed to perform router pre-run check")
			}

			oldLogPath := cfg.Service.LogPath
			processCDFlags()
			if newLogPath := cfg.Service.LogPath; newLogPath != "" && oldLogPath != newLogPath {
				// After processCDFlags, log config may change, so reset mainLog and re-init logging.
				mainLog = zerolog.New(io.Discard)

				// Copy logs written so far to new log file if possible.
				if buf, err := os.ReadFile(oldLogPath); err == nil {
					if err := os.WriteFile(newLogPath, buf, os.FileMode(0o600)); err != nil {
						mainLog.Warn().Err(err).Msg("could not copy old log file")
					}
				}
				initLoggingWithBackup(false)
			}

			if err := ctrld.ValidateConfig(validator.New(), &cfg); err != nil {
				mainLog.Fatal().Msgf("invalid config: %v", err)
			}
			initCache()

			if daemon {
				exe, err := os.Executable()
				if err != nil {
					mainLog.Error().Err(err).Msg("failed to find the binary")
					os.Exit(1)
				}
				curDir, err := os.Getwd()
				if err != nil {
					mainLog.Error().Err(err).Msg("failed to get current working directory")
					os.Exit(1)
				}
				// If running as daemon, re-run the command in background, with daemon off.
				cmd := exec.Command(exe, append(os.Args[1:], "-d=false")...)
				cmd.Dir = curDir
				if err := cmd.Start(); err != nil {
					mainLog.Error().Err(err).Msg("failed to start process as daemon")
					os.Exit(1)
				}
				mainLog.Info().Int("pid", cmd.Process.Pid).Msg("DNS proxy started")
				os.Exit(0)
			}

			if setupRouter {
				switch platform := router.Name(); {
				case platform == router.DDWrt:
					rootCertPool = certs.CACertPool()
					fallthrough
				case platform != "":
					if !router.IsSupported(platform) {
						unsupportedPlatformHelp(cmd)
						os.Exit(1)
					}
					p.onStarted = append(p.onStarted, func() {
						mainLog.Debug().Msg("Router setup")
						if err := router.Configure(&cfg); err != nil {
							mainLog.Error().Err(err).Msg("could not configure router")
						}
					})
					p.onStopped = append(p.onStopped, func() {
						mainLog.Debug().Msg("Router cleanup")
						if err := router.Cleanup(svcConfig); err != nil {
							mainLog.Error().Err(err).Msg("could not cleanup router")
						}
						p.resetDNS()
					})
				}
			}

			close(waitCh)
			<-stopCh
			for _, f := range p.onStopped {
				f()
			}
		},
	}
	runCmd.Flags().BoolVarP(&daemon, "daemon", "d", false, "Run as daemon")
	runCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")
	runCmd.Flags().StringVarP(&configBase64, "base64_config", "", "", "Base64 encoded config")
	runCmd.Flags().StringVarP(&listenAddress, "listen", "", "", "Listener address and port, in format: address:port")
	runCmd.Flags().StringVarP(&primaryUpstream, "primary_upstream", "", "", "Primary upstream endpoint")
	runCmd.Flags().StringVarP(&secondaryUpstream, "secondary_upstream", "", "", "Secondary upstream endpoint")
	runCmd.Flags().StringSliceVarP(&domains, "domains", "", nil, "List of domain to apply in a split DNS policy")
	runCmd.Flags().StringVarP(&logPath, "log", "", "", "Path to log file")
	runCmd.Flags().IntVarP(&cacheSize, "cache_size", "", 0, "Enable cache with size items")
	runCmd.Flags().StringVarP(&cdUID, "cd", "", "", "Control D resolver uid")
	runCmd.Flags().BoolVarP(&cdDev, "dev", "", false, "Use Control D dev resolver/domain")
	_ = runCmd.Flags().MarkHidden("dev")
	runCmd.Flags().StringVarP(&homedir, "homedir", "", "", "")
	_ = runCmd.Flags().MarkHidden("homedir")
	runCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)
	_ = runCmd.Flags().MarkHidden("iface")
	runCmd.Flags().BoolVarP(&setupRouter, "router", "", false, `setup for running on router platforms`)
	_ = runCmd.Flags().MarkHidden("router")

	rootCmd.AddCommand(runCmd)

	startCmd := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Use:   "start",
		Short: "Install and start the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			sc := &service.Config{}
			*sc = *svcConfig
			osArgs := os.Args[2:]
			if os.Args[1] == "service" {
				osArgs = os.Args[3:]
			}
			setDependencies(sc)
			sc.Arguments = append([]string{"run"}, osArgs...)
			if err := router.ConfigureService(sc); err != nil {
				mainLog.Fatal().Err(err).Msg("failed to configure service on router")
			}

			// No config path, generating config in HOME directory.
			noConfigStart := isNoConfigStart(cmd)
			writeDefaultConfig := !noConfigStart && configBase64 == ""
			if configPath != "" {
				v.SetConfigFile(configPath)
			}
			if dir, err := userHomeDir(); err == nil {
				setWorkingDirectory(sc, dir)
				if configPath == "" && writeDefaultConfig {
					defaultConfigFile = filepath.Join(dir, defaultConfigFile)
				}
				sc.Arguments = append(sc.Arguments, "--homedir="+dir)
			}

			tryReadingConfig(writeDefaultConfig)

			if err := v.Unmarshal(&cfg); err != nil {
				mainLog.Fatal().Msgf("failed to unmarshal config: %v", err)
			}

			initLogging()

			processCDFlags()

			if err := ctrld.ValidateConfig(validator.New(), &cfg); err != nil {
				mainLog.Fatal().Msgf("invalid config: %v", err)
			}

			// Explicitly passing config, so on system where home directory could not be obtained,
			// or sub-process env is different with the parent, we still behave correctly and use
			// the expected config file.
			if configPath == "" {
				sc.Arguments = append(sc.Arguments, "--config="+defaultConfigFile)
			}

			p := &prog{}
			s, err := newService(p, sc)
			if err != nil {
				mainLog.Error().Msg(err.Error())
				return
			}

			mainLog.Debug().Msg("cleaning up router before installing")
			_ = router.Cleanup(svcConfig)

			tasks := []task{
				{s.Stop, false},
				{s.Uninstall, false},
				{s.Install, false},
				{s.Start, true},
			}
			if doTasks(tasks) {
				if err := router.PostInstall(svcConfig); err != nil {
					mainLog.Warn().Err(err).Msg("post installation failed, please check system/service log for details error")
					return
				}
				status, err := s.Status()
				if err != nil {
					mainLog.Warn().Err(err).Msg("could not get service status")
					return
				}

				domain := cfg.Upstream["0"].VerifyDomain()
				status = selfCheckStatus(status, domain)
				switch status {
				case service.StatusRunning:
					mainLog.Notice().Msg("Service started")
				default:
					mainLog.Error().Msg("Service did not start, please check system/service log for details error")
					uninstall(p, s)
					os.Exit(1)
				}
				// On Linux, Darwin, Freebsd, ctrld set DNS on startup, because the DNS setting could be
				// reset after rebooting. On windows, we only need to set once here. See prog.preRun in
				// prog_*.go file for dedicated code on each platforms.
				if runtime.GOOS == "windows" {
					p.setDNS()
				}
			}
		},
	}
	// Keep these flags in sync with runCmd above, except for "-d".
	startCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")
	startCmd.Flags().StringVarP(&configBase64, "base64_config", "", "", "Base64 encoded config")
	startCmd.Flags().StringVarP(&listenAddress, "listen", "", "", "Listener address and port, in format: address:port")
	startCmd.Flags().StringVarP(&primaryUpstream, "primary_upstream", "", "", "Primary upstream endpoint")
	startCmd.Flags().StringVarP(&secondaryUpstream, "secondary_upstream", "", "", "Secondary upstream endpoint")
	startCmd.Flags().StringSliceVarP(&domains, "domains", "", nil, "List of domain to apply in a split DNS policy")
	startCmd.Flags().StringVarP(&logPath, "log", "", "", "Path to log file")
	startCmd.Flags().IntVarP(&cacheSize, "cache_size", "", 0, "Enable cache with size items")
	startCmd.Flags().StringVarP(&cdUID, "cd", "", "", "Control D resolver uid")
	startCmd.Flags().BoolVarP(&cdDev, "dev", "", false, "Use Control D dev resolver/domain")
	_ = startCmd.Flags().MarkHidden("dev")
	startCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)
	startCmd.Flags().BoolVarP(&setupRouter, "router", "", false, `setup for running on router platforms`)
	_ = startCmd.Flags().MarkHidden("router")

	stopCmd := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Use:   "stop",
		Short: "Stop the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			prog := &prog{}
			s, err := newService(prog, svcConfig)
			if err != nil {
				mainLog.Error().Msg(err.Error())
				return
			}
			initLogging()
			if doTasks([]task{{s.Stop, true}}) {
				prog.resetDNS()
				mainLog.Notice().Msg("Service stopped")
			}
		},
	}
	stopCmd.Flags().StringVarP(&iface, "iface", "", "", `Reset DNS setting for iface, "auto" means the default interface gateway`)

	restartCmd := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Use:   "restart",
		Short: "Restart the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			s, err := newService(&prog{}, svcConfig)
			if err != nil {
				mainLog.Error().Msg(err.Error())
				return
			}
			initLogging()
			if doTasks([]task{{s.Restart, true}}) {
				mainLog.Notice().Msg("Service restarted")
			}
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show status of the ctrld service",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
		},
		Run: func(cmd *cobra.Command, args []string) {
			s, err := newService(&prog{}, svcConfig)
			if err != nil {
				mainLog.Error().Msg(err.Error())
				return
			}
			status, err := s.Status()
			if err != nil {
				mainLog.Error().Msg(err.Error())
				os.Exit(1)
			}
			switch status {
			case service.StatusUnknown:
				mainLog.Notice().Msg("Unknown status")
				os.Exit(2)
			case service.StatusRunning:
				mainLog.Notice().Msg("Service is running")
				os.Exit(0)
			case service.StatusStopped:
				mainLog.Notice().Msg("Service is stopped")
				os.Exit(1)
			}
		},
	}
	if runtime.GOOS == "darwin" {
		// On darwin, running status command without privileges may return wrong information.
		statusCmd.PreRun = func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		}
	}

	uninstallCmd := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Use:   "uninstall",
		Short: "Stop and uninstall the ctrld service",
		Long: `Stop and uninstall the ctrld service.

NOTE: Uninstalling will set DNS to values provided by DHCP.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			p := &prog{}
			s, err := newService(p, svcConfig)
			if err != nil {
				mainLog.Error().Msg(err.Error())
				return
			}
			if iface == "" {
				iface = "auto"
			}
			uninstall(p, s)
		},
	}
	uninstallCmd.Flags().StringVarP(&iface, "iface", "", "", `Reset DNS setting for iface, use "auto" for the default gateway interface`)

	listIfacesCmd := &cobra.Command{
		Use:   "list",
		Short: "List network interfaces of the host",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
		},
		Run: func(cmd *cobra.Command, args []string) {
			err := interfaces.ForeachInterface(func(i interfaces.Interface, prefixes []netip.Prefix) {
				fmt.Printf("Index : %d\n", i.Index)
				fmt.Printf("Name  : %s\n", i.Name)
				addrs, _ := i.Addrs()
				for i, ipaddr := range addrs {
					if i == 0 {
						fmt.Printf("Addrs : %v\n", ipaddr)
						continue
					}
					fmt.Printf("        %v\n", ipaddr)
				}
				for i, dns := range currentDNS(i.Interface) {
					if i == 0 {
						fmt.Printf("DNS   : %s\n", dns)
						continue
					}
					fmt.Printf("      : %s\n", dns)
				}
				println()
			})
			if err != nil {
				mainLog.Error().Msg(err.Error())
			}
		},
	}
	interfacesCmd := &cobra.Command{
		Use:   "interfaces",
		Short: "Manage network interfaces",
		Args:  cobra.OnlyValidArgs,
		ValidArgs: []string{
			listIfacesCmd.Use,
		},
	}
	interfacesCmd.AddCommand(listIfacesCmd)

	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "Manage ctrld service",
		Args:  cobra.OnlyValidArgs,
		ValidArgs: []string{
			statusCmd.Use,
			stopCmd.Use,
			restartCmd.Use,
			statusCmd.Use,
			uninstallCmd.Use,
			interfacesCmd.Use,
		},
	}
	serviceCmd.AddCommand(startCmd)
	serviceCmd.AddCommand(stopCmd)
	serviceCmd.AddCommand(restartCmd)
	serviceCmd.AddCommand(statusCmd)
	serviceCmd.AddCommand(uninstallCmd)
	serviceCmd.AddCommand(interfacesCmd)
	rootCmd.AddCommand(serviceCmd)
	startCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Use:   "start",
		Short: "Quick start service and configure DNS on interface",
		Run: func(cmd *cobra.Command, args []string) {
			if !cmd.Flags().Changed("iface") {
				os.Args = append(os.Args, "--iface="+ifaceStartStop)
			}
			iface = ifaceStartStop
			startCmd.Run(cmd, args)
		},
	}
	startCmdAlias.Flags().StringVarP(&ifaceStartStop, "iface", "", "auto", `Update DNS setting for iface, "auto" means the default interface gateway`)
	startCmdAlias.Flags().AddFlagSet(startCmd.Flags())
	rootCmd.AddCommand(startCmdAlias)
	stopCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Use:   "stop",
		Short: "Quick stop service and remove DNS from interface",
		Run: func(cmd *cobra.Command, args []string) {
			if !cmd.Flags().Changed("iface") {
				os.Args = append(os.Args, "--iface="+ifaceStartStop)
			}
			iface = ifaceStartStop
			stopCmd.Run(cmd, args)
		},
	}
	stopCmdAlias.Flags().StringVarP(&ifaceStartStop, "iface", "", "auto", `Reset DNS setting for iface, "auto" means the default interface gateway`)
	stopCmdAlias.Flags().AddFlagSet(stopCmd.Flags())
	rootCmd.AddCommand(stopCmdAlias)
}

func writeConfigFile() error {
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

func readConfigFile(writeDefaultConfig bool) bool {
	// If err == nil, there's a config supplied via `--config`, no default config written.
	err := v.ReadInConfig()
	if err == nil {
		mainLog.Info().Msg("loading config file from: " + v.ConfigFileUsed())
		defaultConfigFile = v.ConfigFileUsed()
		return true
	}

	if !writeDefaultConfig {
		return false
	}

	// If error is viper.ConfigFileNotFoundError, write default config.
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		if err := v.Unmarshal(&cfg); err != nil {
			mainLog.Fatal().Msgf("failed to unmarshal default config: %v", err)
		}
		if err := writeConfigFile(); err != nil {
			mainLog.Fatal().Msgf("failed to write default config file: %v", err)
		} else {
			fp, err := filepath.Abs(defaultConfigFile)
			if err != nil {
				mainLog.Fatal().Msgf("failed to get default config file path: %v", err)
			}
			mainLog.Info().Msg("writing default config file to: " + fp)
		}
		defaultConfigWritten = true
		return false
	}
	// Otherwise, report fatal error and exit.
	mainLog.Fatal().Msgf("failed to decode config file: %v", err)
	return false
}

func readBase64Config(configBase64 string) {
	if configBase64 == "" {
		return
	}
	configStr, err := base64.StdEncoding.DecodeString(configBase64)
	if err != nil {
		mainLog.Fatal().Msgf("invalid base64 config: %v", err)
	}

	// readBase64Config is called when:
	//
	//  - "--base64_config" flag set.
	//  - Reading custom config when "--cd" flag set.
	//
	// So we need to re-create viper instance to discard old one.
	v = viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigType("toml")
	if err := v.ReadConfig(bytes.NewReader(configStr)); err != nil {
		mainLog.Fatal().Msgf("failed to read base64 config: %v", err)
	}
}

func processNoConfigFlags(noConfigStart bool) {
	if !noConfigStart {
		return
	}
	if listenAddress == "" || primaryUpstream == "" {
		mainLog.Fatal().Msg(`"listen" and "primary_upstream" flags must be set in no config mode`)
	}
	processListenFlag()

	endpointAndTyp := func(endpoint string) (string, string) {
		typ := ctrld.ResolverTypeFromEndpoint(endpoint)
		return strings.TrimPrefix(endpoint, "quic://"), typ
	}
	pEndpoint, pType := endpointAndTyp(primaryUpstream)
	upstream := map[string]*ctrld.UpstreamConfig{
		"0": {
			Name:     pEndpoint,
			Endpoint: pEndpoint,
			Type:     pType,
			Timeout:  5000,
		},
	}
	if secondaryUpstream != "" {
		sEndpoint, sType := endpointAndTyp(secondaryUpstream)
		upstream["1"] = &ctrld.UpstreamConfig{
			Name:     sEndpoint,
			Endpoint: sEndpoint,
			Type:     sType,
			Timeout:  5000,
		}
		rules := make([]ctrld.Rule, 0, len(domains))
		for _, domain := range domains {
			rules = append(rules, ctrld.Rule{domain: []string{"upstream.1"}})
		}
		lc := v.Get("listener").(map[string]*ctrld.ListenerConfig)["0"]
		lc.Policy = &ctrld.ListenerPolicyConfig{Name: "My Policy", Rules: rules}
	}
	v.Set("upstream", upstream)
}

func processCDFlags() {
	if cdUID == "" {
		return
	}
	logger := mainLog.With().Str("mode", "cd").Logger()
	logger.Info().Msgf("fetching Controld D configuration from API: %s", cdUID)
	resolverConfig, err := controld.FetchResolverConfig(cdUID, rootCmd.Version, cdDev)
	if uer, ok := err.(*controld.UtilityErrorResponse); ok && uer.ErrorField.Code == controld.InvalidConfigCode {
		s, err := newService(&prog{}, svcConfig)
		if err != nil {
			logger.Warn().Err(err).Msg("failed to create new service")
			return
		}
		if netIface, _ := netInterface(iface); netIface != nil {
			if err := restoreNetworkManager(); err != nil {
				logger.Error().Err(err).Msg("could not restore NetworkManager")
				return
			}
			logger.Debug().Str("iface", netIface.Name).Msg("Restoring DNS for interface")
			if err := resetDNS(netIface); err != nil {
				logger.Warn().Err(err).Msg("something went wrong while restoring DNS")
			} else {
				logger.Debug().Str("iface", netIface.Name).Msg("Restoring DNS successfully")
			}
		}

		tasks := []task{{s.Uninstall, true}}
		if doTasks(tasks) {
			logger.Info().Msg("uninstalled service")
		}
		logger.Fatal().Err(uer).Msg("failed to fetch resolver config")
	}
	if err != nil {
		logger.Warn().Err(err).Msg("could not fetch resolver config")
		return
	}

	logger.Info().Msg("generating ctrld config from Control-D configuration")
	cfg = ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{
		"0": {Port: 53},
	}}
	if resolverConfig.Ctrld.CustomConfig != "" {
		logger.Info().Msg("using defined custom config of Control-D resolver")
		readBase64Config(resolverConfig.Ctrld.CustomConfig)
		if err := v.Unmarshal(&cfg); err != nil {
			mainLog.Fatal().Msgf("failed to unmarshal config: %v", err)
		}
		for _, listener := range cfg.Listener {
			if listener.IP == "" {
				listener.IP = randomLocalIP()
			}
			if listener.Port == 0 {
				listener.Port = 53
			}
		}
		switch {
		case setupRouter:
			if lc := cfg.Listener["0"]; lc != nil && lc.IP == "" {
				lc.IP = router.ListenIP()
				lc.Port = router.ListenPort()
			}
		case useSystemdResolved:
			if lc := cfg.Listener["0"]; lc != nil {
				if ip := net.ParseIP(lc.IP); ip != nil && ip.IsLoopback() {
					mainLog.Warn().Msg("using loopback interface do not work with systemd-resolved")
					// systemd-resolved does not allow forwarding DNS queries from 127.0.0.53 to loopback
					// ip address, so trying to listen on default route interface address instead.
					if netIface, _ := net.InterfaceByName(defaultIfaceName()); netIface != nil {
						addrs, _ := netIface.Addrs()
						for _, addr := range addrs {
							if netIP, ok := addr.(*net.IPNet); ok && netIP.IP.To4() != nil {
								lc.IP = netIP.IP.To4().String()
								mainLog.Warn().Msgf("use %s as listener address", lc.IP)
							}
						}
					}
				}
			}
		}
	} else {
		cfg.Network = make(map[string]*ctrld.NetworkConfig)
		cfg.Network["0"] = &ctrld.NetworkConfig{
			Name:  "Network 0",
			Cidrs: []string{"0.0.0.0/0"},
		}
		cfg.Upstream = make(map[string]*ctrld.UpstreamConfig)
		cfg.Upstream["0"] = &ctrld.UpstreamConfig{
			Endpoint: resolverConfig.DOH,
			Type:     ctrld.ResolverTypeDOH,
			Timeout:  5000,
		}
		rules := make([]ctrld.Rule, 0, len(resolverConfig.Exclude))
		for _, domain := range resolverConfig.Exclude {
			rules = append(rules, ctrld.Rule{domain: []string{}})
		}
		cfg.Listener = make(map[string]*ctrld.ListenerConfig)
		lc := &ctrld.ListenerConfig{
			IP:   "127.0.0.1",
			Port: 53,
			Policy: &ctrld.ListenerPolicyConfig{
				Name:  "My Policy",
				Rules: rules,
			},
		}
		if setupRouter {
			lc.IP = router.ListenIP()
			lc.Port = router.ListenPort()
		}
		cfg.Listener["0"] = lc
	}

	processLogAndCacheFlags()

	if err := writeConfigFile(); err != nil {
		logger.Fatal().Err(err).Msg("failed to write config file")
	} else {
		logger.Info().Msg("writing config file to: " + defaultConfigFile)
	}
}

func processListenFlag() {
	if listenAddress == "" {
		return
	}
	host, portStr, err := net.SplitHostPort(listenAddress)
	if err != nil {
		mainLog.Fatal().Msgf("invalid listener address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		mainLog.Fatal().Msgf("invalid port number: %v", err)
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
		cfg.Service.LogLevel = "debug"
		cfg.Service.LogPath = logPath
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
	err := interfaces.ForeachInterface(func(i interfaces.Interface, prefixes []netip.Prefix) {
		if i.Name == ifaceName {
			iface = i.Interface
		}
	})
	if iface == nil {
		return nil, errors.New("interface not found")
	}
	if err := patchNetIfaceName(iface); err != nil {
		return nil, err
	}
	return iface, err
}

func defaultIfaceName() string {
	dri, err := interfaces.DefaultRouteInterface()
	if err != nil {
		// On WSL 1, the route table does not have any default route. But the fact that
		// it only uses /etc/resolv.conf for setup DNS, so we can use "lo" here.
		if oi := osinfo.New(); strings.Contains(oi.String(), "Microsoft") {
			return "lo"
		}
		mainLog.Fatal().Err(err).Msg("failed to get default route interface")
	}
	return dri
}

func selfCheckStatus(status service.Status, domain string) service.Status {
	if domain == "" {
		// Nothing to do, return the status as-is.
		return status
	}
	c := new(dns.Client)
	bo := backoff.NewBackoff("self-check", logf, 10*time.Second)
	bo.LogLongerThan = 500 * time.Millisecond
	ctx := context.Background()
	maxAttempts := 20
	mainLog.Debug().Msg("Performing self-check")

	for i := 0; i < maxAttempts; i++ {
		lc := cfg.Listener["0"]
		m := new(dns.Msg)
		m.SetQuestion(domain+".", dns.TypeA)
		m.RecursionDesired = true
		r, _, err := c.ExchangeContext(ctx, m, net.JoinHostPort(lc.IP, strconv.Itoa(lc.Port)))
		if r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
			mainLog.Debug().Msgf("self-check against %q succeeded", domain)
			return status
		}
		bo.BackOff(ctx, fmt.Errorf("ExchangeContext: %w", err))
	}
	mainLog.Debug().Msgf("self-check against %q failed", domain)
	return service.StatusUnknown
}

func unsupportedPlatformHelp(cmd *cobra.Command) {
	mainLog.Error().Msg("Unsupported or incorrectly chosen router platform. Please open an issue and provide all relevant information: https://github.com/Control-D-Inc/ctrld/issues/new")
}

func userHomeDir() (string, error) {
	switch router.Name() {
	case router.DDWrt, router.Merlin, router.Tomato:
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.Dir(exe), nil
	}
	// viper will expand for us.
	if runtime.GOOS == "windows" {
		return os.UserHomeDir()
	}
	dir := "/etc/controld"
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", err
	}
	return dir, nil
}

func tryReadingConfig(writeDefaultConfig bool) {
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
		mainLog.Fatal().Msgf("failed to get config dir: %v", err)
	}
	for _, config := range configs {
		ctrld.SetConfigNameWithPath(v, config.name, dir)
		v.SetConfigFile(configPath)
		if readConfigFile(config.written) {
			break
		}
	}
}

func uninstall(p *prog, s service.Service) {
	tasks := []task{
		{s.Stop, false},
		{s.Uninstall, true},
	}
	initLogging()
	if doTasks(tasks) {
		if err := router.PostUninstall(svcConfig); err != nil {
			mainLog.Warn().Err(err).Msg("post uninstallation failed, please check system/service log for details error")
			return
		}
		// Stop already reset DNS on router.
		if router.Name() == "" {
			p.resetDNS()
		}
		mainLog.Debug().Msg("Router cleanup")
		// Stop already did router.Cleanup and report any error if happens,
		// ignoring error here to prevent false positive.
		_ = router.Cleanup(svcConfig)
		mainLog.Notice().Msg("Service uninstalled")
		return
	}
}
