package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/go-playground/validator/v10"
	"github.com/kardianos/service"
	"github.com/miekg/dns"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/interfaces"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

const selfCheckFQDN = "verify.controld.com"

var (
	v                    = viper.NewWithOptions(viper.KeyDelimiter("::"))
	defaultConfigWritten = false
	defaultConfigFile    = "ctrld.toml"
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

func initCLI() {
	// Enable opening via explorer.exe on Windows.
	// See: https://github.com/spf13/cobra/issues/844.
	cobra.MousetrapHelpText = ""
	cobra.EnableCommandSorting = false

	rootCmd := &cobra.Command{
		Use:     "ctrld",
		Short:   strings.TrimLeft(rootShortDesc, "\n"),
		Version: "1.1.1",
	}
	rootCmd.PersistentFlags().CountVarP(
		&verbose,
		"verbose",
		"v",
		`verbose log output, "-v" basic logging, "-vv" debug level logging`,
	)
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
	rootCmd.CompletionOptions.HiddenDefaultCmd = true

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the DNS proxy server",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if daemon && runtime.GOOS == "windows" {
				log.Fatal("Cannot run in daemon mode. Please install a Windows service.")
			}
			noConfigStart := isNoConfigStart(cmd)
			writeDefaultConfig := !noConfigStart && configBase64 == ""
			configs := []struct {
				name    string
				written bool
			}{
				// For compatibility, we check for config.toml first, but only read it if exists.
				{"config", false},
				{"ctrld", writeDefaultConfig},
			}
			for _, config := range configs {
				ctrld.SetConfigName(v, config.name)
				v.SetConfigFile(configPath)
				if readConfigFile(config.written) {
					break
				}
			}

			readBase64Config()
			processNoConfigFlags(noConfigStart)
			if err := v.Unmarshal(&cfg); err != nil {
				log.Fatalf("failed to unmarshal config: %v", err)
			}
			// Wait for network up.
			if !ctrldnet.Up() {
				log.Fatal("network is not up yet")
			}
			processLogAndCacheFlags()
			// Log config do not have thing to validate, so it's safe to init log here,
			// so it's able to log information in processCDFlags.
			initLogging()
			processCDFlags()
			if err := ctrld.ValidateConfig(validator.New(), &cfg); err != nil {
				log.Fatalf("invalid config: %v", err)
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

			s, err := service.New(&prog{}, svcConfig)
			if err != nil {
				mainLog.Fatal().Err(err).Msg("failed create new service")
			}
			serviceLogger, err := s.Logger(nil)
			if err != nil {
				mainLog.Error().Err(err).Msg("failed to get service logger")
				return
			}

			if err := s.Run(); err != nil {
				if sErr := serviceLogger.Error(err); sErr != nil {
					mainLog.Error().Err(sErr).Msg("failed to write service log")
				}
				mainLog.Error().Err(err).Msg("failed to start service")
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
	runCmd.Flags().StringVarP(&homedir, "homedir", "", "", "")
	_ = runCmd.Flags().MarkHidden("homedir")
	runCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)
	_ = runCmd.Flags().MarkHidden("iface")

	rootCmd.AddCommand(runCmd)

	startCmd := &cobra.Command{
		PreRun: checkHasElevatedPrivilege,
		Use:    "start",
		Short:  "Install and start the ctrld service",
		Args:   cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			sc := &service.Config{}
			*sc = *svcConfig
			osArgs := os.Args[2:]
			if os.Args[1] == "service" {
				osArgs = os.Args[3:]
			}
			setDependencies(sc)
			sc.Arguments = append([]string{"run"}, osArgs...)

			// No config path, generating config in HOME directory.
			noConfigStart := isNoConfigStart(cmd)
			writeDefaultConfig := !noConfigStart && configBase64 == ""
			if configPath != "" {
				v.SetConfigFile(configPath)
			}
			if dir, err := os.UserHomeDir(); err == nil {
				setWorkingDirectory(sc, dir)
				if configPath == "" && writeDefaultConfig {
					defaultConfigFile = filepath.Join(dir, defaultConfigFile)
					v.SetConfigFile(defaultConfigFile)
				}
				sc.Arguments = append(sc.Arguments, "--homedir="+dir)
			}

			readConfigFile(writeDefaultConfig && cdUID == "")
			if err := v.Unmarshal(&cfg); err != nil {
				log.Fatalf("failed to unmarshal config: %v", err)
			}

			logPath := cfg.Service.LogPath
			cfg.Service.LogPath = ""
			initLogging()
			cfg.Service.LogPath = logPath

			processCDFlags()
			// On Windows, the service will be run as SYSTEM, so if ctrld start as Admin,
			// the user home dir is different, so pass specific arguments that relevant here.
			if runtime.GOOS == "windows" {
				if configPath == "" {
					sc.Arguments = append(sc.Arguments, "--config="+defaultConfigFile)
				}
			}

			prog := &prog{}
			s, err := service.New(prog, sc)
			if err != nil {
				stderrMsg(err.Error())
				return
			}
			tasks := []task{
				{s.Stop, false},
				{s.Uninstall, false},
				{s.Install, false},
				{s.Start, true},
			}
			if doTasks(tasks) {
				status, err := s.Status()
				if err != nil {
					mainLog.Warn().Err(err).Msg("could not get service status")
					return
				}

				status = selfCheckStatus(status)
				switch status {
				case service.StatusRunning:
					mainLog.Info().Msg("Service started")
				default:
					mainLog.Error().Msg("Service did not start, please check system/service log for details error")
					if runtime.GOOS == "linux" {
						prog.resetDNS()
					}
					os.Exit(1)
				}
				prog.setDNS()
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
	startCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)

	stopCmd := &cobra.Command{
		PreRun: checkHasElevatedPrivilege,
		Use:    "stop",
		Short:  "Stop the ctrld service",
		Args:   cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			prog := &prog{}
			s, err := service.New(prog, svcConfig)
			if err != nil {
				stderrMsg(err.Error())
				return
			}
			initLogging()
			if doTasks([]task{{s.Stop, true}}) {
				prog.resetDNS()
				mainLog.Info().Msg("Service stopped")
			}
		},
	}
	stopCmd.Flags().StringVarP(&iface, "iface", "", "", `Reset DNS setting for iface, "auto" means the default interface gateway`)

	restartCmd := &cobra.Command{
		PreRun: checkHasElevatedPrivilege,
		Use:    "restart",
		Short:  "Restart the ctrld service",
		Args:   cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			s, err := service.New(&prog{}, svcConfig)
			if err != nil {
				stderrMsg(err.Error())
				return
			}
			initLogging()
			if doTasks([]task{{s.Restart, true}}) {
				stdoutMsg("Service restarted")
			}
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show status of the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			s, err := service.New(&prog{}, svcConfig)
			if err != nil {
				stderrMsg(err.Error())
				return
			}
			status, err := s.Status()
			if err != nil {
				stderrMsg(err.Error())
				os.Exit(1)
			}
			switch status {
			case service.StatusUnknown:
				stdoutMsg("Unknown status")
				os.Exit(2)
			case service.StatusRunning:
				stdoutMsg("Service is running")
				os.Exit(0)
			case service.StatusStopped:
				stdoutMsg("Service is stopped")
				os.Exit(1)
			}
		},
	}

	uninstallCmd := &cobra.Command{
		PreRun: checkHasElevatedPrivilege,
		Use:    "uninstall",
		Short:  "Stop and uninstall the ctrld service",
		Args:   cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			prog := &prog{}
			s, err := service.New(prog, svcConfig)
			if err != nil {
				stderrMsg(err.Error())
				return
			}
			tasks := []task{
				{s.Stop, false},
				{s.Uninstall, true},
			}
			initLogging()
			if doTasks(tasks) {
				prog.resetDNS()
				mainLog.Info().Msg("Service uninstalled")
				return
			}
		},
	}
	uninstallCmd.Flags().StringVarP(&iface, "iface", "", "auto", `Reset DNS setting for iface, "auto" means the default interface gateway`)

	listIfacesCmd := &cobra.Command{
		Use:   "list",
		Short: "List network interfaces of the host",
		Args:  cobra.NoArgs,
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
				stderrMsg(err.Error())
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
		PreRun: checkHasElevatedPrivilege,
		Use:    "start",
		Short:  "Quick start service and configure DNS on interface",
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
		PreRun: checkHasElevatedPrivilege,
		Use:    "stop",
		Short:  "Quick stop service and remove DNS from interface",
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

	if err := rootCmd.Execute(); err != nil {
		stderrMsg(err.Error())
		os.Exit(1)
	}
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
		fmt.Println("loading config file from:", v.ConfigFileUsed())
		defaultConfigFile = v.ConfigFileUsed()
		v.OnConfigChange(func(in fsnotify.Event) {
			if err := v.UnmarshalKey("listener", &cfg.Listener); err != nil {
				log.Printf("failed to unmarshal listener config: %v", err)
				return
			}
		})
		v.WatchConfig()
		return true
	}

	if !writeDefaultConfig {
		return false
	}

	// If error is viper.ConfigFileNotFoundError, write default config.
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		if err := writeConfigFile(); err != nil {
			log.Fatalf("failed to write default config file: %v", err)
		} else {
			fmt.Println("writing default config file to: " + defaultConfigFile)
		}
		defaultConfigWritten = true
		return false
	}
	// Otherwise, report fatal error and exit.
	log.Fatalf("failed to decode config file: %v", err)
	return false
}

func readBase64Config() {
	if configBase64 == "" {
		return
	}
	configStr, err := base64.StdEncoding.DecodeString(configBase64)
	if err != nil {
		log.Fatalf("invalid base64 config: %v", err)
	}
	if err := v.ReadConfig(bytes.NewReader(configStr)); err != nil {
		log.Fatalf("failed to read base64 config: %v", err)
	}
}

func processNoConfigFlags(noConfigStart bool) {
	if !noConfigStart {
		return
	}
	if listenAddress == "" || primaryUpstream == "" {
		log.Fatal(`"listen" and "primary_upstream" flags must be set in no config mode`)
	}
	processListenFlag()

	upstream := map[string]*ctrld.UpstreamConfig{
		"0": {
			Name:     primaryUpstream,
			Endpoint: primaryUpstream,
			Type:     ctrld.ResolverTypeDOH,
		},
	}
	if secondaryUpstream != "" {
		upstream["1"] = &ctrld.UpstreamConfig{
			Name:     secondaryUpstream,
			Endpoint: secondaryUpstream,
			Type:     ctrld.ResolverTypeLegacy,
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
	if iface == "" {
		iface = "auto"
	}
	logger := mainLog.With().Str("mode", "cd").Logger()
	logger.Info().Msgf("fetching Controld D configuration from API: %s", cdUID)
	resolverConfig, err := controld.FetchResolverConfig(cdUID)
	if uer, ok := err.(*controld.UtilityErrorResponse); ok && uer.ErrorField.Code == controld.InvalidConfigCode {
		s, err := service.New(&prog{}, svcConfig)
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

	logger.Info().Msg("generating ctrld config from Controld-D configuration")
	cfg = ctrld.Config{}
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
	cfg.Listener["0"] = &ctrld.ListenerConfig{
		IP:   "127.0.0.1",
		Port: 53,
		Policy: &ctrld.ListenerPolicyConfig{
			Name:  "My Policy",
			Rules: rules,
		},
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
		log.Fatalf("invalid listener address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("invalid port number: %v", err)
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
		mainLog.Fatal().Err(err).Msg("failed to get default route interface")
	}
	return dri
}

func selfCheckStatus(status service.Status) service.Status {
	c := new(dns.Client)
	bo := backoff.NewBackoff("self-check", logf, 10*time.Second)
	bo.LogLongerThan = 500 * time.Millisecond
	ctx := context.Background()
	err := errors.New("query failed")
	maxAttempts := 20
	mainLog.Debug().Msg("Performing self-check")
	for i := 0; i < maxAttempts; i++ {
		lc := cfg.Listener["0"]
		m := new(dns.Msg)
		m.SetQuestion(selfCheckFQDN+".", dns.TypeA)
		m.RecursionDesired = true
		r, _, _ := c.ExchangeContext(ctx, m, net.JoinHostPort(lc.IP, strconv.Itoa(lc.Port)))
		if r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
			mainLog.Debug().Msgf("self-check against %q succeeded", selfCheckFQDN)
			return status
		}
		bo.BackOff(ctx, err)
	}
	mainLog.Debug().Msgf("self-check against %q failed", selfCheckFQDN)
	return service.StatusUnknown
}
