package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/go-playground/validator/v10"
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

var (
	v                    = viper.NewWithOptions(viper.KeyDelimiter("::"))
	defaultConfigWritten = false
	defaultConfigFile    = "ctrld.toml"
)

var basicModeFlags = []string{"listen", "primary_upstream", "secondary_upstream", "domains", "log", "cache_size"}

func isNoConfigStart(cmd *cobra.Command) bool {
	for _, flagName := range basicModeFlags {
		if cmd.Flags().Lookup(flagName).Changed {
			return true
		}
	}
	return false
}

func initCLI() {
	// Enable opening via explorer.exe on Windows.
	// See: https://github.com/spf13/cobra/issues/844.
	cobra.MousetrapHelpText = ""

	rootCmd := &cobra.Command{
		Use:     "ctrld",
		Short:   "Running Control-D DNS proxy server",
		Version: "1.0.1",
	}
	rootCmd.PersistentFlags().CountVarP(
		&verbose,
		"verbose",
		"v",
		`verbose log output, "-v" means query logging enabled, "-vv" means debug level logging enabled`,
	)

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
			processCDFlags(writeDefaultConfig)
			if err := ctrld.ValidateConfig(validator.New(), &cfg); err != nil {
				log.Fatalf("invalid config: %v", err)
			}
			initLogging()
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
	runCmd.Flags().StringVarP(&configBase64, "base64_config", "", "", "base64 encoded config")
	runCmd.Flags().StringVarP(&listenAddress, "listen", "", "", "listener address and port, in format: address:port")
	runCmd.Flags().StringVarP(&primaryUpstream, "primary_upstream", "", "", "primary upstream endpoint")
	runCmd.Flags().StringVarP(&secondaryUpstream, "secondary_upstream", "", "", "secondary upstream endpoint")
	runCmd.Flags().StringSliceVarP(&domains, "domains", "", nil, "list of domain to apply in a split DNS policy")
	runCmd.Flags().StringVarP(&logPath, "log", "", "", "path to log file")
	runCmd.Flags().IntVarP(&cacheSize, "cache_size", "", 0, "Enable cache with size items")
	runCmd.Flags().StringVarP(&cdUID, "cd", "", "", "Control D resolver uid")

	rootCmd.AddCommand(runCmd)

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			sc := &service.Config{}
			*sc = *svcConfig
			osArgs := os.Args[2:]
			if os.Args[1] == "service" {
				osArgs = os.Args[3:]
			}
			sc.Arguments = append([]string{"run"}, osArgs...)
			if dir, err := os.UserHomeDir(); err == nil {
				// WorkingDirectory is not supported on Windows.
				sc.WorkingDirectory = dir
				// No config path, generating config in HOME directory.
				noConfigStart := isNoConfigStart(cmd)
				writeDefaultConfig := !noConfigStart && configBase64 == ""
				if configPath == "" && writeDefaultConfig {
					defaultConfigFile = filepath.Join(dir, defaultConfigFile)
					readConfigFile(true)
				}

				// On Windows, the service will be run as SYSTEM, so if ctrld start as Admin,
				// the written config won't be writable by SYSTEM account, we have to update
				// the config here when "--cd" is supplied.
				if runtime.GOOS == "windows" && cdUID != "" {
					if err := v.Unmarshal(&cfg); err != nil {
						log.Fatalf("failed to unmarshal config: %v", err)
					}
					processCDFlags(writeDefaultConfig)
				}
			}
			s, err := service.New(&prog{}, sc)
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
				stdoutMsg("Service started")
				return
			}
		},
	}
	// Keep these flags in sync with runCmd above, except for "-d".
	startCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")
	startCmd.Flags().StringVarP(&configBase64, "base64_config", "", "", "base64 encoded config")
	startCmd.Flags().StringVarP(&listenAddress, "listen", "", "", "listener address and port, in format: address:port")
	startCmd.Flags().StringVarP(&primaryUpstream, "primary_upstream", "", "", "primary upstream endpoint")
	startCmd.Flags().StringVarP(&secondaryUpstream, "secondary_upstream", "", "", "secondary upstream endpoint")
	startCmd.Flags().StringSliceVarP(&domains, "domains", "", nil, "list of domain to apply in a split DNS policy")
	startCmd.Flags().StringVarP(&logPath, "log", "", "", "path to log file")
	startCmd.Flags().IntVarP(&cacheSize, "cache_size", "", 0, "Enable cache with size items")
	startCmd.Flags().StringVarP(&cdUID, "cd", "", "", "Control D resolver uid")

	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			s, err := service.New(&prog{}, svcConfig)
			if err != nil {
				stderrMsg(err.Error())
				return
			}
			if doTasks([]task{{s.Stop, true}}) {
				stdoutMsg("Service stopped")
			}
		},
	}

	restartCmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			s, err := service.New(&prog{}, svcConfig)
			if err != nil {
				stderrMsg(err.Error())
				return
			}
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
				return
			}
			switch status {
			case service.StatusUnknown:
				stdoutMsg("Unknown status")
			case service.StatusRunning:
				stdoutMsg("Service is running")
			case service.StatusStopped:
				stdoutMsg("Service is stopped")
			}
		},
	}

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			s, err := service.New(&prog{}, svcConfig)
			if err != nil {
				stderrMsg(err.Error())
				return
			}
			tasks := []task{
				{s.Stop, false},
				{s.Uninstall, true},
			}
			if doTasks(tasks) {
				stdoutMsg("Service uninstalled")
				return
			}
		},
	}

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
		},
	}
	serviceCmd.AddCommand(startCmd)
	serviceCmd.AddCommand(stopCmd)
	serviceCmd.AddCommand(restartCmd)
	serviceCmd.AddCommand(statusCmd)
	serviceCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(serviceCmd)
	startCmdAlias := &cobra.Command{
		Use:   "start",
		Short: "Alias for service start",
		Run: func(cmd *cobra.Command, args []string) {
			startCmd.Run(cmd, args)
		},
	}
	startCmdAlias.Flags().AddFlagSet(startCmd.Flags())
	rootCmd.AddCommand(startCmdAlias)

	if err := rootCmd.Execute(); err != nil {
		stderrMsg(err.Error())
		os.Exit(1)
	}
}

func writeConfigFile() {
	if cfu := v.ConfigFileUsed(); cfu != "" {
		defaultConfigFile = cfu
	}
	if err := v.WriteConfigAs(defaultConfigFile); err != nil {
		log.Printf("failed to write config file: %v\n", err)
	}
}

func readConfigFile(writeDefaultConfig bool) bool {
	// If err == nil, there's a config supplied via `--config`, no default config written.
	err := v.ReadInConfig()
	if err == nil {
		fmt.Println("loading config file from: ", v.ConfigFileUsed())
		return true
	}

	if !writeDefaultConfig {
		return false
	}

	// If error is viper.ConfigFileNotFoundError, write default config.
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		writeConfigFile()
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

	processLogAndCacheFlags()
}

func processCDFlags(writeConfig bool) {
	if cdUID == "" {
		return
	}
	resolverConfig, err := controld.FetchResolverConfig(cdUID)
	if err != nil {
		log.Fatalf("failed to fetch resolver config: %v", err)
	}

	u0 := cfg.Upstream["0"]
	u0.Name = resolverConfig.DOH
	u0.Endpoint = resolverConfig.DOH
	u0.Type = ctrld.ResolverTypeDOH

	rules := make([]ctrld.Rule, 0, len(resolverConfig.Exclude))
	for _, domain := range resolverConfig.Exclude {
		rules = append(rules, ctrld.Rule{domain: []string{}})
	}
	cfg.Listener["0"].Policy = &ctrld.ListenerPolicyConfig{Name: "My Policy", Rules: rules}

	if writeConfig {
		v.Set("listener", cfg.Listener)
		v.Set("upstream", cfg.Upstream)
		writeConfigFile()
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
	sc := ctrld.ServiceConfig{}
	if logPath != "" {
		sc.LogLevel = "debug"
		sc.LogPath = logPath
	}

	if cacheSize != 0 {
		sc.CacheEnable = true
		sc.CacheSize = cacheSize
	}
	v.Set("service", sc)
}
