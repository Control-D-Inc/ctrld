package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/go-playground/validator/v10"
	"github.com/kardianos/service"
	"github.com/pelletier/go-toml"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Control-D-Inc/ctrld"
)

var (
	v                    = viper.NewWithOptions(viper.KeyDelimiter("::"))
	defaultConfigWritten = false
)

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

	basicModeFlags := []string{"listen", "primary_upstream", "secondary_upstream", "domains", "log"}
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the DNS proxy server",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if daemon && runtime.GOOS == "windows" {
				log.Fatal("Cannot run in daemon mode. Please install a Windows service.")
			}
			if configPath != "" {
				v.SetConfigFile(configPath)
			}
			noConfigStart := func() bool {
				for _, flagName := range basicModeFlags {
					if cmd.Flags().Lookup(flagName).Changed {
						return true
					}
				}
				return false
			}()

			readConfigFile(!noConfigStart && configBase64 == "")
			readBase64Config()
			processNoConfigFlags(noConfigStart)
			if err := v.Unmarshal(&cfg); err != nil {
				log.Fatalf("failed to unmarshal config: %v", err)
			}
			if err := ctrld.ValidateConfig(validator.New(), &cfg); err != nil {
				log.Fatalf("invalid config: %v", err)
			}
			initLogging()
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

	rootCmd.AddCommand(runCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func writeConfigFile() {
	c := v.AllSettings()
	bs, err := toml.Marshal(c)
	if err != nil {
		log.Fatalf("unable to marshal config to toml: %v", err)
	}
	if err := os.WriteFile("config.toml", bs, 0600); err != nil {
		log.Printf("failed to write config file: %v\n", err)
	}
}

func readConfigFile(configWritten bool) {
	err := v.ReadInConfig()
	if err == nil || !configWritten {
		return
	}
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		writeConfigFile()
		defaultConfigWritten = true
		return
	}
	log.Fatalf("failed to decode config file: %v", err)
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
		lc.Policy = &ctrld.ListenerPolicyConfig{Name: "My Policy", Rules: rules}
	}
	v.Set("upstream", upstream)

	if logPath != "" {
		v.Set("service", ctrld.ServiceConfig{LogLevel: "debug", LogPath: logPath})
	}
}
