package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"

	"github.com/kardianos/service"
	"github.com/pelletier/go-toml"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
		Version: "1.0.0",
	}
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose log output")

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
			if err := v.ReadInConfig(); err != nil {
				if _, ok := err.(viper.ConfigFileNotFoundError); ok {
					writeConfigFile()
					defaultConfigWritten = true
				} else {
					log.Fatalf("failed to decode config file: %v", err)
				}
			}
			if err := v.Unmarshal(&cfg); err != nil {
				log.Fatalf("failed to unmarshal config: %v", err)
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
