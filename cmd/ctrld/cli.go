package main

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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cuonglm/osinfo"
	"github.com/fsnotify/fsnotify"
	"github.com/go-playground/validator/v10"
	"github.com/kardianos/service"
	"github.com/miekg/dns"
	"github.com/olekukonko/tablewriter"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/interfaces"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/clientinfo"
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
			waitCh := make(chan struct{})
			stopCh := make(chan struct{})
			p := &prog{
				waitCh: waitCh,
				stopCh: stopCh,
				cfg:    &cfg,
			}
			if homedir == "" {
				if dir, err := userHomeDir(); err == nil {
					homedir = dir
				}
			}
			sockPath := filepath.Join(homedir, ctrldLogUnixSock)
			if addr, err := net.ResolveUnixAddr("unix", sockPath); err == nil {
				if conn, err := net.Dial(addr.Network(), addr.String()); err == nil {
					lc := &logConn{conn: conn}
					consoleWriter.Out = io.MultiWriter(os.Stdout, lc)
					p.logConn = lc
				}
			}

			if daemon && runtime.GOOS == "windows" {
				mainLog.Load().Fatal().Msg("Cannot run in daemon mode. Please install a Windows service.")
			}

			if !daemon {
				// We need to call s.Run() as soon as possible to response to the OS manager, so it
				// can see ctrld is running and don't mark ctrld as failed service.
				go func() {
					s, err := newService(p, svcConfig)
					if err != nil {
						mainLog.Load().Fatal().Err(err).Msg("failed create new service")
					}
					if err := s.Run(); err != nil {
						mainLog.Load().Error().Err(err).Msg("failed to start service")
					}
				}()
			}
			noConfigStart := isNoConfigStart(cmd)
			writeDefaultConfig := !noConfigStart && configBase64 == ""
			tryReadingConfig(writeDefaultConfig)

			readBase64Config(configBase64)
			processNoConfigFlags(noConfigStart)
			if err := v.Unmarshal(&cfg); err != nil {
				mainLog.Load().Fatal().Msgf("failed to unmarshal config: %v", err)
			}

			processLogAndCacheFlags()

			// Log config do not have thing to validate, so it's safe to init log here,
			// so it's able to log information in processCDFlags.
			initLogging()

			mainLog.Load().Info().Msgf("starting ctrld %s", curVersion())
			mainLog.Load().Info().Msgf("os: %s", osVersion())

			// Wait for network up.
			if !ctrldnet.Up() {
				mainLog.Load().Fatal().Msg("network is not up yet")
			}

			p.router = router.New(&cfg, cdUID != "")
			cs, err := newControlServer(filepath.Join(homedir, ctrldControlUnixSock))
			if err != nil {
				mainLog.Load().Warn().Err(err).Msg("could not create control server")
			}
			p.cs = cs

			// Processing --cd flag require connecting to ControlD API, which needs valid
			// time for validating server certificate. Some routers need NTP synchronization
			// to set the current time, so this check must happen before processCDFlags.
			if err := p.router.PreRun(); err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to perform router pre-run check")
			}

			oldLogPath := cfg.Service.LogPath
			if uid := cdUIDFromProvToken(); uid != "" {
				cdUID = uid
			}
			if cdUID != "" {
				processCDFlags()
			}

			updateListenerConfig()

			if cdUID != "" {
				processLogAndCacheFlags()
			}

			if err := writeConfigFile(); err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to write config file")
			} else {
				mainLog.Load().Info().Msg("writing config file to: " + defaultConfigFile)
			}

			if newLogPath := cfg.Service.LogPath; newLogPath != "" && oldLogPath != newLogPath {
				// After processCDFlags, log config may change, so reset mainLog and re-init logging.
				l := zerolog.New(io.Discard)
				mainLog.Store(&l)

				// Copy logs written so far to new log file if possible.
				if buf, err := os.ReadFile(oldLogPath); err == nil {
					if err := os.WriteFile(newLogPath, buf, os.FileMode(0o600)); err != nil {
						mainLog.Load().Warn().Err(err).Msg("could not copy old log file")
					}
				}
				initLoggingWithBackup(false)
			}

			validateConfig(&cfg)
			initCache()

			if daemon {
				exe, err := os.Executable()
				if err != nil {
					mainLog.Load().Error().Err(err).Msg("failed to find the binary")
					os.Exit(1)
				}
				curDir, err := os.Getwd()
				if err != nil {
					mainLog.Load().Error().Err(err).Msg("failed to get current working directory")
					os.Exit(1)
				}
				// If running as daemon, re-run the command in background, with daemon off.
				cmd := exec.Command(exe, append(os.Args[1:], "-d=false")...)
				cmd.Dir = curDir
				if err := cmd.Start(); err != nil {
					mainLog.Load().Error().Err(err).Msg("failed to start process as daemon")
					os.Exit(1)
				}
				mainLog.Load().Info().Int("pid", cmd.Process.Pid).Msg("DNS proxy started")
				os.Exit(0)
			}

			p.onStarted = append(p.onStarted, func() {
				for _, lc := range p.cfg.Listener {
					if shouldAllocateLoopbackIP(lc.IP) {
						if err := allocateIP(lc.IP); err != nil {
							mainLog.Load().Error().Err(err).Msgf("could not allocate IP: %s", lc.IP)
						}
					}
				}
			})
			p.onStopped = append(p.onStopped, func() {
				for _, lc := range p.cfg.Listener {
					if shouldAllocateLoopbackIP(lc.IP) {
						if err := deAllocateIP(lc.IP); err != nil {
							mainLog.Load().Error().Err(err).Msgf("could not de-allocate IP: %s", lc.IP)
						}
					}
				}
			})
			if platform := router.Name(); platform != "" {
				if cp := router.CertPool(); cp != nil {
					rootCertPool = cp
				}
				p.onStarted = append(p.onStarted, func() {
					mainLog.Load().Debug().Msg("router setup on start")
					if err := p.router.Setup(); err != nil {
						mainLog.Load().Error().Err(err).Msg("could not configure router")
					}
				})
				p.onStopped = append(p.onStopped, func() {
					mainLog.Load().Debug().Msg("router cleanup on stop")
					if err := p.router.Cleanup(); err != nil {
						mainLog.Load().Error().Err(err).Msg("could not cleanup router")
					}
					p.resetDNS()
				})
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
	runCmd.Flags().StringVarP(&cdOrg, "cd-org", "", "", "Control D provision token")
	runCmd.Flags().BoolVarP(&cdDev, "dev", "", false, "Use Control D dev resolver/domain")
	_ = runCmd.Flags().MarkHidden("dev")
	runCmd.Flags().StringVarP(&homedir, "homedir", "", "", "")
	_ = runCmd.Flags().MarkHidden("homedir")
	runCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)
	_ = runCmd.Flags().MarkHidden("iface")

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
			if cdUID != "" {
				if _, err := controld.FetchResolverConfig(cdUID, rootCmd.Version, cdDev); err != nil {
					mainLog.Load().Fatal().Err(err).Msgf("failed to fetch resolver uid: %s", cdUID)
				}
			} else if uid := cdUIDFromProvToken(); uid != "" {
				cdUID = uid
				removeProvTokenFromArgs(sc)
				// Pass --cd flag to "ctrld run" command, so the provision token takes no effect.
				sc.Arguments = append(sc.Arguments, "--cd="+cdUID)
			}

			p := &prog{
				router: router.New(&cfg, cdUID != ""),
				cfg:    &cfg,
			}
			if err := p.router.ConfigureService(sc); err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to configure service on router")
			}

			// No config path, generating config in HOME directory.
			noConfigStart := isNoConfigStart(cmd)
			writeDefaultConfig := !noConfigStart && configBase64 == ""
			if configPath != "" {
				v.SetConfigFile(configPath)
			}

			// A buffer channel to gather log output from runCmd and report
			// to user in case self-check process failed.
			runCmdLogCh := make(chan string, 256)
			if dir, err := userHomeDir(); err == nil {
				setWorkingDirectory(sc, dir)
				if configPath == "" && writeDefaultConfig {
					defaultConfigFile = filepath.Join(dir, defaultConfigFile)
				}
				sc.Arguments = append(sc.Arguments, "--homedir="+dir)
				sockPath := filepath.Join(dir, ctrldLogUnixSock)
				_ = os.Remove(sockPath)
				go func() {
					defer func() {
						close(runCmdLogCh)
						_ = os.Remove(sockPath)
					}()
					if conn := runLogServer(sockPath); conn != nil {
						// Enough buffer for log message, we don't produce
						// such long log message, but just in case.
						buf := make([]byte, 1024)
						for {
							n, err := conn.Read(buf)
							if err != nil {
								return
							}
							runCmdLogCh <- string(buf[:n])
						}
					}
				}()
			}

			tryReadingConfig(writeDefaultConfig)

			if err := v.Unmarshal(&cfg); err != nil {
				mainLog.Load().Fatal().Msgf("failed to unmarshal config: %v", err)
			}

			initLogging()

			// Explicitly passing config, so on system where home directory could not be obtained,
			// or sub-process env is different with the parent, we still behave correctly and use
			// the expected config file.
			if configPath == "" {
				sc.Arguments = append(sc.Arguments, "--config="+defaultConfigFile)
			}

			s, err := newService(p, sc)
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
				return
			}

			if router.Name() != "" {
				mainLog.Load().Debug().Msg("cleaning up router before installing")
				_ = p.router.Cleanup()
			}

			tasks := []task{
				{s.Stop, false},
				{s.Uninstall, false},
				{s.Install, false},
				{s.Start, true},
			}
			if doTasks(tasks) {
				if err := p.router.Install(sc); err != nil {
					mainLog.Load().Warn().Err(err).Msg("post installation failed, please check system/service log for details error")
					return
				}

				status := selfCheckStatus(s)
				switch status {
				case service.StatusRunning:
					mainLog.Load().Notice().Msg("Service started")
				default:
					marker := bytes.Repeat([]byte("="), 32)
					mainLog.Load().Error().Msg("ctrld service may not have started due to an error or misconfiguration, service log:")
					_, _ = mainLog.Load().Write(marker)
					for msg := range runCmdLogCh {
						_, _ = mainLog.Load().Write([]byte(msg))
					}
					_, _ = mainLog.Load().Write(marker)
					uninstall(p, s)
					os.Exit(1)
				}
				// On Linux, Darwin, Freebsd, ctrld set DNS on startup, because the DNS setting could be
				// reset after rebooting. On windows, we only need to set once here. See prog.preRun in
				// prog_*.go file for dedicated code on each platform.
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
	startCmd.Flags().StringVarP(&cdOrg, "cd-org", "", "", "Control D provision token")
	startCmd.Flags().BoolVarP(&cdDev, "dev", "", false, "Use Control D dev resolver/domain")
	_ = startCmd.Flags().MarkHidden("dev")
	startCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)

	routerCmd := &cobra.Command{
		Use: "setup",
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
		},
		Run: func(cmd *cobra.Command, _ []string) {
			exe, err := os.Executable()
			if err != nil {
				mainLog.Load().Fatal().Msgf("could not find executable path: %v", err)
				os.Exit(1)
			}
			flags := make([]string, 0)
			cmd.Flags().Visit(func(flag *pflag.Flag) {
				flags = append(flags, fmt.Sprintf("--%s=%s", flag.Name, flag.Value))
			})
			cmdArgs := []string{"start"}
			cmdArgs = append(cmdArgs, flags...)
			command := exec.Command(exe, cmdArgs...)
			command.Stdout = os.Stdout
			command.Stderr = os.Stderr
			command.Stdin = os.Stdin
			if err := command.Run(); err != nil {
				mainLog.Load().Fatal().Msg(err.Error())
			}
		},
	}
	routerCmd.Flags().AddFlagSet(startCmd.Flags())
	routerCmd.Hidden = true
	rootCmd.AddCommand(routerCmd)

	stopCmd := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Use:   "stop",
		Short: "Stop the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			readConfig(false)
			v.Unmarshal(&cfg)
			p := &prog{router: router.New(&cfg, cdUID != "")}
			s, err := newService(p, svcConfig)
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
				return
			}
			initLogging()
			if doTasks([]task{{s.Stop, true}}) {
				p.router.Cleanup()
				p.resetDNS()
				mainLog.Load().Notice().Msg("Service stopped")
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
				mainLog.Load().Error().Msg(err.Error())
				return
			}
			initLogging()
			if doTasks([]task{{s.Restart, true}}) {
				mainLog.Load().Notice().Msg("Service restarted")
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
				mainLog.Load().Error().Msg(err.Error())
				return
			}
			status, err := s.Status()
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
				os.Exit(1)
			}
			switch status {
			case service.StatusUnknown:
				mainLog.Load().Notice().Msg("Unknown status")
				os.Exit(2)
			case service.StatusRunning:
				mainLog.Load().Notice().Msg("Service is running")
				os.Exit(0)
			case service.StatusStopped:
				mainLog.Load().Notice().Msg("Service is stopped")
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
			readConfig(false)
			v.Unmarshal(&cfg)
			p := &prog{router: router.New(&cfg, cdUID != "")}
			s, err := newService(p, svcConfig)
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
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
				mainLog.Load().Error().Msg(err.Error())
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

	restartCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Use:   "restart",
		Short: "Restart the ctrld service",
		Run: func(cmd *cobra.Command, args []string) {
			restartCmd.Run(cmd, args)
		},
	}
	rootCmd.AddCommand(restartCmdAlias)

	statusCmdAlias := &cobra.Command{
		Use:   "status",
		Short: "Show status of the ctrld service",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
		},
		Run: statusCmd.Run,
	}
	rootCmd.AddCommand(statusCmdAlias)

	uninstallCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Use:   "uninstall",
		Short: "Stop and uninstall the ctrld service",
		Long: `Stop and uninstall the ctrld service.

NOTE: Uninstalling will set DNS to values provided by DHCP.`,
		Run: func(cmd *cobra.Command, args []string) {
			if !cmd.Flags().Changed("iface") {
				os.Args = append(os.Args, "--iface="+ifaceStartStop)
			}
			iface = ifaceStartStop
			uninstallCmd.Run(cmd, args)
		},
	}
	uninstallCmdAlias.Flags().StringVarP(&ifaceStartStop, "iface", "", "auto", `Reset DNS setting for iface, "auto" means the default interface gateway`)
	uninstallCmdAlias.Flags().AddFlagSet(stopCmd.Flags())
	rootCmd.AddCommand(uninstallCmdAlias)

	listClientsCmd := &cobra.Command{
		Use:   "list",
		Short: "List clients that ctrld discovered",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Run: func(cmd *cobra.Command, args []string) {
			dir, err := userHomeDir()
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to find ctrld home dir")
			}
			cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
			resp, err := cc.post(listClientsPath, nil)
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to get clients list")
			}
			defer resp.Body.Close()

			var clients []*clientinfo.Client
			if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to decode clients list result")
			}
			map2Slice := func(m map[string]struct{}) []string {
				s := make([]string, 0, len(m))
				for k := range m {
					s = append(s, k)
				}
				sort.Strings(s)
				return s
			}
			data := make([][]string, len(clients))
			for i, c := range clients {
				row := []string{
					c.IP.String(),
					c.Hostname,
					c.Mac,
					strings.Join(map2Slice(c.Source), ","),
				}
				data[i] = row
			}
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"IP", "Hostname", "Mac", "Discovered"})
			table.SetAutoFormatHeaders(false)
			table.AppendBulk(data)
			table.Render()
		},
	}
	clientsCmd := &cobra.Command{
		Use:   "clients",
		Short: "Manage clients",
		Args:  cobra.OnlyValidArgs,
		ValidArgs: []string{
			listClientsCmd.Use,
		},
	}
	clientsCmd.AddCommand(listClientsCmd)
	rootCmd.AddCommand(clientsCmd)
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
		mainLog.Load().Info().Msg("loading config file from: " + v.ConfigFileUsed())
		defaultConfigFile = v.ConfigFileUsed()
		return true
	}

	if !writeDefaultConfig {
		return false
	}

	// If error is viper.ConfigFileNotFoundError, write default config.
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		if err := v.Unmarshal(&cfg); err != nil {
			mainLog.Load().Fatal().Msgf("failed to unmarshal default config: %v", err)
		}
		if err := writeConfigFile(); err != nil {
			mainLog.Load().Fatal().Msgf("failed to write default config file: %v", err)
		} else {
			fp, err := filepath.Abs(defaultConfigFile)
			if err != nil {
				mainLog.Load().Fatal().Msgf("failed to get default config file path: %v", err)
			}
			mainLog.Load().Info().Msg("writing default config file to: " + fp)
		}
		defaultConfigWritten = true
		return false
	}

	if _, ok := err.(viper.ConfigParseError); ok {
		if f, _ := os.Open(v.ConfigFileUsed()); f != nil {
			var i any
			if err, ok := toml.NewDecoder(f).Decode(&i).(*toml.DecodeError); ok {
				row, col := err.Position()
				mainLog.Load().Fatal().Msgf("failed to decode config file at line: %d, column: %d, error: %v", row, col, err)
			}
		}
	}

	// Otherwise, report fatal error and exit.
	mainLog.Load().Fatal().Msgf("failed to decode config file: %v", err)
	return false
}

func readBase64Config(configBase64 string) {
	if configBase64 == "" {
		return
	}
	configStr, err := base64.StdEncoding.DecodeString(configBase64)
	if err != nil {
		mainLog.Load().Fatal().Msgf("invalid base64 config: %v", err)
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
		mainLog.Load().Fatal().Msgf("failed to read base64 config: %v", err)
	}
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
	logger := mainLog.Load().With().Str("mode", "cd").Logger()
	logger.Info().Msgf("fetching Controld D configuration from API: %s", cdUID)
	bo := backoff.NewBackoff("processCDFlags", logf, 30*time.Second)
	bo.LogLongerThan = 30 * time.Second
	ctx := context.Background()
	resolverConfig, err := controld.FetchResolverConfig(cdUID, rootCmd.Version, cdDev)
	for {
		if errUrlNetworkError(err) {
			bo.BackOff(ctx, err)
			logger.Warn().Msg("could not fetch resolver using bootstrap DNS, retrying...")
			resolverConfig, err = controld.FetchResolverConfig(cdUID, rootCmd.Version, cdDev)
			continue
		}
		break
	}
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
	cfg = ctrld.Config{}

	// Fetch config, unmarshal to cfg.
	if resolverConfig.Ctrld.CustomConfig != "" {
		logger.Info().Msg("using defined custom config of Control-D resolver")
		readBase64Config(resolverConfig.Ctrld.CustomConfig)
		if err := v.Unmarshal(&cfg); err != nil {
			mainLog.Load().Fatal().Msgf("failed to unmarshal config: %v", err)
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
			Policy: &ctrld.ListenerPolicyConfig{
				Name:  "My Policy",
				Rules: rules,
			},
		}
		cfg.Listener["0"] = lc
	}
	// Set default value.
	if len(cfg.Listener) == 0 {
		cfg.Listener = map[string]*ctrld.ListenerConfig{
			"0": {IP: "", Port: 0},
		}
	}
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
	if ifaceName := router.DefaultInterfaceName(); ifaceName != "" {
		return ifaceName
	}
	dri, err := interfaces.DefaultRouteInterface()
	if err != nil {
		// On WSL 1, the route table does not have any default route. But the fact that
		// it only uses /etc/resolv.conf for setup DNS, so we can use "lo" here.
		if oi := osinfo.New(); strings.Contains(oi.String(), "Microsoft") {
			return "lo"
		}
		mainLog.Load().Fatal().Err(err).Msg("failed to get default route interface")
	}
	return dri
}

func selfCheckStatus(s service.Service) service.Status {
	status, err := s.Status()
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not get service status")
		return status
	}
	// If ctrld is not running, do nothing, just return the status as-is.
	if status != service.StatusRunning {
		return status
	}
	dir, err := userHomeDir()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to check ctrld listener status: could not get home directory")
		return service.StatusUnknown
	}

	bo := backoff.NewBackoff("self-check", logf, 10*time.Second)
	bo.LogLongerThan = 10 * time.Second
	ctx := context.Background()

	mainLog.Load().Debug().Msg("waiting for ctrld listener to be ready")
	cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))

	// The socket control server may not start yet, so attempt to ping
	// it until we got a response. For each iteration, check ctrld status
	// to make sure ctrld is still running.
	for {
		curStatus, err := s.Status()
		if err != nil {
			mainLog.Load().Warn().Err(err).Msg("could not get service status while doing self-check")
			return status
		}
		if curStatus != service.StatusRunning {
			return curStatus
		}
		if _, err := cc.post("/", nil); err != nil {
			// Do not count attempt if the server is not ready yet.
			if errUrlConnRefused(err) {
				bo.BackOff(ctx, err)
				continue
			}
			mainLog.Load().Warn().Err(err).Msg("could not ping socket control server")
			return service.StatusUnknown
		}
		break
	}
	resp, err := cc.post(startedPath, nil)
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to connect to control server")
		return service.StatusUnknown
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		mainLog.Load().Error().Msg("ctrld listener is not ready")
		return service.StatusUnknown
	}

	mainLog.Load().Debug().Msg("ctrld listener is ready")
	mainLog.Load().Debug().Msg("performing self-check")
	bo = backoff.NewBackoff("self-check", logf, 10*time.Second)
	bo.LogLongerThan = 500 * time.Millisecond
	maxAttempts := 20
	c := new(dns.Client)
	var (
		lcChanged map[string]*ctrld.ListenerConfig
		ucChanged map[string]*ctrld.UpstreamConfig
		mu        sync.Mutex
	)

	if err := v.ReadInConfig(); err != nil {
		mainLog.Load().Fatal().Err(err).Msg("failed to read new config")
	}
	if err := v.Unmarshal(&cfg); err != nil {
		mainLog.Load().Fatal().Err(err).Msg("failed to update new config")
	}
	domain := cfg.FirstUpstream().VerifyDomain()
	if domain == "" {
		// Nothing to do, return the status as-is.
		return status
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("could not watch config change")
		return service.StatusUnknown
	}
	defer watcher.Close()

	v.OnConfigChange(func(in fsnotify.Event) {
		mu.Lock()
		defer mu.Unlock()
		if err := v.UnmarshalKey("listener", &lcChanged); err != nil {
			mainLog.Load().Error().Msgf("failed to unmarshal listener config: %v", err)
			return
		}
		if err := v.UnmarshalKey("upstream", &ucChanged); err != nil {
			mainLog.Load().Error().Msgf("failed to unmarshal upstream config: %v", err)
			return
		}
	})
	v.WatchConfig()
	var (
		lastAnswer *dns.Msg
		lastErr    error
	)
	for i := 0; i < maxAttempts; i++ {
		mu.Lock()
		if lcChanged != nil {
			cfg.Listener = lcChanged
		}
		if ucChanged != nil {
			cfg.Upstream = ucChanged
		}
		mu.Unlock()
		lc := cfg.FirstListener()
		domain = cfg.FirstUpstream().VerifyDomain()
		if domain == "" {
			continue
		}

		m := new(dns.Msg)
		m.SetQuestion(domain+".", dns.TypeA)
		m.RecursionDesired = true
		r, _, err := c.ExchangeContext(ctx, m, net.JoinHostPort(lc.IP, strconv.Itoa(lc.Port)))
		if r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
			mainLog.Load().Debug().Msgf("self-check against %q succeeded", domain)
			return status
		}
		lastAnswer = r
		lastErr = err
		bo.BackOff(ctx, fmt.Errorf("ExchangeContext: %w", err))
	}
	mainLog.Load().Debug().Msgf("self-check against %q failed", domain)
	lc := cfg.FirstListener()
	addr := net.JoinHostPort(lc.IP, strconv.Itoa(lc.Port))
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
		mainLog.Load().Debug().Msg(marker)
	}
	return service.StatusUnknown
}

func userHomeDir() (string, error) {
	dir, err := router.HomeDir()
	if err != nil {
		return "", err
	}
	if dir != "" {
		return dir, nil
	}
	// viper will expand for us.
	if runtime.GOOS == "windows" {
		return os.UserHomeDir()
	}
	dir = "/etc/controld"
	if err := os.MkdirAll(dir, 0750); err != nil {
		return os.UserHomeDir() // fallback to user home directory
	}
	if ok, _ := dirWritable(dir); !ok {
		return os.UserHomeDir()
	}
	return dir, nil
}

func tryReadingConfig(writeDefaultConfig bool) {
	// --config is specified.
	if configPath != "" {
		v.SetConfigFile(configPath)
		readConfigFile(false)
		return
	}
	// no config start or base64 config mode.
	if !writeDefaultConfig {
		return
	}
	readConfig(writeDefaultConfig)
}

func readConfig(writeDefaultConfig bool) {
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
		if err := p.router.ConfigureService(svcConfig); err != nil {
			mainLog.Load().Fatal().Err(err).Msg("could not configure service")
		}
		if err := p.router.Uninstall(svcConfig); err != nil {
			mainLog.Load().Warn().Err(err).Msg("post uninstallation failed, please check system/service log for details error")
			return
		}
		p.resetDNS()
		if router.Name() != "" {
			mainLog.Load().Debug().Msg("Router cleanup")
		}
		// Stop already did router.Cleanup and report any error if happens,
		// ignoring error here to prevent false positive.
		_ = p.router.Cleanup()
		mainLog.Load().Notice().Msg("Service uninstalled")
		return
	}
}

func validateConfig(cfg *ctrld.Config) {
	err := ctrld.ValidateConfig(validator.New(), cfg)
	if err == nil {
		return
	}
	var ve validator.ValidationErrors
	if errors.As(err, &ve) {
		for _, fe := range ve {
			mainLog.Load().Error().Msgf("invalid config: %s: %s", fe.Namespace(), fieldErrorMsg(fe))
		}
	}
	os.Exit(1)
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
		return fmt.Sprintf("value is required")
	case "dnsrcode":
		return fmt.Sprintf("invalid DNS rcode value: %s", fe.Value())
	case "ipstack":
		ipStacks := []string{ctrld.IpStackV4, ctrld.IpStackV6, ctrld.IpStackSplit, ctrld.IpStackBoth}
		return fmt.Sprintf("must be one of: %q", strings.Join(ipStacks, " "))
	case "iporempty":
		return fmt.Sprintf("invalid IP format: %s", fe.Value())
	case "file":
		return fmt.Sprintf("filed does not exist: %s", fe.Value())
	}
	return ""
}

// couldBeDirectListener reports whether ctrld can be a direct listener on port 53.
// It returns true only if ctrld can listen on port 53 for all interfaces. That means
// there's no other software listening on port 53.
//
// If someone listening on port 53, or ctrld could only listen on port 53 for a specific
// interface, ctrld could only be configured as a DNS forwarder.
func couldBeDirectListener(lc *ctrld.ListenerConfig) bool {
	if lc == nil || lc.Port != 53 {
		return false
	}
	switch lc.IP {
	case "", "::", "0.0.0.0":
		return true
	default:
		return false
	}

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

// updateListenerConfig updates the config for listeners if not defined,
// or defined but invalid to be used, e.g: using loopback address other
// than 127.0.0.1 with sytemd-resolved.
func updateListenerConfig() {
	lcc := make(map[string]*listenerConfigCheck)
	cdMode := cdUID != ""
	for n, listener := range cfg.Listener {
		lcc[n] = &listenerConfigCheck{}
		if listener.IP == "" {
			listener.IP = "0.0.0.0"
			lcc[n].IP = true
		}
		if listener.Port == 0 {
			listener.Port = 53
			lcc[n].Port = true
		}
		// In cd mode, we always try to pick an ip:port pair to work.
		if cdMode {
			lcc[n].IP = true
			lcc[n].Port = true
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

	logMsg := func(e *zerolog.Event, listenerNum int, format string, v ...any) {
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
		tryLocalhost := !isLoopback(listener.IP) && router.CanListenLocalhost()
		tryAllPort53 := true
		tryOldIPPort5354 := true
		tryPort5354 := true
		attempts := 0
		maxAttempts := 10
		for {
			if attempts == maxAttempts {
				logMsg(mainLog.Load().Fatal(), n, "could not find available listen ip and port")
			}
			addr := net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port))
			err := tryListen(addr)
			if err == nil {
				break
			}
			if !check.IP && !check.Port {
				logMsg(mainLog.Load().Fatal(), n, "failed to listen: %v", err)
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
					logMsg(mainLog.Load().Warn(), n, "could not listen on address: %s, trying: %s", addr, net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port)))
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
					logMsg(mainLog.Load().Warn(), n, "could not listen on address: %s, trying localhost: %s", addr, net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port)))
				}
				continue
			}
			if tryOldIPPort5354 {
				tryOldIPPort5354 = false
				if check.IP {
					listener.IP = oldIP
				}
				if check.Port {
					listener.Port = 5354
				}
				logMsg(mainLog.Load().Warn(), n, "could not listen on address: %s, trying current ip with port 5354", addr)
				continue
			}
			if tryPort5354 {
				tryPort5354 = false
				if check.IP {
					listener.IP = "0.0.0.0"
				}
				if check.Port {
					listener.Port = 5354
				}
				logMsg(mainLog.Load().Warn(), n, "could not listen on address: %s, trying 0.0.0.0:5354", addr)
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
				logMsg(mainLog.Load().Fatal(), n, "could not listener on %s: %v", net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port)), err)
			}
			logMsg(mainLog.Load().Warn(), n, "could not listen on address: %s, pick a random ip+port", addr)
			attempts++
		}
	}

	// Specific case for systemd-resolved.
	if useSystemdResolved {
		if listener := cfg.FirstListener(); listener != nil && listener.Port == 53 {
			n := listeners[0]
			// systemd-resolved does not allow forwarding DNS queries from 127.0.0.53 to loopback
			// ip address, other than "127.0.0.1", so trying to listen on default route interface
			// address instead.
			if ip := net.ParseIP(listener.IP); ip != nil && ip.IsLoopback() && ip.String() != "127.0.0.1" {
				logMsg(mainLog.Load().Warn(), n, "using loopback interface do not work with systemd-resolved")
				found := false
				if netIface, _ := net.InterfaceByName(defaultIfaceName()); netIface != nil {
					addrs, _ := netIface.Addrs()
					for _, addr := range addrs {
						if netIP, ok := addr.(*net.IPNet); ok && netIP.IP.To4() != nil {
							addr := net.JoinHostPort(netIP.IP.String(), strconv.Itoa(listener.Port))
							if err := tryListen(addr); err == nil {
								found = true
								listener.IP = netIP.IP.String()
								logMsg(mainLog.Load().Warn(), n, "use %s as listener address", listener.IP)
								break
							}
						}
					}
				}
				if !found {
					logMsg(mainLog.Load().Fatal(), n, "could not use %q as DNS nameserver with systemd resolved", listener.IP)
				}
			}
		}
	}
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
	// Process provision token if provided.
	resolverConfig, err := controld.FetchResolverUID(cdOrg, rootCmd.Version, cdDev)
	if err != nil {
		mainLog.Load().Fatal().Err(err).Msgf("failed to fetch resolver uid with provision token: %s", cdOrg)
	}
	return resolverConfig.UID
}

// removeProvTokenFromArgs removes the --cd-org from command line arguments.
func removeProvTokenFromArgs(sc *service.Config) {
	a := sc.Arguments[:0]
	skip := false
	for _, x := range sc.Arguments {
		if skip {
			skip = false
			continue
		}
		// For "--cd-org XXX", skip it and mark next arg skipped.
		if x == "--cd-org" {
			skip = true
			continue
		}
		// For "--cd-org=XXX", just skip it.
		if strings.HasPrefix(x, "--cd-org=") {
			continue
		}
		a = append(a, x)
	}
	sc.Arguments = a
}
