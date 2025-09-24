package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/Control-D-Inc/ctrld"
)

// Start implements the logic from cmdStart.Run
func (sc *ServiceCommand) Start(cmd *cobra.Command, args []string) error {
	logger := mainLog.Load()
	logger.Debug().Msg("Service start command started")

	checkStrFlagEmpty(cmd, cdUidFlagName)
	checkStrFlagEmpty(cmd, cdOrgFlagName)
	validateCdAndNextDNSFlags()

	svcConfig := sc.createServiceConfig()
	osArgs := os.Args[2:]
	osArgs = filterEmptyStrings(osArgs)
	if os.Args[1] == "service" {
		osArgs = os.Args[3:]
	}
	setDependencies(svcConfig)
	svcConfig.Arguments = append([]string{"run"}, osArgs...)

	// Initialize service manager with proper configuration
	s, p, err := sc.initializeServiceManagerWithServiceConfig(svcConfig)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to initialize service manager")
		return err
	}

	p.cfg = &cfg
	p.preRun()

	status, err := s.Status()
	isCtrldRunning := status == service.StatusRunning
	isCtrldInstalled := !errors.Is(err, service.ErrNotInstalled)

	// Get current running iface, if any.
	var currentIface *ifaceResponse

	// If pin code was set, do not allow running start command.
	if isCtrldRunning {
		if err := checkDeactivationPin(s, nil); isCheckDeactivationPinErr(err) {
			logger.Error().Msg("Deactivation pin check failed")
			os.Exit(deactivationPinInvalidExitCode)
		}
		currentIface = runningIface(s)
		logger.Debug().Msgf("Current interface on start: %v", currentIface)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reportSetDnsOk := func(sockDir string) {
		if cc := newSocketControlClient(ctx, s, sockDir); cc != nil {
			if resp, _ := cc.post(ifacePath, nil); resp != nil && resp.StatusCode == http.StatusOK {
				if iface == "auto" {
					iface = defaultIfaceName()
				}
				res := &ifaceResponse{}
				if err := json.NewDecoder(resp.Body).Decode(res); err != nil {
					logger.Warn().Err(err).Msg("Failed to get iface info")
					return
				}
				if res.OK {
					name := res.Name
					if iff, err := net.InterfaceByName(name); err == nil {
						_, _ = patchNetIfaceName(iff)
						name = iff.Name
					}
					logger := logger.With().Str("iface", name)
					logger.Debug().Msg("Setting DNS successfully")
					if res.All {
						// Log that DNS is set for other interfaces.
						withEachPhysicalInterfaces(
							name,
							"set DNS",
							func(i *net.Interface) error { return nil },
						)
					}
				}
			}
		}
	}

	// No config path, generating config in HOME directory.
	noConfigStart := isNoConfigStart(cmd)
	writeDefaultConfig := !noConfigStart && configBase64 == ""

	logServerStarted := make(chan struct{})
	stopLogCh := make(chan struct{})
	ud, err := userHomeDir()
	sockDir := ud
	var logServerSocketPath string
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get user home directory")
		logger.Warn().Msg("Log server did not start")
		close(logServerStarted)
	} else {
		setWorkingDirectory(svcConfig, ud)
		if configPath == "" && writeDefaultConfig {
			defaultConfigFile = filepath.Join(ud, defaultConfigFile)
		}
		svcConfig.Arguments = append(svcConfig.Arguments, "--homedir="+ud)
		if d, err := socketDir(); err == nil {
			sockDir = d
		}
		logServerSocketPath = filepath.Join(sockDir, ctrldLogUnixSock)
		_ = os.Remove(logServerSocketPath)
		go func() {
			defer os.Remove(logServerSocketPath)

			close(logServerStarted)

			// Start HTTP log server
			if err := httpLogServer(logServerSocketPath, stopLogCh); err != nil && err != http.ErrServerClosed {
				logger.Warn().Err(err).Msg("Failed to serve HTTP log server")
				return
			}
		}()
	}
	<-logServerStarted

	if !startOnly {
		startOnly = len(osArgs) == 0
	}
	// If user run "ctrld start" and ctrld is already installed, starting existing service.
	if startOnly && isCtrldInstalled {
		tryReadingConfigWithNotice(false, true)
		if err := v.Unmarshal(&cfg); err != nil {
			logger.Fatal().Msgf("Failed to unmarshal config: %v", err)
		}

		// if already running, dont restart
		if isCtrldRunning {
			logger.Notice().Msg("Service is already running")
			return nil
		}

		initInteractiveLogging()
		tasks := []task{
			{func() error {
				// Save current DNS so we can restore later.
				withEachPhysicalInterfaces("", "saveCurrentStaticDNS", func(i *net.Interface) error {
					if err := saveCurrentStaticDNS(i); !errors.Is(err, errSaveCurrentStaticDNSNotSupported) && err != nil {
						return err
					}
					return nil
				})
				return nil
			}, false, "Save current DNS"},
			{func() error {
				return ConfigureWindowsServiceFailureActions(ctrldServiceName)
			}, false, "Configure service failure actions"},
			{s.Start, true, "Start"},
			{noticeWritingControlDConfig, false, "Notice writing ControlD config"},
		}
		logger.Notice().Msg("Starting existing ctrld service")
		if doTasks(tasks) {
			logger.Notice().Msg("Service started")
			sockDir, err := socketDir()
			if err != nil {
				logger.Warn().Err(err).Msg("Failed to get socket directory")
				os.Exit(1)
			}
			reportSetDnsOk(sockDir)
		} else {
			logger.Error().Err(err).Msg("Failed to start existing ctrld service")
			os.Exit(1)
		}
		return nil
	}

	if cdUID != "" {
		_ = doValidateCdRemoteConfig(cdUID, true)
	} else if uid := cdUIDFromProvToken(); uid != "" {
		cdUID = uid
		logger.Debug().Msg("Using uid from provision token")
		removeOrgFlagsFromArgs(svcConfig)
		// Pass --cd flag to "ctrld run" command, so the provision token takes no effect.
		svcConfig.Arguments = append(svcConfig.Arguments, "--cd="+cdUID)
	}
	if cdUID != "" {
		validateCdUpstreamProtocol()
	}

	if configPath != "" {
		v.SetConfigFile(configPath)
	}

	tryReadingConfigWithNotice(writeDefaultConfig, true)

	if err := v.Unmarshal(&cfg); err != nil {
		logger.Fatal().Msgf("Failed to unmarshal config: %v", err)
	}

	initInteractiveLogging()

	if nextdns != "" {
		removeNextDNSFromArgs(svcConfig)
	}

	// Explicitly passing config, so on system where home directory could not be obtained,
	// or sub-process env is different with the parent, we still behave correctly and use
	// the expected config file.
	if configPath == "" {
		svcConfig.Arguments = append(svcConfig.Arguments, "--config="+defaultConfigFile)
	}

	tasks := []task{
		{s.Stop, false, "Stop"},
		{func() error { return doGenerateNextDNSConfig(nextdns) }, true, "Checking config"},
		{func() error { return ensureUninstall(s) }, false, "Ensure uninstall"},
		//resetDnsTask(p, s, isCtrldInstalled, currentIface),
		{func() error {
			// Save current DNS so we can restore later.
			withEachPhysicalInterfaces("", "saveCurrentStaticDNS", func(i *net.Interface) error {
				if err := saveCurrentStaticDNS(i); !errors.Is(err, errSaveCurrentStaticDNSNotSupported) && err != nil {
					return err
				}
				return nil
			})
			return nil
		}, false, "Save current DNS"},
		{s.Install, false, "Install"},
		{func() error {
			return ConfigureWindowsServiceFailureActions(ctrldServiceName)
		}, false, "Configure Windows service failure actions"},
		{s.Start, true, "Start"},
		// Note that startCmd do not actually write ControlD config, but the config file was
		// generated after s.Start, so we notice users here for consistent with nextdns mode.
		{noticeWritingControlDConfig, false, "Notice writing ControlD config"},
	}
	logger.Notice().Msg("Starting service")
	if doTasks(tasks) {
		// add a small delay to ensure the service is started and did not crash
		time.Sleep(1 * time.Second)

		ok, status, err := selfCheckStatus(ctx, s, sockDir)
		switch {
		case ok && status == service.StatusRunning:
			logger.Notice().Msg("Service started")
		default:
			marker := append(bytes.Repeat([]byte("="), 32), '\n')
			// If ctrld service is not running, emitting log obtained from ctrld process.
			if status != service.StatusRunning || ctx.Err() != nil {
				logger.Error().Msg("Ctrld service may not have started due to an error or misconfiguration, service log:")
				_, _ = logger.Write(marker)

				// Wait for log collection to complete
				<-stopLogCh

				// Retrieve logs from HTTP server if available
				if logServerSocketPath != "" {
					hlc := newHTTPLogClient(logServerSocketPath)
					logs, err := hlc.GetLogs()
					if err != nil {
						logger.Warn().Err(err).Msg("Failed to get logs from HTTP log server")
					}
					if len(logs) == 0 {
						logger.Write([]byte(`<no log output is obtained from ctrld process>`))
					} else {
						logger.Write(logs)
					}
				} else {
					logger.Write([]byte(`<no log output from HTTP log server>`))
				}
			}
			// Report any error if occurred.
			if err != nil {
				_, _ = logger.Write(marker)
				msg := fmt.Sprintf("An error occurred while performing test query: %s", err)
				logger.Write([]byte(msg))
			}
			// If ctrld service is running but selfCheckStatus failed, it could be related
			// to user's system firewall configuration, notice users about it.
			if status == service.StatusRunning && err == nil {
				_, _ = logger.Write(marker)
				logger.Write([]byte(`ctrld service was running, but a DNS query could not be sent to its listener`))
				logger.Write([]byte(`Please check your system firewall if it is configured to block/intercept/redirect DNS queries`))
			}

			_, _ = logger.Write(marker)
			uninstall(p, s)
			os.Exit(1)
		}
		reportSetDnsOk(sockDir)
	}

	logger.Debug().Msg("Service start command completed")
	return nil
}

// createStartCommands creates the start command and its alias
func createStartCommands(sc *ServiceCommand) (*cobra.Command, *cobra.Command) {
	// Start command
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Install and start the ctrld service",
		Long: `Install and start the ctrld service

NOTE: running "ctrld start" without any arguments will start already installed ctrld service.`,
		Args: func(cmd *cobra.Command, args []string) error {
			args = filterEmptyStrings(args)
			if len(args) > 0 {
				return fmt.Errorf("'ctrld start' doesn't accept positional arguments\n" +
					"Use flags instead (e.g. --cd, --iface) or see 'ctrld start --help' for all options")
			}
			return nil
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: sc.Start,
	}
	// Keep these flags in sync with runCmd above, except for "-d"/"--nextdns".
	startCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")
	startCmd.Flags().StringVarP(&configBase64, "base64_config", "", "", "Base64 encoded config")
	startCmd.Flags().StringVarP(&listenAddress, "listen", "", "", "Listener address and port, in format: address:port")
	startCmd.Flags().StringVarP(&primaryUpstream, "primary_upstream", "", "", "Primary upstream endpoint")
	startCmd.Flags().StringVarP(&secondaryUpstream, "secondary_upstream", "", "", "Secondary upstream endpoint")
	startCmd.Flags().StringSliceVarP(&domains, "domains", "", nil, "List of domain to apply in a split DNS policy")
	startCmd.Flags().StringVarP(&logPath, "log", "", "", "Path to log file")
	startCmd.Flags().IntVarP(&cacheSize, "cache_size", "", 0, "Enable cache with size items")
	startCmd.Flags().StringVarP(&cdUID, cdUidFlagName, "", "", "Control D resolver uid")
	startCmd.Flags().StringVarP(&cdOrg, cdOrgFlagName, "", "", "Control D provision token")
	startCmd.Flags().StringVarP(&customHostname, customHostnameFlagName, "", "", "Custom hostname passed to ControlD API")
	startCmd.Flags().BoolVarP(&cdDev, "dev", "", false, "Use Control D dev resolver/domain")
	_ = startCmd.Flags().MarkHidden("dev")
	startCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)
	startCmd.Flags().StringVarP(&nextdns, nextdnsFlagName, "", "", "NextDNS resolver id")
	startCmd.Flags().StringVarP(&cdUpstreamProto, "proto", "", ctrld.ResolverTypeDOH, `Control D upstream type, either "doh" or "doh3"`)
	startCmd.Flags().BoolVarP(&skipSelfChecks, "skip_self_checks", "", false, `Skip self checks after installing ctrld service`)
	startCmd.Flags().BoolVarP(&startOnly, "start_only", "", false, "Do not install new service")
	_ = startCmd.Flags().MarkHidden("start_only")
	startCmd.Flags().BoolVarP(&rfc1918, "rfc1918", "", false, "Listen on RFC1918 addresses when 127.0.0.1 is the only listener")

	// Start command alias
	startCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "start",
		Short: "Quick start service and configure DNS on interface",
		Long: `Quick start service and configure DNS on interface

NOTE: running "ctrld start" without any arguments will start already installed ctrld service.`,
		Args: func(cmd *cobra.Command, args []string) error {
			args = filterEmptyStrings(args)
			if len(args) > 0 {
				return fmt.Errorf("'ctrld start' doesn't accept positional arguments\n" +
					"Use flags instead (e.g. --cd, --iface) or see 'ctrld start --help' for all options")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(os.Args) == 2 {
				startOnly = true
			}
			if !cmd.Flags().Changed("iface") {
				os.Args = append(os.Args, "--iface="+ifaceStartStop)
			}
			iface = ifaceStartStop
			return startCmd.RunE(cmd, args)
		},
	}
	startCmdAlias.Flags().StringVarP(&ifaceStartStop, "iface", "", "auto", `Update DNS setting for iface, "auto" means the default interface gateway`)
	startCmdAlias.Flags().AddFlagSet(startCmd.Flags())

	return startCmd, startCmdAlias
}
