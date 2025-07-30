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
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/Control-D-Inc/ctrld"
)

// Start implements the logic from cmdStart.Run
func (sc *ServiceCommand) Start(cmd *cobra.Command, args []string) error {
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
			os.Exit(deactivationPinInvalidExitCode)
		}
		currentIface = runningIface(s)
		mainLog.Load().Debug().Msgf("current interface on start: %v", currentIface)
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
					mainLog.Load().Warn().Err(err).Msg("failed to get iface info")
					return
				}
				if res.OK {
					name := res.Name
					if iff, err := net.InterfaceByName(name); err == nil {
						_, _ = patchNetIfaceName(iff)
						name = iff.Name
					}
					logger := mainLog.Load().With().Str("iface", name)
					logger.Debug().Msg("setting DNS successfully")
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
	// A buffer channel to gather log output from runCmd and report
	// to user in case self-check process failed.
	runCmdLogCh := make(chan string, 256)
	ud, err := userHomeDir()
	sockDir := ud
	if err != nil {
		mainLog.Load().Warn().Msg("log server did not start")
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
		sockPath := filepath.Join(sockDir, ctrldLogUnixSock)
		_ = os.Remove(sockPath)
		go func() {
			defer func() {
				close(runCmdLogCh)
				_ = os.Remove(sockPath)
			}()
			close(logServerStarted)
			if conn := runLogServer(sockPath); conn != nil {
				// Enough buffer for log message, we don't produce
				// such long log message, but just in case.
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					msg := string(buf[:n])
					if _, _, found := strings.Cut(msg, msgExit); found {
						cancel()
					}
					runCmdLogCh <- msg
				}
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
			mainLog.Load().Fatal().Msgf("failed to unmarshal config: %v", err)
		}

		// if already running, dont restart
		if isCtrldRunning {
			mainLog.Load().Notice().Msg("service is already running")
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
		mainLog.Load().Notice().Msg("Starting existing ctrld service")
		if doTasks(tasks) {
			mainLog.Load().Notice().Msg("Service started")
			sockDir, err := socketDir()
			if err != nil {
				mainLog.Load().Warn().Err(err).Msg("Failed to get socket directory")
				os.Exit(1)
			}
			reportSetDnsOk(sockDir)
		} else {
			mainLog.Load().Error().Err(err).Msg("Failed to start existing ctrld service")
			os.Exit(1)
		}
		return nil
	}

	if cdUID != "" {
		_ = doValidateCdRemoteConfig(cdUID, true)
	} else if uid := cdUIDFromProvToken(); uid != "" {
		cdUID = uid
		mainLog.Load().Debug().Msg("using uid from provision token")
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
		mainLog.Load().Fatal().Msgf("failed to unmarshal config: %v", err)
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
	mainLog.Load().Notice().Msg("Starting service")
	if doTasks(tasks) {
		// add a small delay to ensure the service is started and did not crash
		time.Sleep(1 * time.Second)

		ok, status, err := selfCheckStatus(ctx, s, sockDir)
		switch {
		case ok && status == service.StatusRunning:
			mainLog.Load().Notice().Msg("Service started")
		default:
			marker := bytes.Repeat([]byte("="), 32)
			// If ctrld service is not running, emitting log obtained from ctrld process.
			if status != service.StatusRunning || ctx.Err() != nil {
				mainLog.Load().Error().Msg("ctrld service may not have started due to an error or misconfiguration, service log:")
				_, _ = mainLog.Load().Write(marker)
				haveLog := false
				for msg := range runCmdLogCh {
					_, _ = mainLog.Load().Write([]byte(strings.ReplaceAll(msg, msgExit, "")))
					haveLog = true
				}
				// If we're unable to get log from "ctrld run", notice users about it.
				if !haveLog {
					mainLog.Load().Write([]byte(`<no log output is obtained from ctrld process>"`))
				}
			}
			// Report any error if occurred.
			if err != nil {
				_, _ = mainLog.Load().Write(marker)
				msg := fmt.Sprintf("An error occurred while performing test query: %s", err)
				mainLog.Load().Write([]byte(msg))
			}
			// If ctrld service is running but selfCheckStatus failed, it could be related
			// to user's system firewall configuration, notice users about it.
			if status == service.StatusRunning && err == nil {
				_, _ = mainLog.Load().Write(marker)
				mainLog.Load().Write([]byte(`ctrld service was running, but a DNS query could not be sent to its listener`))
				mainLog.Load().Write([]byte(`Please check your system firewall if it is configured to block/intercept/redirect DNS queries`))
			}

			_, _ = mainLog.Load().Write(marker)
			uninstall(p, s)
			os.Exit(1)
		}
		reportSetDnsOk(sockDir)
	}

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
