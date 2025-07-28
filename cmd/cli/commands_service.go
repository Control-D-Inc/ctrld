package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/Control-D-Inc/ctrld"
)

// ServiceCommand handles service-related operations
type ServiceCommand struct {
	serviceManager *ServiceManager
}

// NewServiceCommand creates a new service command handler
func NewServiceCommand() (*ServiceCommand, error) {
	sm, err := NewServiceManager()
	if err != nil {
		return nil, err
	}

	return &ServiceCommand{
		serviceManager: sm,
	}, nil
}

// createServiceConfig creates a properly initialized service configuration
func (sc *ServiceCommand) createServiceConfig() *service.Config {
	return &service.Config{
		Name:        ctrldServiceName,
		DisplayName: "Control-D Helper Service",
		Description: "A highly configurable, multi-protocol DNS forwarding proxy",
		Option:      service.KeyValue{},
	}
}

// Start implements the logic from cmdStart.Run
func (sc *ServiceCommand) Start(cmd *cobra.Command, args []string) error {
	s := sc.serviceManager.svc
	p := sc.serviceManager.prog
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

// Stop implements the logic from cmdStop.Run
func (sc *ServiceCommand) Stop(cmd *cobra.Command, args []string) error {
	s := sc.serviceManager.svc
	p := sc.serviceManager.prog
	readConfig(false)
	v.Unmarshal(&cfg)
	p.cfg = &cfg
	p.preRun()
	if ir := runningIface(s); ir != nil {
		p.runningIface = ir.Name
		p.requiredMultiNICsConfig = ir.All
	}

	initInteractiveLogging()

	status, err := s.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		mainLog.Load().Warn().Msg("service not installed")
		return nil
	}
	if status == service.StatusStopped {
		mainLog.Load().Warn().Msg("service is already stopped")
		return nil
	}

	if err := checkDeactivationPin(s, nil); isCheckDeactivationPinErr(err) {
		os.Exit(deactivationPinInvalidExitCode)
	}
	if doTasks([]task{{s.Stop, true, "Stop"}}) {
		mainLog.Load().Notice().Msg("Service stopped")
	}
	return nil
}

// Restart implements the logic from cmdRestart.Run
func (sc *ServiceCommand) Restart(cmd *cobra.Command, args []string) error {
	s := sc.serviceManager.svc
	p := sc.serviceManager.prog
	readConfig(false)
	v.Unmarshal(&cfg)
	cdUID = curCdUID()
	cdMode := cdUID != ""

	p.cfg = &cfg
	if iface == "" {
		iface = "auto"
	}
	p.preRun()
	if ir := runningIface(s); ir != nil {
		p.runningIface = ir.Name
		p.requiredMultiNICsConfig = ir.All
	}

	initInteractiveLogging()

	var validateConfigErr error
	if cdMode {
		validateConfigErr = doValidateCdRemoteConfig(cdUID, false)
	}

	if ir := runningIface(s); ir != nil {
		iface = ir.Name
	}
	doRestart := func() bool {
		tasks := []task{
			{s.Stop, true, "Stop"},
			{func() error {
				// restore static DNS settings or DHCP
				p.resetDNS(false, true)
				return nil
			}, false, "Cleanup"},
			{func() error {
				time.Sleep(time.Second * 1)
				return nil
			}, false, "Waiting for service to stop"},
		}
		if !doTasks(tasks) {
			return false
		}
		tasks = []task{
			{s.Start, true, "Start"},
		}
		return doTasks(tasks)
	}

	if doRestart() {
		if dir, err := socketDir(); err == nil {
			timeout := dialSocketControlServerTimeout
			if validateConfigErr != nil {
				timeout = 5 * time.Second
			}
			if cc := newSocketControlClientWithTimeout(context.TODO(), s, dir, timeout); cc != nil {
				_, _ = cc.post(ifacePath, nil)
			} else {
				mainLog.Load().Warn().Err(err).Msg("Service was restarted, but ctrld process may not be ready yet")
			}
		} else {
			mainLog.Load().Warn().Err(err).Msg("Service was restarted, but could not ping the control server")
		}
		mainLog.Load().Notice().Msg("Service restarted")
	} else {
		mainLog.Load().Error().Msg("Service restart failed")
	}
	return nil
}

// Reload implements the logic from cmdReload.Run
func (sc *ServiceCommand) Reload(cmd *cobra.Command, args []string) error {
	status, err := sc.serviceManager.svc.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		mainLog.Load().Warn().Msg("service not installed")
		return nil
	}
	if status == service.StatusStopped {
		mainLog.Load().Warn().Msg("service is not running")
		return nil
	}
	dir, err := socketDir()
	if err != nil {
		mainLog.Load().Fatal().Err(err).Msg("failed to find ctrld home dir")
	}
	cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
	resp, err := cc.post(reloadPath, nil)
	if err != nil {
		mainLog.Load().Fatal().Err(err).Msg("failed to send reload signal to ctrld")
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		mainLog.Load().Notice().Msg("Service reloaded")
	case http.StatusCreated:
		mainLog.Load().Warn().Msg("Service was reloaded, but new config requires service restart.")
		mainLog.Load().Warn().Msg("Restarting service")
		if _, err := sc.serviceManager.svc.Status(); errors.Is(err, service.ErrNotInstalled) {
			mainLog.Load().Warn().Msg("Service not installed")
			return nil
		}
		return sc.Restart(cmd, args)
	default:
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			mainLog.Load().Fatal().Err(err).Msg("could not read response from control server")
		}
		mainLog.Load().Error().Err(err).Msgf("failed to reload ctrld: %s", string(buf))
	}
	return nil
}

// Status implements the logic from cmdStatus.Run
func (sc *ServiceCommand) Status(cmd *cobra.Command, args []string) error {
	status, err := sc.serviceManager.svc.Status()
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
	return nil
}

// Uninstall implements the logic from cmdUninstall.Run
func (sc *ServiceCommand) Uninstall(cmd *cobra.Command, args []string) error {
	s := sc.serviceManager.svc
	p := sc.serviceManager.prog
	readConfig(false)
	v.Unmarshal(&cfg)
	p.cfg = &cfg
	if iface == "" {
		iface = "auto"
	}
	p.preRun()
	if ir := runningIface(s); ir != nil {
		p.runningIface = ir.Name
		p.requiredMultiNICsConfig = ir.All
	}
	if err := checkDeactivationPin(s, nil); isCheckDeactivationPinErr(err) {
		os.Exit(deactivationPinInvalidExitCode)
	}
	uninstall(p, s)
	if cleanup {
		var files []string
		// Config file.
		files = append(files, v.ConfigFileUsed())
		// Log file and backup log file.
		// For safety, only process if log file path is absolute.
		if logFile := normalizeLogFilePath(cfg.Service.LogPath); filepath.IsAbs(logFile) {
			files = append(files, logFile)
			oldLogFile := logFile + oldLogSuffix
			if _, err := os.Stat(oldLogFile); err == nil {
				files = append(files, oldLogFile)
			}
		}
		// Socket files.
		if dir, _ := socketDir(); dir != "" {
			files = append(files, filepath.Join(dir, ctrldControlUnixSock))
			files = append(files, filepath.Join(dir, ctrldLogUnixSock))
		}
		// Static DNS settings files.
		withEachPhysicalInterfaces("", "", func(i *net.Interface) error {
			file := ctrld.SavedStaticDnsSettingsFilePath(i)
			files = append(files, file)
			return nil
		})
		for _, file := range files {
			if file == "" {
				continue
			}
			if err := os.Remove(file); err == nil {
				mainLog.Load().Notice().Msgf("removed %s", file)
			}
		}
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
	rootCmd.AddCommand(startCmdAlias)

	return startCmd, startCmdAlias
}

// InitServiceCmd creates the service command with proper logic and aliases
func InitServiceCmd() *cobra.Command {
	// Create service command handlers
	sc, err := NewServiceCommand()
	if err != nil {
		panic(fmt.Sprintf("failed to create service command: %v", err))
	}

	// Uninstall command
	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and uninstall the ctrld service",
		Long: `Stop and uninstall the ctrld service.

NOTE: Uninstalling will set DNS to values provided by DHCP.`,
		Args: cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: sc.Uninstall,
	}

	startCmd, startCmdAlias := createStartCommands(sc)
	rootCmd.AddCommand(startCmdAlias)

	// Stop command
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the ctrld service",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: sc.Stop,
	}
	stopCmd.Flags().StringVarP(&iface, "iface", "", "", `Reset DNS setting for iface, "auto" means the default interface gateway`)
	stopCmd.Flags().Int64VarP(&deactivationPin, "pin", "", defaultDeactivationPin, `Pin code for stopping ctrld`)
	_ = stopCmd.Flags().MarkHidden("pin")

	// Restart command
	restartCmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart the ctrld service",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: sc.Restart,
	}

	// Status command
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show status of the ctrld service",
		Args:  cobra.NoArgs,
		RunE:  sc.Status,
	}
	if runtime.GOOS == "darwin" {
		// On darwin, running status command without privileges may return wrong information.
		statusCmd.PreRun = func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		}
	}

	// Reload command
	reloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Reload the ctrld service",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: sc.Reload,
	}

	// Interfaces command - use the existing InitInterfacesCmd function
	interfacesCmd := InitInterfacesCmd()

	stopCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "stop",
		Short: "Quick stop service and remove DNS from interface",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("iface") {
				os.Args = append(os.Args, "--iface="+ifaceStartStop)
			}
			iface = ifaceStartStop
			return stopCmd.RunE(cmd, args)
		},
	}
	stopCmdAlias.Flags().StringVarP(&ifaceStartStop, "iface", "", "auto", `Reset DNS setting for iface, "auto" means the default interface gateway`)
	stopCmdAlias.Flags().AddFlagSet(stopCmd.Flags())
	rootCmd.AddCommand(stopCmdAlias)

	// Create aliases for other service commands
	restartCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "restart",
		Short: "Restart the ctrld service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return restartCmd.RunE(cmd, args)
		},
	}
	rootCmd.AddCommand(restartCmdAlias)

	reloadCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "reload",
		Short: "Reload the ctrld service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return reloadCmd.RunE(cmd, args)
		},
	}
	rootCmd.AddCommand(reloadCmdAlias)

	statusCmdAlias := &cobra.Command{
		Use:   "status",
		Short: "Show status of the ctrld service",
		Args:  cobra.NoArgs,
		RunE:  statusCmd.RunE,
	}
	rootCmd.AddCommand(statusCmdAlias)

	uninstallCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "uninstall",
		Short: "Stop and uninstall the ctrld service",
		Long: `Stop and uninstall the ctrld service.

NOTE: Uninstalling will set DNS to values provided by DHCP.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("iface") {
				os.Args = append(os.Args, "--iface="+ifaceStartStop)
			}
			iface = ifaceStartStop
			return uninstallCmd.RunE(cmd, args)
		},
	}
	uninstallCmdAlias.Flags().StringVarP(&ifaceStartStop, "iface", "", "auto", `Reset DNS setting for iface, "auto" means the default interface gateway`)
	uninstallCmdAlias.Flags().AddFlagSet(uninstallCmd.Flags())
	rootCmd.AddCommand(uninstallCmdAlias)

	// Create service command
	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "Manage ctrld service",
		Args:  cobra.OnlyValidArgs,
	}
	serviceCmd.ValidArgs = make([]string, 7)
	serviceCmd.ValidArgs[0] = startCmd.Use
	serviceCmd.ValidArgs[1] = stopCmd.Use
	serviceCmd.ValidArgs[2] = restartCmd.Use
	serviceCmd.ValidArgs[3] = reloadCmd.Use
	serviceCmd.ValidArgs[4] = statusCmd.Use
	serviceCmd.ValidArgs[5] = uninstallCmd.Use
	serviceCmd.ValidArgs[6] = interfacesCmd.Use

	serviceCmd.AddCommand(uninstallCmd)
	serviceCmd.AddCommand(startCmd)
	serviceCmd.AddCommand(stopCmd)
	serviceCmd.AddCommand(restartCmd)
	serviceCmd.AddCommand(reloadCmd)
	serviceCmd.AddCommand(statusCmd)
	serviceCmd.AddCommand(interfacesCmd)

	rootCmd.AddCommand(serviceCmd)

	return serviceCmd
}
