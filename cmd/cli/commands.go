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
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docker/go-units"
	"github.com/kardianos/service"
	"github.com/minio/selfupdate"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/clientinfo"
	"github.com/Control-D-Inc/ctrld/internal/router"
)

func initLogCmd() *cobra.Command {
	warnRuntimeLoggingNotEnabled := func() {
		mainLog.Load().Warn().Msg("runtime debug logging is not enabled")
		mainLog.Load().Warn().Msg(`ctrld may be running without "--cd" flag or logging is already enabled`)
	}
	logSendCmd := &cobra.Command{
		Use:   "send",
		Short: "Send runtime debug logs to ControlD",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Run: func(cmd *cobra.Command, args []string) {

			p := &prog{router: router.New(&cfg, false)}
			s, _ := newService(p, svcConfig)

			status, err := s.Status()
			if errors.Is(err, service.ErrNotInstalled) {
				mainLog.Load().Warn().Msg("service not installed")
				return
			}
			if status == service.StatusStopped {
				mainLog.Load().Warn().Msg("service is not running")
				return
			}

			dir, err := socketDir()
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to find ctrld home dir")
			}
			cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
			resp, err := cc.post(sendLogsPath, nil)
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to send logs")
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusServiceUnavailable:
				mainLog.Load().Warn().Msg("runtime logs could only be sent once per minute")
				return
			case http.StatusMovedPermanently:
				warnRuntimeLoggingNotEnabled()
				return
			}
			var logs logSentResponse
			if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to decode sent logs result")
			}
			size := units.BytesSize(float64(logs.Size))
			if logs.Error == "" {
				mainLog.Load().Notice().Msgf("runtime logs sent successfully (%s)", size)
			} else {
				mainLog.Load().Error().Msgf("failed to send logs (%s)", size)
				mainLog.Load().Error().Msg(logs.Error)
			}
		},
	}
	logViewCmd := &cobra.Command{
		Use:   "view",
		Short: "View current runtime debug logs",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Run: func(cmd *cobra.Command, args []string) {

			p := &prog{router: router.New(&cfg, false)}
			s, _ := newService(p, svcConfig)

			status, err := s.Status()
			if errors.Is(err, service.ErrNotInstalled) {
				mainLog.Load().Warn().Msg("service not installed")
				return
			}
			if status == service.StatusStopped {
				mainLog.Load().Warn().Msg("service is not running")
				return
			}

			dir, err := socketDir()
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to find ctrld home dir")
			}
			cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
			resp, err := cc.post(viewLogsPath, nil)
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to get logs")
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusMovedPermanently:
				warnRuntimeLoggingNotEnabled()
				return
			case http.StatusBadRequest:
				mainLog.Load().Warn().Msg("runtime debugs log is not available")
				buf, err := io.ReadAll(resp.Body)
				if err != nil {
					mainLog.Load().Fatal().Err(err).Msg("failed to read response body")
				}
				mainLog.Load().Warn().Msgf("ctrld process response:\n\n%s\n", string(buf))
				return
			case http.StatusOK:
			}
			var logs logViewResponse
			if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to decode view logs result")
			}
			fmt.Println(logs.Data)
		},
	}
	logCmd := &cobra.Command{
		Use:   "log",
		Short: "Manage runtime debug logs",
		Args:  cobra.OnlyValidArgs,
		ValidArgs: []string{
			logSendCmd.Use,
		},
	}
	logCmd.AddCommand(logSendCmd)
	logCmd.AddCommand(logViewCmd)
	rootCmd.AddCommand(logCmd)

	return logCmd
}

func initRunCmd() *cobra.Command {
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the DNS proxy server",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			RunCobraCommand(cmd)
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
	runCmd.Flags().StringVarP(&cdUID, cdUidFlagName, "", "", "Control D resolver uid")
	runCmd.Flags().StringVarP(&cdOrg, cdOrgFlagName, "", "", "Control D provision token")
	runCmd.Flags().StringVarP(&customHostname, customHostnameFlagName, "", "", "Custom hostname passed to ControlD API")
	runCmd.Flags().BoolVarP(&cdDev, "dev", "", false, "Use Control D dev resolver/domain")
	_ = runCmd.Flags().MarkHidden("dev")
	runCmd.Flags().StringVarP(&homedir, "homedir", "", "", "")
	_ = runCmd.Flags().MarkHidden("homedir")
	runCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)
	_ = runCmd.Flags().MarkHidden("iface")
	runCmd.Flags().StringVarP(&cdUpstreamProto, "proto", "", ctrld.ResolverTypeDOH, `Control D upstream type, either "doh" or "doh3"`)

	runCmd.FParseErrWhitelist = cobra.FParseErrWhitelist{UnknownFlags: true}
	rootCmd.AddCommand(runCmd)

	return runCmd
}

func initStartCmd() *cobra.Command {
	startCmd := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "start",
		Short: "Install and start the ctrld service",
		Long: `Install and start the ctrld service

NOTE: running "ctrld start" without any arguments will start already installed ctrld service.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			checkStrFlagEmpty(cmd, cdUidFlagName)
			checkStrFlagEmpty(cmd, cdOrgFlagName)
			validateCdAndNextDNSFlags()
			sc := &service.Config{}
			*sc = *svcConfig
			osArgs := os.Args[2:]
			if os.Args[1] == "service" {
				osArgs = os.Args[3:]
			}
			setDependencies(sc)
			sc.Arguments = append([]string{"run"}, osArgs...)

			p := &prog{
				router: router.New(&cfg, cdUID != ""),
				cfg:    &cfg,
			}
			s, err := newService(p, sc)
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
				return
			}

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
							logger := mainLog.Load().With().Str("iface", name).Logger()
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
				setWorkingDirectory(sc, ud)
				if configPath == "" && writeDefaultConfig {
					defaultConfigFile = filepath.Join(ud, defaultConfigFile)
				}
				sc.Arguments = append(sc.Arguments, "--homedir="+ud)
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

				initInteractiveLogging()
				tasks := []task{
					{s.Stop, false, "Stop"},
					resetDnsTask(p, s, isCtrldInstalled, currentIface),
					{func() error {
						// Save current DNS so we can restore later.
						withEachPhysicalInterfaces("", "", func(i *net.Interface) error {
							if err := saveCurrentStaticDNS(i); !errors.Is(err, errSaveCurrentStaticDNSNotSupported) && err != nil {
								return err
							}
							return nil
						})
						return nil
					}, false, "Save current DNS"},
					{func() error {
						return ConfigureWindowsServiceFailureActions(ctrldServiceName)
					}, false, "Configure Windows service failure actions"},
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
				return
			}

			if cdUID != "" {
				doValidateCdRemoteConfig(cdUID)
			} else if uid := cdUIDFromProvToken(); uid != "" {
				cdUID = uid
				mainLog.Load().Debug().Msg("using uid from provision token")
				removeOrgFlagsFromArgs(sc)
				// Pass --cd flag to "ctrld run" command, so the provision token takes no effect.
				sc.Arguments = append(sc.Arguments, "--cd="+cdUID)
			}
			if cdUID != "" {
				validateCdUpstreamProtocol()
			}

			if err := p.router.ConfigureService(sc); err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to configure service on router")
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
				removeNextDNSFromArgs(sc)
			}

			// Explicitly passing config, so on system where home directory could not be obtained,
			// or sub-process env is different with the parent, we still behave correctly and use
			// the expected config file.
			if configPath == "" {
				sc.Arguments = append(sc.Arguments, "--config="+defaultConfigFile)
			}

			if router.Name() != "" && iface != "" {
				mainLog.Load().Debug().Msg("cleaning up router before installing")
				_ = p.router.Cleanup()
			}

			tasks := []task{
				{s.Stop, false, "Stop"},
				{func() error { return doGenerateNextDNSConfig(nextdns) }, true, "Checking config"},
				{func() error { return ensureUninstall(s) }, false, "Ensure uninstall"},
				resetDnsTask(p, s, isCtrldInstalled, currentIface),
				{func() error {
					// Save current DNS so we can restore later.
					withEachPhysicalInterfaces("", "", func(i *net.Interface) error {
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
				if err := p.router.Install(sc); err != nil {
					mainLog.Load().Warn().Err(err).Msg("post installation failed, please check system/service log for details error")
					return
				}

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
		},
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

	routerCmd := &cobra.Command{
		Use: "setup",
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

	startCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "start",
		Short: "Quick start service and configure DNS on interface",
		Long: `Quick start service and configure DNS on interface

NOTE: running "ctrld start" without any arguments will start already installed ctrld service.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(os.Args) == 2 {
				startOnly = true
			}
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

	return startCmd
}

func initStopCmd() *cobra.Command {
	stopCmd := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "stop",
		Short: "Stop the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			readConfig(false)
			v.Unmarshal(&cfg)
			p := &prog{router: router.New(&cfg, runInCdMode())}
			s, err := newService(p, svcConfig)
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
				return
			}
			p.preRun()
			if ir := runningIface(s); ir != nil {
				p.runningIface = ir.Name
				p.requiredMultiNICsConfig = ir.All
			}

			initInteractiveLogging()

			status, err := s.Status()
			if errors.Is(err, service.ErrNotInstalled) {
				mainLog.Load().Warn().Msg("service not installed")
				return
			}
			if status == service.StatusStopped {
				mainLog.Load().Warn().Msg("service is already stopped")
				return
			}

			if err := checkDeactivationPin(s, nil); isCheckDeactivationPinErr(err) {
				os.Exit(deactivationPinInvalidExitCode)
			}
			if doTasks([]task{{s.Stop, true, "Stop"}}) {
				p.router.Cleanup()
				p.resetDNS()

				// restore DNS settings
				if netIface, err := netInterface(p.runningIface); err == nil {
					if err := restoreDNS(netIface); err != nil {
						mainLog.Load().Error().Err(err).Msg("could not restore DNS on interface")
					} else {
						mainLog.Load().Debug().Msg("Restored DNS on interface successfully")
					}
				}

				if router.WaitProcessExited() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
					defer cancel()

					for {
						select {
						case <-ctx.Done():
							mainLog.Load().Error().Msg("timeout while waiting for service to stop")
							return
						default:
						}
						time.Sleep(time.Second)
						if status, _ := s.Status(); status == service.StatusStopped {
							break
						}
					}
				}
				mainLog.Load().Notice().Msg("Service stopped")
			}
		},
	}
	stopCmd.Flags().StringVarP(&iface, "iface", "", "", `Reset DNS setting for iface, "auto" means the default interface gateway`)
	stopCmd.Flags().Int64VarP(&deactivationPin, "pin", "", defaultDeactivationPin, `Pin code for stopping ctrld`)
	_ = stopCmd.Flags().MarkHidden("pin")

	stopCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
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

	return stopCmd
}

func initRestartCmd() *cobra.Command {
	restartCmd := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "restart",
		Short: "Restart the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			readConfig(false)
			v.Unmarshal(&cfg)
			cdUID = curCdUID()
			cdMode := cdUID != ""

			p := &prog{router: router.New(&cfg, cdMode)}
			s, err := newService(p, svcConfig)
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
				return
			}
			if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
				mainLog.Load().Warn().Msg("service not installed")
				return
			}
			if iface == "" {
				iface = "auto"
			}
			p.preRun()
			if ir := runningIface(s); ir != nil {
				p.runningIface = ir.Name
				p.requiredMultiNICsConfig = ir.All
			}

			initInteractiveLogging()

			if cdMode {
				doValidateCdRemoteConfig(cdUID)
			}

			if ir := runningIface(s); ir != nil {
				iface = ir.Name
			}

			doRestart := func() bool {
				tasks := []task{
					{s.Stop, true, "Stop"},
					{func() error {
						p.router.Cleanup()
						p.resetDNS()
						return nil
					}, false, "Cleanup"},
					{func() error {
						time.Sleep(time.Second * 1)
						return nil
					}, false, "Waiting for service to stop"},
				}
				if doTasks(tasks) {

					if router.WaitProcessExited() {
						ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
						defer cancel()

					loop:
						for {
							select {
							case <-ctx.Done():
								mainLog.Load().Error().Msg("timeout while waiting for service to stop")
								break loop
							default:
							}
							time.Sleep(time.Second)
							if status, _ := s.Status(); status == service.StatusStopped {
								break
							}
						}
					}
				} else {
					return false
				}

				tasks = []task{
					{s.Start, true, "Start"},
				}

				return doTasks(tasks)

			}

			if doRestart() {
				dir, err := socketDir()
				if err != nil {
					mainLog.Load().Warn().Err(err).Msg("Service was restarted, but could not ping the control server")
					return
				}
				cc := newSocketControlClient(context.TODO(), s, dir)
				if cc == nil {
					mainLog.Load().Error().Msg("Could not complete service restart")
					os.Exit(1)
				}
				_, _ = cc.post(ifacePath, nil)
				mainLog.Load().Notice().Msg("Service restarted")
			} else {
				mainLog.Load().Error().Msg("Service restart failed")
			}
		},
	}

	restartCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "restart",
		Short: "Restart the ctrld service",
		Run: func(cmd *cobra.Command, args []string) {
			restartCmd.Run(cmd, args)
		},
	}
	rootCmd.AddCommand(restartCmdAlias)

	return restartCmd
}

func initReloadCmd(restartCmd *cobra.Command) *cobra.Command {
	reloadCmd := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "reload",
		Short: "Reload the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {

			p := &prog{router: router.New(&cfg, false)}
			s, _ := newService(p, svcConfig)

			status, err := s.Status()
			if errors.Is(err, service.ErrNotInstalled) {
				mainLog.Load().Warn().Msg("service not installed")
				return
			}
			if status == service.StatusStopped {
				mainLog.Load().Warn().Msg("service is not running")
				return
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
				s, err := newService(&prog{}, svcConfig)
				if err != nil {
					mainLog.Load().Error().Msg(err.Error())
					return
				}
				mainLog.Load().Warn().Msg("Service was reloaded, but new config requires service restart.")
				mainLog.Load().Warn().Msg("Restarting service")
				if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
					mainLog.Load().Warn().Msg("Service not installed")
					return
				}
				restartCmd.Run(cmd, args)
			default:
				buf, err := io.ReadAll(resp.Body)
				if err != nil {
					mainLog.Load().Fatal().Err(err).Msg("could not read response from control server")
				}
				mainLog.Load().Error().Err(err).Msgf("failed to reload ctrld: %s", string(buf))
			}
		},
	}

	reloadCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Use:   "reload",
		Short: "Reload the ctrld service",
		Run: func(cmd *cobra.Command, args []string) {
			reloadCmd.Run(cmd, args)
		},
	}
	rootCmd.AddCommand(reloadCmdAlias)

	return reloadCmd
}

func initStatusCmd() *cobra.Command {
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show status of the ctrld service",
		Args:  cobra.NoArgs,
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
			checkHasElevatedPrivilege()
		}
	}

	statusCmdAlias := &cobra.Command{
		Use:   "status",
		Short: "Show status of the ctrld service",
		Args:  cobra.NoArgs,
		Run:   statusCmd.Run,
	}
	rootCmd.AddCommand(statusCmdAlias)

	return statusCmd
}

func initUninstallCmd() *cobra.Command {
	uninstallCmd := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
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
			p := &prog{router: router.New(&cfg, runInCdMode())}
			s, err := newService(p, svcConfig)
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
				return
			}
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
					file := savedStaticDnsSettingsFilePath(i)
					if _, err := os.Stat(file); err == nil {
						files = append(files, file)
					}
					return nil
				})
				// Windows forwarders file.
				if hasLocalDnsServerRunning() {
					files = append(files, absHomeDir(windowsForwardersFilename))
				}
				// Binary itself.
				bin, _ := os.Executable()
				if bin != "" && supportedSelfDelete {
					files = append(files, bin)
				}
				// Backup file after upgrading.
				oldBin := bin + oldBinSuffix
				if _, err := os.Stat(oldBin); err == nil {
					files = append(files, oldBin)
				}
				for _, file := range files {
					if file == "" {
						continue
					}
					if err := os.Remove(file); err != nil {
						if os.IsNotExist(err) {
							continue
						}
						mainLog.Load().Warn().Err(err).Msg("failed to remove file")
					} else {
						mainLog.Load().Debug().Msgf("file removed: %s", file)
					}
				}
				if err := selfDeleteExe(); err != nil {
					mainLog.Load().Warn().Err(err).Msg("failed to remove file")
				} else {
					if !supportedSelfDelete {
						mainLog.Load().Debug().Msgf("file removed: %s", bin)
					}
				}
			}
		},
	}
	uninstallCmd.Flags().StringVarP(&iface, "iface", "", "", `Reset DNS setting for iface, use "auto" for the default gateway interface`)
	uninstallCmd.Flags().Int64VarP(&deactivationPin, "pin", "", defaultDeactivationPin, `Pin code for uninstalling ctrld`)
	_ = uninstallCmd.Flags().MarkHidden("pin")
	uninstallCmd.Flags().BoolVarP(&cleanup, "cleanup", "", false, `Removing ctrld binary and config files`)

	uninstallCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
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
	uninstallCmdAlias.Flags().AddFlagSet(uninstallCmd.Flags())
	rootCmd.AddCommand(uninstallCmdAlias)

	return uninstallCmd
}

func initInterfacesCmd() *cobra.Command {
	listIfacesCmd := &cobra.Command{
		Use:   "list",
		Short: "List network interfaces of the host",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			withEachPhysicalInterfaces("", "", func(i *net.Interface) error {
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
				nss, err := currentStaticDNS(i)
				if err != nil {
					mainLog.Load().Warn().Err(err).Msg("failed to get DNS")
				}
				if len(nss) == 0 {
					nss = currentDNS(i)
				}
				for i, dns := range nss {
					if i == 0 {
						fmt.Printf("DNS   : %s\n", dns)
						continue
					}
					fmt.Printf("      : %s\n", dns)
				}
				println()
				return nil
			})
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

	return interfacesCmd
}

func initClientsCmd() *cobra.Command {
	listClientsCmd := &cobra.Command{
		Use:   "list",
		Short: "List clients that ctrld discovered",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Run: func(cmd *cobra.Command, args []string) {

			p := &prog{router: router.New(&cfg, false)}
			s, _ := newService(p, svcConfig)

			status, err := s.Status()
			if errors.Is(err, service.ErrNotInstalled) {
				mainLog.Load().Warn().Msg("service not installed")
				return
			}
			if status == service.StatusStopped {
				mainLog.Load().Warn().Msg("service is not running")
				return
			}

			dir, err := socketDir()
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
					if k == "" { // skip empty source from output.
						continue
					}
					s = append(s, k)
				}
				sort.Strings(s)
				return s
			}
			// If metrics is enabled, server set this for all clients, so we can check only the first one.
			// Ideally, we may have a field in response to indicate that query count should be shown, but
			// it would break earlier version of ctrld, which only look list of clients in response.
			withQueryCount := len(clients) > 0 && clients[0].IncludeQueryCount
			data := make([][]string, len(clients))
			for i, c := range clients {
				row := []string{
					c.IP.String(),
					c.Hostname,
					c.Mac,
					strings.Join(map2Slice(c.Source), ","),
				}
				if withQueryCount {
					row = append(row, strconv.FormatInt(c.QueryCount, 10))
				}
				data[i] = row
			}
			table := tablewriter.NewWriter(os.Stdout)
			headers := []string{"IP", "Hostname", "Mac", "Discovered"}
			if withQueryCount {
				headers = append(headers, "Queries")
			}
			table.SetHeader(headers)
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

	return clientsCmd
}

func initUpgradeCmd() *cobra.Command {
	const (
		upgradeChannelDev     = "dev"
		upgradeChannelProd    = "prod"
		upgradeChannelDefault = "default"
	)
	upgradeChannel := map[string]string{
		upgradeChannelDefault: "https://dl.controld.dev",
		upgradeChannelDev:     "https://dl.controld.dev",
		upgradeChannelProd:    "https://dl.controld.com",
	}
	if isStableVersion(curVersion()) {
		upgradeChannel[upgradeChannelDefault] = upgradeChannel[upgradeChannelProd]
	}
	upgradeCmd := &cobra.Command{
		Use:       "upgrade",
		Short:     "Upgrading ctrld to latest version",
		ValidArgs: []string{upgradeChannelDev, upgradeChannelProd},
		Args:      cobra.MaximumNArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		Run: func(cmd *cobra.Command, args []string) {
			bin, err := os.Executable()
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to get current ctrld binary path")
			}
			sc := &service.Config{}
			*sc = *svcConfig
			sc.Executable = bin
			readConfig(false)
			v.Unmarshal(&cfg)
			p := &prog{router: router.New(&cfg, runInCdMode())}
			s, err := newService(p, sc)
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
				return
			}
			if iface == "" {
				iface = "auto"
			}
			p.preRun()
			if ir := runningIface(s); ir != nil {
				p.runningIface = ir.Name
				p.requiredMultiNICsConfig = ir.All
			}

			svcInstalled := true
			if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
				svcInstalled = false
			}
			oldBin := bin + oldBinSuffix
			baseUrl := upgradeChannel[upgradeChannelDefault]
			if len(args) > 0 {
				channel := args[0]
				switch channel {
				case upgradeChannelProd, upgradeChannelDev: // ok
				default:
					mainLog.Load().Fatal().Msgf("uprade argument must be either %q or %q", upgradeChannelProd, upgradeChannelDev)
				}
				baseUrl = upgradeChannel[channel]
			}
			dlUrl := upgradeUrl(baseUrl)
			mainLog.Load().Debug().Msgf("Downloading binary: %s", dlUrl)
			resp, err := http.Get(dlUrl)
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to download binary")
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				mainLog.Load().Fatal().Msgf("could not download binary: %s", http.StatusText(resp.StatusCode))
			}
			mainLog.Load().Debug().Msg("Updating current binary")
			if err := selfupdate.Apply(resp.Body, selfupdate.Options{OldSavePath: oldBin}); err != nil {
				if rerr := selfupdate.RollbackError(err); rerr != nil {
					mainLog.Load().Error().Err(rerr).Msg("could not rollback old binary")
				}
				mainLog.Load().Fatal().Err(err).Msg("failed to update current binary")
			}

			doRestart := func() bool {
				if !svcInstalled {
					return true
				}
				tasks := []task{
					{s.Stop, true, "Stop"},
					{func() error {
						p.router.Cleanup()
						p.resetDNS()
						return nil
					}, false, "Cleanup"},
					{func() error {
						time.Sleep(time.Second * 1)
						return nil
					}, false, "Waiting for service to stop"},
				}
				if doTasks(tasks) {

					if router.WaitProcessExited() {
						ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
						defer cancel()

					loop:
						for {
							select {
							case <-ctx.Done():
								mainLog.Load().Error().Msg("timeout while waiting for service to stop")
								break loop
							default:
							}
							time.Sleep(time.Second)
							if status, _ := s.Status(); status == service.StatusStopped {
								break
							}
						}
					}
				}

				tasks = []task{
					{s.Start, true, "Start"},
				}
				if doTasks(tasks) {
					if dir, err := socketDir(); err == nil {
						if cc := newSocketControlClient(context.TODO(), s, dir); cc != nil {
							_, _ = cc.post(ifacePath, nil)
							return true
						}
					}
				}
				return false
			}
			if svcInstalled {
				mainLog.Load().Debug().Msg("Restarting ctrld service using new binary")
			}
			if doRestart() {
				_ = os.Remove(oldBin)
				_ = os.Chmod(bin, 0755)
				ver := "unknown version"
				out, err := exec.Command(bin, "--version").CombinedOutput()
				if err != nil {
					mainLog.Load().Warn().Err(err).Msg("Failed to get new binary version")
				}
				if after, found := strings.CutPrefix(string(out), "ctrld version "); found {
					ver = after
				}
				mainLog.Load().Notice().Msgf("Upgrade successful - %s", ver)
				return
			}

			mainLog.Load().Warn().Msgf("Upgrade failed, restoring previous binary: %s", oldBin)
			if err := os.Remove(bin); err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to remove new binary")
			}
			if err := os.Rename(oldBin, bin); err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to restore old binary")
			}
			if doRestart() {
				mainLog.Load().Notice().Msg("Restored previous binary successfully")
				return
			}
		},
	}
	rootCmd.AddCommand(upgradeCmd)

	return upgradeCmd
}

func initServicesCmd(commands ...*cobra.Command) *cobra.Command {
	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "Manage ctrld service",
		Args:  cobra.OnlyValidArgs,
	}
	serviceCmd.ValidArgs = make([]string, len(commands))
	for i, cmd := range commands {
		serviceCmd.ValidArgs[i] = cmd.Use
		serviceCmd.AddCommand(cmd)
	}
	rootCmd.AddCommand(serviceCmd)

	return serviceCmd
}
