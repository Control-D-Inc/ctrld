package cli

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
	"net/url"
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

	"github.com/Masterminds/semver"
	"github.com/cuonglm/osinfo"
	"github.com/fsnotify/fsnotify"
	"github.com/go-playground/validator/v10"
	"github.com/kardianos/service"
	"github.com/miekg/dns"
	"github.com/minio/selfupdate"
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

// selfCheckInternalTestDomain is used for testing ctrld self response to clients.
const selfCheckInternalTestDomain = "ctrld" + loopTestDomain

var (
	version = "dev"
	commit  = "none"
)

var (
	v                    = viper.NewWithOptions(viper.KeyDelimiter("::"))
	defaultConfigFile    = "ctrld.toml"
	rootCertPool         *x509.CertPool
	errSelfCheckNoAnswer = errors.New("no answer from ctrld listener")
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
	runCmd.Flags().BoolVarP(&cdDev, "dev", "", false, "Use Control D dev resolver/domain")
	_ = runCmd.Flags().MarkHidden("dev")
	runCmd.Flags().StringVarP(&homedir, "homedir", "", "", "")
	_ = runCmd.Flags().MarkHidden("homedir")
	runCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)
	_ = runCmd.Flags().MarkHidden("iface")
	runCmd.Flags().StringVarP(&cdUpstreamProto, "proto", "", ctrld.ResolverTypeDOH, `Control D upstream type, either "doh" or "doh3"`)

	runCmd.FParseErrWhitelist = cobra.FParseErrWhitelist{UnknownFlags: true}
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
			if cdUID != "" {
				rc, err := controld.FetchResolverConfig(cdUID, rootCmd.Version, cdDev)
				if err != nil {
					mainLog.Load().Fatal().Err(err).Msgf("failed to fetch resolver uid: %s", cdUID)
				}
				// validateCdRemoteConfig clobbers v, saving it here to restore later.
				oldV := v
				if err := validateCdRemoteConfig(rc, &ctrld.Config{}); err != nil {
					if errors.As(err, &viper.ConfigParseError{}) {
						if configStr, _ := base64.StdEncoding.DecodeString(rc.Ctrld.CustomConfig); len(configStr) > 0 {
							tmpDir := os.TempDir()
							tmpConfFile := filepath.Join(tmpDir, "ctrld.toml")
							errorLogged := false
							// Write remote config to a temporary file to get details error.
							if we := os.WriteFile(tmpConfFile, configStr, 0600); we == nil {
								if de := decoderErrorFromTomlFile(tmpConfFile); de != nil {
									row, col := de.Position()
									mainLog.Load().Error().Msgf("failed to parse custom config at line: %d, column: %d, error: %s", row, col, de.Error())
									errorLogged = true
								}
								_ = os.Remove(tmpConfFile)
							}
							// If we could not log details error, emit what we have already got.
							if !errorLogged {
								mainLog.Load().Error().Msgf("failed to parse custom config: %v", err)
							}
						}
					} else {
						mainLog.Load().Error().Msgf("failed to unmarshal custom config: %v", err)
					}
					mainLog.Load().Warn().Msg("disregarding invalid custom config")
				}
				v = oldV
			} else if uid := cdUIDFromProvToken(); uid != "" {
				cdUID = uid
				removeProvTokenFromArgs(sc)
				// Pass --cd flag to "ctrld run" command, so the provision token takes no effect.
				sc.Arguments = append(sc.Arguments, "--cd="+cdUID)
			}
			if cdUID != "" {
				validateCdUpstreamProtocol()
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
				sockDir := dir
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

			tryReadingConfigWithNotice(writeDefaultConfig, true)

			if err := v.Unmarshal(&cfg); err != nil {
				mainLog.Load().Fatal().Msgf("failed to unmarshal config: %v", err)
			}

			initLogging()

			if nextdns != "" {
				removeNextDNSFromArgs(sc)
			}

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

			status, err := s.Status()
			isCtrldInstalled := !errors.Is(err, service.ErrNotInstalled)

			// If pin code was set, do not allow running start command.
			if status == service.StatusRunning {
				if err := checkDeactivationPin(s, nil); isCheckDeactivationPinErr(err) {
					os.Exit(deactivationPinInvalidExitCode)
				}
			}

			if router.Name() != "" && iface != "" {
				mainLog.Load().Debug().Msg("cleaning up router before installing")
				_ = p.router.Cleanup()
			}

			tasks := []task{
				{s.Stop, false},
				{func() error { return doGenerateNextDNSConfig(nextdns) }, true},
				{func() error { return ensureUninstall(s) }, false},
				{func() error {
					// If ctrld is installed, we should not save current DNS settings, because:
					//
					// - The DNS settings was being set by ctrld already.
					// - We could not determine the state of DNS settings before installing ctrld.
					if isCtrldInstalled {
						return nil
					}

					// Save current DNS so we can restore later.
					withEachPhysicalInterfaces("", "save DNS settings", func(i *net.Interface) error {
						return saveCurrentStaticDNS(i)
					})
					return nil
				}, false},
				{s.Install, false},
				{s.Start, true},
				// Note that startCmd do not actually write ControlD config, but the config file was
				// generated after s.Start, so we notice users here for consistent with nextdns mode.
				{noticeWritingControlDConfig, false},
			}
			mainLog.Load().Notice().Msg("Starting service")
			if doTasks(tasks) {
				if err := p.router.Install(sc); err != nil {
					mainLog.Load().Warn().Err(err).Msg("post installation failed, please check system/service log for details error")
					return
				}

				ok, status, err := selfCheckStatus(s)
				switch {
				case ok && status == service.StatusRunning:
					mainLog.Load().Notice().Msg("Service started")
				default:
					marker := bytes.Repeat([]byte("="), 32)
					// If ctrld service is not running, emitting log obtained from ctrld process.
					if status != service.StatusRunning {
						mainLog.Load().Error().Msg("ctrld service may not have started due to an error or misconfiguration, service log:")
						_, _ = mainLog.Load().Write(marker)
						haveLog := false
						for msg := range runCmdLogCh {
							_, _ = mainLog.Load().Write([]byte(msg))
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
				p.setDNS()
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
	startCmd.Flags().BoolVarP(&cdDev, "dev", "", false, "Use Control D dev resolver/domain")
	_ = startCmd.Flags().MarkHidden("dev")
	startCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)
	startCmd.Flags().StringVarP(&nextdns, nextdnsFlagName, "", "", "NextDNS resolver id")
	startCmd.Flags().StringVarP(&cdUpstreamProto, "proto", "", ctrld.ResolverTypeDOH, `Control D upstream type, either "doh" or "doh3"`)

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
			p := &prog{router: router.New(&cfg, runInCdMode())}
			s, err := newService(p, svcConfig)
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
				return
			}
			initLogging()
			if err := checkDeactivationPin(s, nil); isCheckDeactivationPinErr(err) {
				os.Exit(deactivationPinInvalidExitCode)
			}
			if doTasks([]task{{s.Stop, true}}) {
				p.router.Cleanup()
				p.resetDNS()
				mainLog.Load().Notice().Msg("Service stopped")
			}
		},
	}
	stopCmd.Flags().StringVarP(&iface, "iface", "", "", `Reset DNS setting for iface, "auto" means the default interface gateway`)
	stopCmd.Flags().Int64VarP(&deactivationPin, "pin", "", defaultDeactivationPin, `Pin code for stopping ctrld`)
	_ = stopCmd.Flags().MarkHidden("pin")

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
			if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
				mainLog.Load().Warn().Msg("service not installed")
				return
			}
			initLogging()

			tasks := []task{
				{s.Stop, false},
				{s.Start, true},
			}
			if doTasks(tasks) {
				dir, err := socketDir()
				if err != nil {
					mainLog.Load().Warn().Err(err).Msg("Service was restarted, but could not ping the control server")
					return
				}
				if cc := newSocketControlClient(s, dir); cc == nil {
					mainLog.Load().Notice().Msg("Service was not restarted")
					os.Exit(1)
				}
				mainLog.Load().Notice().Msg("Service restarted")
			}
		},
	}

	reloadCmd := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Use:   "reload",
		Short: "Reload the ctrld service",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
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
			p := &prog{router: router.New(&cfg, runInCdMode())}
			s, err := newService(p, svcConfig)
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
				return
			}
			if iface == "" {
				iface = "auto"
			}
			if err := checkDeactivationPin(s, nil); isCheckDeactivationPinErr(err) {
				os.Exit(deactivationPinInvalidExitCode)
			}
			uninstall(p, s)
		},
	}
	uninstallCmd.Flags().StringVarP(&iface, "iface", "", "", `Reset DNS setting for iface, use "auto" for the default gateway interface`)
	uninstallCmd.Flags().Int64VarP(&deactivationPin, "pin", "", defaultDeactivationPin, `Pin code for uninstalling ctrld`)
	_ = uninstallCmd.Flags().MarkHidden("pin")

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
			startCmd.Use,
			stopCmd.Use,
			restartCmd.Use,
			reloadCmd.Use,
			statusCmd.Use,
			uninstallCmd.Use,
			interfacesCmd.Use,
		},
	}
	serviceCmd.AddCommand(startCmd)
	serviceCmd.AddCommand(stopCmd)
	serviceCmd.AddCommand(restartCmd)
	serviceCmd.AddCommand(reloadCmd)
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

	reloadCmdAlias := &cobra.Command{
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Use:   "reload",
		Short: "Reload the ctrld service",
		Run: func(cmd *cobra.Command, args []string) {
			reloadCmd.Run(cmd, args)
		},
	}
	rootCmd.AddCommand(reloadCmdAlias)

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

	upgradeCmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrading ctrld to latest version",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
			checkHasElevatedPrivilege()
		},
		Run: func(cmd *cobra.Command, args []string) {
			s, err := newService(&prog{}, svcConfig)
			if err != nil {
				mainLog.Load().Error().Msg(err.Error())
				return
			}
			if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
				mainLog.Load().Warn().Msg("service not installed")
				return
			}
			bin, err := os.Executable()
			if err != nil {
				mainLog.Load().Fatal().Err(err).Msg("failed to get current ctrld binary path")
			}
			oldBin := bin + "_previous"
			urlString := "https://dl.controld.com"
			if !isStableVersion(curVersion()) {
				urlString = "https://dl.controld.dev"
			}
			dlUrl := fmt.Sprintf("%s/%s-%s/ctrld", urlString, runtime.GOOS, runtime.GOARCH)
			if runtime.GOOS == "windows" {
				dlUrl += ".exe"
			}
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
				tasks := []task{
					{s.Stop, false},
					{s.Start, false},
				}
				if doTasks(tasks) {
					if dir, err := socketDir(); err == nil {
						return newSocketControlClient(s, dir) != nil
					}
				}
				return false
			}
			mainLog.Load().Debug().Msg("Restarting ctrld service using new binary")
			if doRestart() {
				_ = os.Remove(oldBin)
				_ = os.Chmod(bin, 0755)
				mainLog.Load().Notice().Msg("Upgrade successful")
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
}

// isMobile reports whether the current OS is a mobile platform.
func isMobile() bool {
	return runtime.GOOS == "android" || runtime.GOOS == "ios"
}

// isAndroid reports whether the current OS is Android.
func isAndroid() bool {
	return runtime.GOOS == "android"
}

// isStableVersion reports whether vs is a stable semantic version.
func isStableVersion(vs string) bool {
	v, err := semver.NewVersion(vs)
	if err != nil {
		return false
	}
	return v.Prerelease() == ""
}

// RunCobraCommand runs ctrld cli.
func RunCobraCommand(cmd *cobra.Command) {
	noConfigStart = isNoConfigStart(cmd)
	checkStrFlagEmpty(cmd, cdUidFlagName)
	checkStrFlagEmpty(cmd, cdOrgFlagName)
	run(nil, make(chan struct{}))
}

// RunMobile runs the ctrld cli on mobile platforms.
func RunMobile(appConfig *AppConfig, appCallback *AppCallback, stopCh chan struct{}) {
	if appConfig == nil {
		panic("appConfig is nil")
	}
	initConsoleLogging()
	noConfigStart = false
	homedir = appConfig.HomeDir
	verbose = appConfig.Verbose
	cdUID = appConfig.CdUID
	cdUpstreamProto = appConfig.UpstreamProto
	logPath = appConfig.LogPath
	run(appCallback, stopCh)
}

// CheckDeactivationPin checks if deactivation pin is valid
func CheckDeactivationPin(pin int64, stopCh chan struct{}) int {
	deactivationPin = pin
	if err := checkDeactivationPin(nil, stopCh); isCheckDeactivationPinErr(err) {
		return deactivationPinInvalidExitCode
	}
	return 0
}

// run runs ctrld cli with given app callback and stop channel.
func run(appCallback *AppCallback, stopCh chan struct{}) {
	if stopCh == nil {
		mainLog.Load().Fatal().Msg("stopCh is nil")
	}
	waitCh := make(chan struct{})
	p := &prog{
		waitCh:       waitCh,
		stopCh:       stopCh,
		reloadCh:     make(chan struct{}),
		reloadDoneCh: make(chan struct{}),
		cfg:          &cfg,
		appCallback:  appCallback,
	}
	if homedir == "" {
		if dir, err := userHomeDir(); err == nil {
			homedir = dir
		}
	}
	sockDir := homedir
	if d, err := socketDir(); err == nil {
		sockDir = d
	}
	sockPath := filepath.Join(sockDir, ctrldLogUnixSock)
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
	writeDefaultConfig := !noConfigStart && configBase64 == ""
	tryReadingConfig(writeDefaultConfig)

	if err := readBase64Config(configBase64); err != nil {
		mainLog.Load().Fatal().Err(err).Msg("failed to read base64 config")
	}
	processNoConfigFlags(noConfigStart)
	p.mu.Lock()
	if err := v.Unmarshal(&cfg); err != nil {
		mainLog.Load().Fatal().Msgf("failed to unmarshal config: %v", err)
	}
	p.mu.Unlock()

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
	cs, err := newControlServer(filepath.Join(sockDir, ControlSocketName()))
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
		validateCdUpstreamProtocol()
		if err := processCDFlags(&cfg); err != nil {
			if isMobile() {
				appCallback.Exit(err.Error())
				return
			}

			uninstallIfInvalidCdUID := func() {
				cdLogger := mainLog.Load().With().Str("mode", "cd").Logger()
				if uer, ok := err.(*controld.UtilityErrorResponse); ok && uer.ErrorField.Code == controld.InvalidConfigCode {
					s, err := newService(&prog{}, svcConfig)
					if err != nil {
						cdLogger.Warn().Err(err).Msg("failed to create new service")
						return
					}
					if netIface, _ := netInterface(iface); netIface != nil {
						if err := restoreNetworkManager(); err != nil {
							cdLogger.Error().Err(err).Msg("could not restore NetworkManager")
							return
						}
						cdLogger.Debug().Str("iface", netIface.Name).Msg("Restoring DNS for interface")
						if err := resetDNS(netIface); err != nil {
							cdLogger.Warn().Err(err).Msg("something went wrong while restoring DNS")
						} else {
							cdLogger.Debug().Str("iface", netIface.Name).Msg("Restoring DNS successfully")
						}
					}

					tasks := []task{{s.Uninstall, true}}
					if doTasks(tasks) {
						cdLogger.Info().Msg("uninstalled service")
					}
					cdLogger.Fatal().Err(uer).Msg("failed to fetch resolver config")
					return
				}
			}
			uninstallIfInvalidCdUID()
		}
	}

	updated := updateListenerConfig(&cfg)

	if cdUID != "" {
		processLogAndCacheFlags()
	}

	if updated {
		if err := writeConfigFile(); err != nil {
			mainLog.Load().Fatal().Err(err).Msg("failed to write config file")
		} else {
			mainLog.Load().Info().Msg("writing config file to: " + defaultConfigFile)
		}
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

	if err := validateConfig(&cfg); err != nil {
		os.Exit(1)
	}
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
		if iface != "" {
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
	}

	close(waitCh)
	<-stopCh
	for _, f := range p.onStopped {
		f()
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

// readConfigFile reads in config file.
//
// - It writes default config file if config file not found if writeDefaultConfig is true.
// - It emits notice message to user if notice is true.
func readConfigFile(writeDefaultConfig, notice bool) bool {
	// If err == nil, there's a config supplied via `--config`, no default config written.
	err := v.ReadInConfig()
	if err == nil {
		if notice {
			mainLog.Load().Notice().Msg("Reading config: " + v.ConfigFileUsed())
		}
		mainLog.Load().Info().Msg("loading config file from: " + v.ConfigFileUsed())
		defaultConfigFile = v.ConfigFileUsed()
		return true
	}

	if !writeDefaultConfig {
		return false
	}

	// If error is viper.ConfigFileNotFoundError, write default config.
	if errors.As(err, &viper.ConfigFileNotFoundError{}) {
		if err := v.Unmarshal(&cfg); err != nil {
			mainLog.Load().Fatal().Msgf("failed to unmarshal default config: %v", err)
		}
		nop := zerolog.Nop()
		_, _ = tryUpdateListenerConfig(&cfg, &nop, true)
		if err := writeConfigFile(); err != nil {
			mainLog.Load().Fatal().Msgf("failed to write default config file: %v", err)
		} else {
			fp, err := filepath.Abs(defaultConfigFile)
			if err != nil {
				mainLog.Load().Fatal().Msgf("failed to get default config file path: %v", err)
			}
			if cdUID == "" && nextdns == "" {
				mainLog.Load().Notice().Msg("Generating controld default config: " + fp)
			}
			mainLog.Load().Info().Msg("writing default config file to: " + fp)
		}
		return false
	}

	// If error is viper.ConfigParseError, emit details line and column number.
	if errors.As(err, &viper.ConfigParseError{}) {
		if de := decoderErrorFromTomlFile(v.ConfigFileUsed()); de != nil {
			row, col := de.Position()
			mainLog.Load().Fatal().Msgf("failed to decode config file at line: %d, column: %d, error: %v", row, col, err)
		}
	}

	// Otherwise, report fatal error and exit.
	mainLog.Load().Fatal().Msgf("failed to decode config file: %v", err)
	return false
}

// decoderErrorFromTomlFile parses the invalid toml file, returning the details decoder error.
func decoderErrorFromTomlFile(cf string) *toml.DecodeError {
	if f, _ := os.Open(cf); f != nil {
		defer f.Close()
		var i any
		var de *toml.DecodeError
		if err := toml.NewDecoder(f).Decode(&i); err != nil && errors.As(err, &de) {
			return de
		}
	}
	return nil
}

// readBase64Config reads ctrld config from the base64 input string.
func readBase64Config(configBase64 string) error {
	if configBase64 == "" {
		return nil
	}
	configStr, err := base64.StdEncoding.DecodeString(configBase64)
	if err != nil {
		return fmt.Errorf("invalid base64 config: %w", err)
	}

	// readBase64Config is called when:
	//
	//  - "--base64_config" flag set.
	//  - Reading custom config when "--cd" flag set.
	//
	// So we need to re-create viper instance to discard old one.
	v = viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigType("toml")
	return v.ReadConfig(bytes.NewReader(configStr))
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

// defaultDeactivationPin is the default value for cdDeactivationPin.
// If cdDeactivationPin equals to this default, it means the pin code is not set from Control D API.
const defaultDeactivationPin = -1

// cdDeactivationPin is used in cd mode to decide whether stop and uninstall commands can be run.
var cdDeactivationPin int64 = defaultDeactivationPin

// deactivationPinNotSet reports whether cdDeactivationPin was not set by processCDFlags.
func deactivationPinNotSet() bool {
	return cdDeactivationPin == defaultDeactivationPin
}

func processCDFlags(cfg *ctrld.Config) error {
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
	if err != nil {
		if isMobile() {
			return err
		}
		logger.Warn().Err(err).Msg("could not fetch resolver config")
		return err
	}

	if resolverConfig.DeactivationPin != nil {
		logger.Debug().Msg("saving deactivation pin")
		cdDeactivationPin = *resolverConfig.DeactivationPin
	}

	logger.Info().Msg("generating ctrld config from Control-D configuration")

	*cfg = ctrld.Config{}
	// Fetch config, unmarshal to cfg.
	if resolverConfig.Ctrld.CustomConfig != "" {
		logger.Info().Msg("using defined custom config of Control-D resolver")
		if err := validateCdRemoteConfig(resolverConfig, cfg); err == nil {
			setListenerDefaultValue(cfg)
			return nil
		}
		mainLog.Load().Err(err).Msg("disregarding invalid custom config")
	}

	bootstrapIP := func(endpoint string) string {
		u, err := url.Parse(endpoint)
		if err != nil {
			logger.Warn().Err(err).Msgf("no bootstrap IP for invalid endpoint: %s", endpoint)
			return ""
		}
		switch {
		case dns.IsSubDomain(ctrld.FreeDnsDomain, u.Host):
			return ctrld.FreeDNSBoostrapIP
		case dns.IsSubDomain(ctrld.PremiumDnsDomain, u.Host):
			return ctrld.PremiumDNSBoostrapIP
		}
		return ""
	}
	cfg.Network = make(map[string]*ctrld.NetworkConfig)
	cfg.Network["0"] = &ctrld.NetworkConfig{
		Name:  "Network 0",
		Cidrs: []string{"0.0.0.0/0"},
	}
	cfg.Upstream = make(map[string]*ctrld.UpstreamConfig)
	cfg.Upstream["0"] = &ctrld.UpstreamConfig{
		BootstrapIP: bootstrapIP(resolverConfig.DOH),
		Endpoint:    resolverConfig.DOH,
		Type:        cdUpstreamProto,
		Timeout:     5000,
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

	// Set default value.
	setListenerDefaultValue(cfg)

	return nil
}

// setListenerDefaultValue sets the default value for cfg.Listener if none existed.
func setListenerDefaultValue(cfg *ctrld.Config) {
	if len(cfg.Listener) == 0 {
		cfg.Listener = map[string]*ctrld.ListenerConfig{
			"0": {IP: "", Port: 0},
		}
	}
}

// validateCdRemoteConfig validates the custom config from ControlD if defined.
func validateCdRemoteConfig(rc *controld.ResolverConfig, cfg *ctrld.Config) error {
	if rc.Ctrld.CustomConfig == "" {
		return nil
	}
	if err := readBase64Config(rc.Ctrld.CustomConfig); err != nil {
		return err
	}
	return v.Unmarshal(&cfg)
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

// selfCheckStatus performs the end-to-end DNS test by sending query to ctrld listener.
// It returns a boolean to indicate whether the check is succeeded, the actual status
// of ctrld service, and an additional error if any.
//
// We perform two tests:
//
// - Internal testing, ensuring query could be sent from client -> ctrld.
// - External testing, ensuring query could be sent from ctrld -> upstream.
//
// Self-check is considered success only if both tests are ok.
func selfCheckStatus(s service.Service) (bool, service.Status, error) {
	status, err := s.Status()
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not get service status")
		return false, service.StatusUnknown, err
	}
	// If ctrld is not running, do nothing, just return the status as-is.
	if status != service.StatusRunning {
		return false, status, nil
	}
	dir, err := socketDir()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to check ctrld listener status: could not get home directory")
		return false, status, err
	}
	mainLog.Load().Debug().Msg("waiting for ctrld listener to be ready")
	cc := newSocketControlClient(s, dir)
	if cc == nil {
		return false, status, errors.New("could not connect to control server")
	}

	resp, err := cc.post(startedPath, nil)
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to connect to control server")
		return false, status, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		mainLog.Load().Error().Msg("ctrld listener is not ready")
		return false, status, errors.New("ctrld listener is not ready")
	}

	// Not a ctrld upstream, return status as-is.
	if cfg.FirstUpstream().VerifyDomain() == "" {
		return true, status, nil
	}

	mainLog.Load().Debug().Msg("ctrld listener is ready")
	mainLog.Load().Debug().Msg("performing self-check")
	bo := backoff.NewBackoff("self-check", logf, 10*time.Second)
	bo.LogLongerThan = 500 * time.Millisecond
	ctx := context.Background()
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
		return true, status, nil
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("could not watch config change")
		return false, status, err
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
		lastAnswer     *dns.Msg
		lastErr        error
		internalTested bool
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
		if !internalTested {
			domain = selfCheckInternalTestDomain
		}
		if domain == "" {
			continue
		}

		m := new(dns.Msg)
		m.SetQuestion(domain+".", dns.TypeA)
		m.RecursionDesired = true
		r, _, exErr := exchangeContextWithTimeout(c, time.Second, m, net.JoinHostPort(lc.IP, strconv.Itoa(lc.Port)))
		if r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
			internalTested = domain == selfCheckInternalTestDomain
			if internalTested {
				mainLog.Load().Debug().Msgf("internal self-check against %q succeeded", domain)
				continue // internal domain test ok, continue with external test.
			} else {
				mainLog.Load().Debug().Msgf("external self-check against %q succeeded", domain)
			}
			return true, status, nil
		}
		// Return early if this is a connection refused.
		if errConnectionRefused(exErr) {
			return false, status, exErr
		}
		lastAnswer = r
		lastErr = exErr
		bo.BackOff(ctx, fmt.Errorf("ExchangeContext: %w", exErr))
	}
	mainLog.Load().Debug().Msgf("self-check against %q failed", domain)
	// Ping all upstreams to provide better error message to users.
	for name, uc := range cfg.Upstream {
		if err := uc.ErrorPing(); err != nil {
			mainLog.Load().Err(err).Msgf("failed to connect to upstream.%s, endpoint: %s", name, uc.Endpoint)
		}
	}
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
		return false, status, errSelfCheckNoAnswer
	}
	return false, status, lastErr
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
		// If we're on windows, use the install path for this.
		exePath, err := os.Executable()
		if err != nil {
			return "", err
		}

		return filepath.Dir(exePath), nil
	}
	// Mobile platform should provide a rw dir path for this.
	if isMobile() {
		return homedir, nil
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

// socketDir returns directory that ctrld will create socket file for running controlServer.
func socketDir() (string, error) {
	switch {
	case runtime.GOOS == "windows", isMobile():
		return userHomeDir()
	}
	dir := "/var/run"
	if ok, _ := dirWritable(dir); !ok {
		return userHomeDir()
	}
	return dir, nil
}

// tryReadingConfig is like tryReadingConfigWithNotice, with notice set to false.
func tryReadingConfig(writeDefaultConfig bool) {
	tryReadingConfigWithNotice(writeDefaultConfig, false)
}

// tryReadingConfigWithNotice tries reading in config files, either specified by user or from default
// locations. If notice is true, emitting a notice message to user which config file was read.
func tryReadingConfigWithNotice(writeDefaultConfig, notice bool) {
	// --config is specified.
	if configPath != "" {
		v.SetConfigFile(configPath)
		readConfigFile(false, notice)
		return
	}
	// no config start or base64 config mode.
	if !writeDefaultConfig {
		return
	}
	readConfigWithNotice(writeDefaultConfig, notice)
}

// readConfig calls readConfigWithNotice with notice set to false.
func readConfig(writeDefaultConfig bool) {
	readConfigWithNotice(writeDefaultConfig, false)
}

// readConfigWithNotice calls readConfigFile with config file set to ctrld.toml
// or config.toml for compatible with earlier versions of ctrld.
func readConfigWithNotice(writeDefaultConfig, notice bool) {
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
		if readConfigFile(config.written, notice) {
			break
		}
	}
}

func uninstall(p *prog, s service.Service) {
	if _, err := s.Status(); err != nil && errors.Is(err, service.ErrNotInstalled) {
		mainLog.Load().Error().Msg(err.Error())
		return
	}
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

func validateConfig(cfg *ctrld.Config) error {
	if err := ctrld.ValidateConfig(validator.New(), cfg); err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			for _, fe := range ve {
				mainLog.Load().Error().Msgf("invalid config: %s: %s", fe.Namespace(), fieldErrorMsg(fe))
			}
		}
		return err
	}
	return nil
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
	case "max":
		if fe.Kind() == reflect.Map || fe.Kind() == reflect.Slice {
			return fmt.Sprintf("exceeded maximum number of elements: %s", fe.Param())
		}
		return fmt.Sprintf("maximum value: %q", fe.Param())
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
		return "value is required"
	case "dnsrcode":
		return fmt.Sprintf("invalid DNS rcode value: %s", fe.Value())
	case "ipstack":
		ipStacks := []string{ctrld.IpStackV4, ctrld.IpStackV6, ctrld.IpStackSplit, ctrld.IpStackBoth}
		return fmt.Sprintf("must be one of: %q", strings.Join(ipStacks, " "))
	case "iporempty":
		return fmt.Sprintf("invalid IP format: %s", fe.Value())
	case "file":
		return fmt.Sprintf("filed does not exist: %s", fe.Value())
	case "http_url":
		return fmt.Sprintf("invalid http/https url: %s", fe.Value())
	}
	return ""
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

// mobileListenerPort returns hardcoded port for mobile platforms.
func mobileListenerPort() int {
	if isAndroid() {
		return 5354
	}
	return 53
}

// mobileListenerIp returns hardcoded listener ip for mobile platforms
func mobileListenerIp() string {
	if isAndroid() {
		return "0.0.0.0"
	}
	return "127.0.0.1"
}

// updateListenerConfig updates the config for listeners if not defined,
// or defined but invalid to be used, e.g: using loopback address other
// than 127.0.0.1 with systemd-resolved.
func updateListenerConfig(cfg *ctrld.Config) bool {
	updated, _ := tryUpdateListenerConfig(cfg, nil, true)
	return updated
}

// tryUpdateListenerConfig tries updating listener config with a working one.
// If fatal is true, and there's listen address conflicted, the function do
// fatal error.
func tryUpdateListenerConfig(cfg *ctrld.Config, infoLogger *zerolog.Logger, fatal bool) (updated, ok bool) {
	ok = true
	lcc := make(map[string]*listenerConfigCheck)
	cdMode := cdUID != ""
	nextdnsMode := nextdns != ""
	// For Windows server with local Dns server running, we can only try on random local IP.
	hasLocalDnsServer := windowsHasLocalDnsServerRunning()
	for n, listener := range cfg.Listener {
		lcc[n] = &listenerConfigCheck{}
		if listener.IP == "" {
			listener.IP = "0.0.0.0"
			if hasLocalDnsServer {
				// Windows Server lies to us that we could listen on 0.0.0.0:53
				// even there's a process already done that, stick to local IP only.
				listener.IP = "127.0.0.1"
			}
			lcc[n].IP = true
		}
		if listener.Port == 0 {
			listener.Port = 53
			lcc[n].Port = true
		}
		// In cd mode, we always try to pick an ip:port pair to work.
		// Same if nextdns resolver is used.
		//
		// Except on Windows Server with local Dns running,
		// we could only listen on random local IP port 53.
		if cdMode || nextdnsMode {
			lcc[n].IP = true
			lcc[n].Port = true
			if hasLocalDnsServer {
				lcc[n].Port = false
			}
		}
		updated = updated || lcc[n].IP || lcc[n].Port
	}
	il := mainLog.Load()
	if infoLogger != nil {
		il = infoLogger
	}
	if isMobile() {
		// On Mobile, only use first listener, ignore others.
		firstLn := cfg.FirstListener()
		for k := range cfg.Listener {
			if cfg.Listener[k] != firstLn {
				delete(cfg.Listener, k)
			}
		}
		if cdMode {
			firstLn.IP = mobileListenerIp()
			firstLn.Port = mobileListenerPort()
			clear(lcc)
			updated = true
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
		if hasLocalDnsServer {
			tryAllPort53 = false
			tryOldIPPort5354 = false
			tryPort5354 = false
		}
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
				if fatal {
					logMsg(mainLog.Load().Fatal(), n, "failed to listen: %v", err)
				}
				ok = false
				break
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
					logMsg(il.Info(), n, "could not listen on address: %s, trying: %s", addr, net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port)))
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
					logMsg(il.Info(), n, "could not listen on address: %s, trying localhost: %s", addr, net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port)))
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
				logMsg(il.Info(), n, "could not listen on address: %s, trying current ip with port 5354", addr)
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
				logMsg(il.Info(), n, "could not listen on address: %s, trying 0.0.0.0:5354", addr)
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
				if fatal {
					logMsg(mainLog.Load().Fatal(), n, "could not listener on %s: %v", net.JoinHostPort(listener.IP, strconv.Itoa(listener.Port)), err)
				}
				ok = false
				break
			}
			logMsg(il.Info(), n, "could not listen on address: %s, pick a random ip+port", addr)
			attempts++
		}
	}
	if !ok {
		return
	}

	// Specific case for systemd-resolved.
	if useSystemdResolved {
		if listener := cfg.FirstListener(); listener != nil && listener.Port == 53 {
			n := listeners[0]
			// systemd-resolved does not allow forwarding DNS queries from 127.0.0.53 to loopback
			// ip address, other than "127.0.0.1", so trying to listen on default route interface
			// address instead.
			if ip := net.ParseIP(listener.IP); ip != nil && ip.IsLoopback() && ip.String() != "127.0.0.1" {
				logMsg(il.Info(), n, "using loopback interface do not work with systemd-resolved")
				found := false
				if netIface, _ := net.InterfaceByName(defaultIfaceName()); netIface != nil {
					addrs, _ := netIface.Addrs()
					for _, addr := range addrs {
						if netIP, ok := addr.(*net.IPNet); ok && netIP.IP.To4() != nil {
							addr := net.JoinHostPort(netIP.IP.String(), strconv.Itoa(listener.Port))
							if err := tryListen(addr); err == nil {
								found = true
								listener.IP = netIP.IP.String()
								logMsg(il.Info(), n, "use %s as listener address", listener.IP)
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
	return
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
		if x == "--"+cdOrgFlagName {
			skip = true
			continue
		}
		// For "--cd-org=XXX", just skip it.
		if strings.HasPrefix(x, "--"+cdOrgFlagName+"=") {
			continue
		}
		a = append(a, x)
	}
	sc.Arguments = a
}

// newSocketControlClient returns new control client after control server was started.
func newSocketControlClient(s service.Service, dir string) *controlClient {
	bo := backoff.NewBackoff("self-check", logf, 10*time.Second)
	bo.LogLongerThan = 10 * time.Second
	ctx := context.Background()

	cc := newControlClient(filepath.Join(dir, ctrldControlUnixSock))
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	// The socket control server may not start yet, so attempt to ping
	// it until we got a response. For each iteration, check ctrld status
	// to make sure ctrld is still running.
	for {
		curStatus, err := s.Status()
		if err != nil {
			return nil
		}
		if curStatus != service.StatusRunning {
			return nil
		}
		if _, err := cc.post("/", nil); err == nil {
			// Server was started, stop pinging.
			break
		}
		// The socket control server is not ready yet, backoff for waiting it to be ready.
		bo.BackOff(ctx, err)
		select {
		case <-timeout.C:
			return nil
		default:
		}
		continue
	}

	return cc
}

func newSocketControlClientMobile(dir string, stopCh chan struct{}) *controlClient {
	bo := backoff.NewBackoff("self-check", logf, 3*time.Second)
	bo.LogLongerThan = 3 * time.Second
	ctx := context.Background()
	cc := newControlClient(filepath.Join(dir, ControlSocketName()))
	for {
		select {
		case <-stopCh:
			return nil
		default:
			_, err := cc.post("/", nil)
			if err == nil {
				return cc
			} else {
				bo.BackOff(ctx, err)
			}
		}
	}
}

// checkStrFlagEmpty validates if a string flag was set to an empty string.
// If yes, emitting a fatal error message.
func checkStrFlagEmpty(cmd *cobra.Command, flagName string) {
	fl := cmd.Flags().Lookup(flagName)
	if !fl.Changed || fl.Value.Type() != "string" {
		return
	}
	if fl.Value.String() == "" {
		mainLog.Load().Fatal().Msgf(`flag "--%s" value must be non-empty`, fl.Name)
	}
}

func validateCdUpstreamProtocol() {
	if cdUID == "" {
		return
	}
	switch cdUpstreamProto {
	case ctrld.ResolverTypeDOH, ctrld.ResolverTypeDOH3:
	default:
		mainLog.Load().Fatal().Msg(`flag "--protocol" must be "doh" or "doh3"`)
	}
}

func validateCdAndNextDNSFlags() {
	if (cdUID != "" || cdOrg != "") && nextdns != "" {
		mainLog.Load().Fatal().Msgf("--%s/--%s could not be used with --%s", cdUidFlagName, cdOrgFlagName, nextdnsFlagName)
	}
}

// removeNextDNSFromArgs removes the --nextdns from command line arguments.
func removeNextDNSFromArgs(sc *service.Config) {
	a := sc.Arguments[:0]
	skip := false
	for _, x := range sc.Arguments {
		if skip {
			skip = false
			continue
		}
		// For "--nextdns XXX", skip it and mark next arg skipped.
		if x == "--"+nextdnsFlagName {
			skip = true
			continue
		}
		// For "--nextdns=XXX", just skip it.
		if strings.HasPrefix(x, "--"+nextdnsFlagName+"=") {
			continue
		}
		a = append(a, x)
	}
	sc.Arguments = a
}

// doGenerateNextDNSConfig generates a working config with nextdns resolver.
func doGenerateNextDNSConfig(uid string) error {
	if uid == "" {
		return nil
	}
	mainLog.Load().Notice().Msgf("Generating nextdns config: %s", defaultConfigFile)
	generateNextDNSConfig(uid)
	updateListenerConfig(&cfg)
	return writeConfigFile()
}

func noticeWritingControlDConfig() error {
	if cdUID != "" {
		mainLog.Load().Notice().Msgf("Generating controld config: %s", defaultConfigFile)
	}
	return nil
}

// deactivationPinInvalidExitCode indicates exit code due to invalid pin code.
const deactivationPinInvalidExitCode = 126

// errInvalidDeactivationPin indicates that the deactivation pin is invalid.
var errInvalidDeactivationPin = errors.New("deactivation pin is invalid")

// errRequiredDeactivationPin indicates that the deactivation pin is required but not provided by users.
var errRequiredDeactivationPin = errors.New("deactivation pin is required to stop or uninstall the service")

// checkDeactivationPin validates if the deactivation pin matches one in ControlD config.
func checkDeactivationPin(s service.Service, stopCh chan struct{}) error {
	dir, err := socketDir()
	if err != nil {
		mainLog.Load().Err(err).Msg("could not check deactivation pin")
		return err
	}
	var cc *controlClient
	if s == nil {
		cc = newSocketControlClientMobile(dir, stopCh)
	} else {
		cc = newSocketControlClient(s, dir)
	}
	if cc == nil {
		return nil // ctrld is not running.
	}
	data, _ := json.Marshal(&deactivationRequest{Pin: deactivationPin})
	resp, _ := cc.post(deactivationPath, bytes.NewReader(data))
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusBadRequest:
			mainLog.Load().Error().Msg(errRequiredDeactivationPin.Error())
			return errRequiredDeactivationPin // pin is required
		case http.StatusOK:
			return nil // valid pin
		case http.StatusNotFound:
			return nil // the server is running older version of ctrld
		}
	}
	mainLog.Load().Error().Msg(errInvalidDeactivationPin.Error())
	return errInvalidDeactivationPin
}

// isCheckDeactivationPinErr reports whether there is an error during check deactivation pin process.
func isCheckDeactivationPinErr(err error) bool {
	return errors.Is(err, errInvalidDeactivationPin) || errors.Is(err, errRequiredDeactivationPin)
}

// ensureUninstall ensures that s.Uninstall will remove ctrld service from system completely.
func ensureUninstall(s service.Service) error {
	maxAttempts := 10
	var err error
	for i := 0; i < maxAttempts; i++ {
		err = s.Uninstall()
		if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.Join(err, errors.New("uninstall failed"))
}

// exchangeContextWithTimeout wraps c.ExchangeContext with the given timeout.
func exchangeContextWithTimeout(c *dns.Client, timeout time.Duration, msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.ExchangeContext(ctx, msg, addr)
}

// powershell runs the given powershell command.
func powershell(cmd string) ([]byte, error) {
	out, err := exec.Command("powershell", "-Command", cmd).CombinedOutput()
	return bytes.TrimSpace(out), err
}

// windowsHasLocalDnsServerRunning reports whether we are on Windows and having Dns server running.
func windowsHasLocalDnsServerRunning() bool {
	if runtime.GOOS == "windows" {
		out, _ := powershell("Get-WindowsFeature -Name DNS")
		if !bytes.Contains(bytes.ToLower(out), []byte("installed")) {
			return false
		}

		_, err := powershell("Get-Process -Name DNS")
		return err == nil
	}
	return false
}

// absHomeDir returns the absolute path to given filename using home directory as root dir.
func absHomeDir(filename string) string {
	if homedir != "" {
		return filepath.Join(homedir, filename)
	}
	dir, err := userHomeDir()
	if err != nil {
		return filename
	}
	return filepath.Join(dir, filename)
}

// runInCdMode reports whether ctrld service is running in cd mode.
func runInCdMode() bool {
	if s, _ := newService(&prog{}, svcConfig); s != nil {
		if dir, _ := socketDir(); dir != "" {
			cc := newSocketControlClient(s, dir)
			if cc != nil {
				resp, _ := cc.post(cdPath, nil)
				if resp != nil {
					defer resp.Body.Close()
					return resp.StatusCode == http.StatusOK
				}
			}
		}
	}
	return false
}
