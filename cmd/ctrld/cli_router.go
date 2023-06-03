//go:build linux || freebsd

package main

import (
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Control-D-Inc/ctrld/internal/router"
)

func initRouterCLI() {
	validArgs := append(router.SupportedPlatforms(), "auto")
	var b strings.Builder
	b.WriteString("Auto-setup Control D on a router.\n\nSupported platforms:\n\n")
	for _, arg := range validArgs {
		b.WriteString("    ₒ ")
		b.WriteString(arg)
		if arg == "auto" {
			b.WriteString(" - detect the platform you are running on")
		}
		b.WriteString("\n")
	}

	routerCmd := &cobra.Command{
		Use:   "setup",
		Short: b.String(),
		PreRun: func(cmd *cobra.Command, args []string) {
			initConsoleLogging()
		},
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				_ = cmd.Help()
				return
			}
			if len(args) != 1 {
				_ = cmd.Help()
				return
			}
			platform := args[0]
			if platform == "auto" {
				platform = router.Name()
			}
			if !router.IsSupported(platform) {
				unsupportedPlatformHelp(cmd)
				os.Exit(1)
			}

			exe, err := os.Executable()
			if err != nil {
				mainLog.Fatal().Msgf("could not find executable path: %v", err)
				os.Exit(1)
			}

			cmdArgs := []string{"start"}
			cmdArgs = append(cmdArgs, osArgs(platform)...)
			cmdArgs = append(cmdArgs, "--router")
			command := exec.Command(exe, cmdArgs...)
			command.Stdout = os.Stdout
			command.Stderr = os.Stderr
			command.Stdin = os.Stdin
			if err := command.Run(); err != nil {
				mainLog.Fatal().Msg(err.Error())
			}
		},
	}
	// Keep these flags in sync with startCmd, except for "--router".
	routerCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")
	routerCmd.Flags().StringVarP(&configBase64, "base64_config", "", "", "Base64 encoded config")
	routerCmd.Flags().StringVarP(&listenAddress, "listen", "", "", "Listener address and port, in format: address:port")
	routerCmd.Flags().StringVarP(&primaryUpstream, "primary_upstream", "", "", "Primary upstream endpoint")
	routerCmd.Flags().StringVarP(&secondaryUpstream, "secondary_upstream", "", "", "Secondary upstream endpoint")
	routerCmd.Flags().StringSliceVarP(&domains, "domains", "", nil, "List of domain to apply in a split DNS policy")
	routerCmd.Flags().StringVarP(&logPath, "log", "", "", "Path to log file")
	routerCmd.Flags().IntVarP(&cacheSize, "cache_size", "", 0, "Enable cache with size items")
	routerCmd.Flags().StringVarP(&cdUID, "cd", "", "", "Control D resolver uid")
	routerCmd.Flags().BoolVarP(&cdDev, "dev", "", false, "Use Control D dev resolver/domain")
	_ = routerCmd.Flags().MarkHidden("dev")
	routerCmd.Flags().StringVarP(&iface, "iface", "", "", `Update DNS setting for iface, "auto" means the default interface gateway`)

	tmpl := routerCmd.UsageTemplate()
	tmpl = strings.Replace(tmpl, "{{.UseLine}}", "{{.UseLine}} [platform]", 1)
	routerCmd.SetUsageTemplate(tmpl)
	rootCmd.AddCommand(routerCmd)
}

func osArgs(platform string) []string {
	args := os.Args[2:]
	n := 0
	for _, x := range args {
		if x != platform && x != "auto" {
			args[n] = x
			n++
		}
	}
	return args[:n]
}
