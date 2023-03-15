package main

import (
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Control-D-Inc/ctrld/internal/router"
)

func initRouterCLI() {
	validArgs := append(router.SupportedPlatforms(), "auto")
	var b strings.Builder
	b.WriteString("Auto-setup Control D on a onRouter.\n\nSupported platforms:\n\n")
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
			switch platform {
			case router.DDWrt, router.Merlin, router.OpenWrt, router.Ubios:
			default:
				unsupportedPlatformHelp(cmd)
			}
			exe, err := os.Executable()
			if err != nil {
				log.Fatal(err)
				os.Exit(1)
			}

			cmdArgs := []string{"start"}
			cmdArgs = append(cmdArgs, os.Args[3:]...)
			cmdArgs = append(cmdArgs, "--router=true")
			command := exec.Command(exe, cmdArgs...)
			command.Stdout = os.Stdout
			command.Stderr = os.Stderr
			command.Stdin = os.Stdin
			if err := command.Run(); err != nil {
				log.Fatal(err)
			}
		},
	}
	tmpl := routerCmd.UsageTemplate()
	tmpl = strings.Replace(tmpl, "{{.UseLine}}", "{{.UseLine}} [platform]", 1)
	routerCmd.SetUsageTemplate(tmpl)
	rootCmd.AddCommand(routerCmd)
}
