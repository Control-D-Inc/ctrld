package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
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
	// TODO: Port the complete logic from cmdStart.Run
	// This should include all the complex logic from initStartCmd
	return nil
}

// Stop implements the logic from cmdStop.Run
func (sc *ServiceCommand) Stop(cmd *cobra.Command, args []string) error {
	// TODO: Port the complete logic from cmdStop.Run
	// This should include all the complex logic from initStopCmd
	return nil
}

// Restart implements the logic from cmdRestart.Run
func (sc *ServiceCommand) Restart(cmd *cobra.Command, args []string) error {
	// TODO: Port the complete logic from cmdRestart.Run
	// This should include all the complex logic from initRestartCmd
	return nil
}

// Reload implements the logic from cmdReload.Run
func (sc *ServiceCommand) Reload(cmd *cobra.Command, args []string) error {
	// TODO: Port the complete logic from cmdReload.Run
	// This should include all the complex logic from initReloadCmd
	return nil
}

// Status implements the logic from cmdStatus.Run
func (sc *ServiceCommand) Status(cmd *cobra.Command, args []string) error {
	// TODO: Port the complete logic from cmdStatus.Run
	// This should include all the complex logic from initStatusCmd
	return nil
}

// Uninstall implements the logic from cmdUninstall.Run
func (sc *ServiceCommand) Uninstall(cmd *cobra.Command, args []string) error {
	// TODO: Port the complete logic from cmdUninstall.Run
	// This should include all the complex logic from initUninstallCmd
	return nil
}

// Interfaces implements the logic from cmdInterfaces.Run
func (sc *ServiceCommand) Interfaces(cmd *cobra.Command, args []string) error {
	// TODO: Port the complete logic from cmdInterfaces.Run
	// This should include all the complex logic from initInterfacesCmd
	return nil
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

	// Start command
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the ctrld service",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: sc.Start,
	}

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

	// Interfaces command
	interfacesCmd := &cobra.Command{
		Use:   "interfaces",
		Short: "List network interfaces",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: sc.Interfaces,
	}

	// Create aliases for root command
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
